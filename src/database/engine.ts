import { Worker } from "node:worker_threads";
import {
  QueryExecutionResult,
  SqliteSecurityControlsReport,
  UserRole,
} from "../types.js";
import { SEED_SQL, TABLE_METADATA } from "./seed.js";
import { SQLValidator } from "../security/validator.js";
import {
  ALLOWED_FUNCTIONS_LIST,
  PII_COLUMNS,
  ROLE_ALLOWED_TABLES,
  SQL_LIMITS,
} from "../security/policy.js";
import {
  enforceResultPolicy,
  SecurityResultPolicyViolation,
} from "../security/result-policy.js";
import { auditLogger } from "./audit.js";
import { SQLITE_WORKER_MODULE_SOURCE } from "./sqlite-worker-code.js";

export class QueryTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QueryTimeoutError";
  }
}

export interface SecureDatabaseEngineOptions {
  timeoutMs?: number;
  maxPageCount?: number;
  maxAuthorizerOps?: number;
  maxOldGenerationSizeMb?: number;
  maxYoungGenerationSizeMb?: number;
  extraSeedSql?: string;
  extraAllowedViews?: string[];
}

export class SecureDatabaseEngine {
  private worker: Worker | null = null;
  private workerReadyPromise: Promise<void> | null = null;
  private requestSeq = 0;
  private executionChain: Promise<unknown> = Promise.resolve();
  private workerTerminationCount = 0;

  private readonly timeoutMs: number;
  private readonly maxPageCount: number;
  private readonly maxAuthorizerOps: number;
  private readonly maxOldGenerationSizeMb: number;
  private readonly maxYoungGenerationSizeMb: number;
  private readonly extraSeedSql: string;
  private readonly extraAllowedViews: string[];
  private readonly validator: SQLValidator;

  constructor(optionsOrTimeoutMs: number | SecureDatabaseEngineOptions = 5000) {
    const opts: SecureDatabaseEngineOptions =
      typeof optionsOrTimeoutMs === "number"
        ? { timeoutMs: optionsOrTimeoutMs }
        : optionsOrTimeoutMs;

    this.timeoutMs = opts.timeoutMs ?? 5000;
    this.maxPageCount = opts.maxPageCount ?? SQL_LIMITS.sqliteMaxPageCount;
    this.maxAuthorizerOps = opts.maxAuthorizerOps ?? SQL_LIMITS.maxAuthorizerOps;
    this.maxOldGenerationSizeMb =
      opts.maxOldGenerationSizeMb ?? SQL_LIMITS.workerMaxOldGenerationSizeMb;
    this.maxYoungGenerationSizeMb =
      opts.maxYoungGenerationSizeMb ??
      SQL_LIMITS.workerMaxYoungGenerationSizeMb;
    this.extraSeedSql = opts.extraSeedSql ?? "";
    this.extraAllowedViews = (opts.extraAllowedViews ?? []).map((v) =>
      v.toLowerCase()
    );
    this.validator = new SQLValidator({
      extraAllowedViews: this.extraAllowedViews,
    });
  }

  public async init(): Promise<void> {
    if (this.worker && this.workerReadyPromise) {
      await this.workerReadyPromise;
      return;
    }

    const resourceLimits = {
      maxOldGenerationSizeMb: this.maxOldGenerationSizeMb,
      maxYoungGenerationSizeMb: this.maxYoungGenerationSizeMb,
      codeRangeSizeMb: SQL_LIMITS.workerCodeRangeSizeMb,
      stackSizeMb: SQL_LIMITS.workerStackSizeMb,
    };

    const workerUrl = new URL(
      "data:text/javascript;base64," +
        Buffer.from(SQLITE_WORKER_MODULE_SOURCE, "utf8").toString("base64")
    );

    const worker = new Worker(workerUrl, {
      workerData: {
        seedSql: SEED_SQL,
        extraSeedSql: this.extraSeedSql,
        allowedFunctionsList: [...ALLOWED_FUNCTIONS_LIST],
        piiColumnsList: [...PII_COLUMNS],
        roleAllowedTables: ROLE_ALLOWED_TABLES,
        extraAllowedViews: this.extraAllowedViews,
        maxPageCount: this.maxPageCount,
        maxAuthorizerOps: this.maxAuthorizerOps,
        maxRows: SQL_LIMITS.maxRows,
        workerResourceLimits: resourceLimits,
      },
      resourceLimits,
    });

    this.worker = worker;
    this.workerReadyPromise = new Promise<void>((resolve, reject) => {
      const onMessage = (msg: any) => {
        if (msg && msg.type === "ready") {
          worker.off("message", onMessage);
          worker.off("error", onError);
          worker.unref();
          resolve();
        }
      };
      const onError = (err: Error) => {
        worker.off("message", onMessage);
        worker.off("error", onError);
        this.worker = null;
        this.workerReadyPromise = null;
        reject(err);
      };
      worker.on("message", onMessage);
      worker.on("error", onError);
    });

    await this.workerReadyPromise;
  }

  public getWorkerTerminationCount(): number {
    return this.workerTerminationCount;
  }

  public async close(): Promise<void> {
    if (this.worker) {
      const w = this.worker;
      this.worker = null;
      this.workerReadyPromise = null;
      await w.terminate();
    }
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    const next = this.executionChain.then(task, task);
    this.executionChain = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  private async sendWorkerRequest(
    payload: Record<string, unknown>,
    deadlineMs: number
  ): Promise<any> {
    await this.init();
    const worker = this.worker;
    if (!worker) {
      throw new Error("SQLite worker thread failed to initialize.");
    }

    const reqId = ++this.requestSeq;
    worker.ref();

    return new Promise<any>((resolve, reject) => {
      let settled = false;

      const cleanup = () => {
        clearTimeout(timer);
        worker.off("message", onMessage);
        worker.off("error", onError);
        worker.off("exit", onExit);
        if (this.worker === worker) {
          worker.unref();
        }
      };

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.workerTerminationCount += 1;
        this.worker = null;
        this.workerReadyPromise = null;
        cleanup();
        void worker.terminate();
        reject(
          new QueryTimeoutError(
            `Query exceeded hard deadline of ${deadlineMs}ms; SQLite worker thread was terminated.`
          )
        );
      }, deadlineMs);

      const onMessage = (msg: any) => {
        if (!msg || msg.id !== reqId || settled) return;
        settled = true;
        cleanup();
        resolve(msg);
      };

      const onError = (err: Error) => {
        if (settled) return;
        settled = true;
        this.worker = null;
        this.workerReadyPromise = null;
        cleanup();
        void worker.terminate();
        reject(err);
      };

      const onExit = (code: number) => {
        if (settled) return;
        settled = true;
        this.worker = null;
        this.workerReadyPromise = null;
        cleanup();
        reject(
          new Error(
            `SQLite worker exited unexpectedly with code ${code} (possible memory cap termination).`
          )
        );
      };

      worker.on("message", onMessage);
      worker.on("error", onError);
      worker.on("exit", onExit);
      worker.postMessage({ ...payload, id: reqId });
    });
  }

  public async inspectSecurityControls(): Promise<SqliteSecurityControlsReport> {
    return this.enqueue(async () => {
      const res = await this.sendWorkerRequest(
        { type: "inspect_controls" },
        this.timeoutMs
      );
      return res.controls as SqliteSecurityControlsReport;
    });
  }

  /**
   * Test-only entrypoint sending SQL directly to the worker without running the
   * JavaScript AST validator, used to prove that SQLite's compile-time authorizer,
   * defensive mode, and read-only pragmas enforce policy independently.
   */
  public async executeRawInWorkerForTest(
    rawSql: string,
    role: UserRole
  ): Promise<{ columns: string[]; rows: Record<string, unknown>[] }> {
    return this.enqueue(async () => {
      const res = await this.sendWorkerRequest(
        {
          type: "query",
          sql: rawSql,
          role,
          rowCap: SQL_LIMITS.maxRows,
        },
        this.timeoutMs
      );
      if (!res.ok) {
        throw new Error(String(res.error));
      }
      return {
        columns: res.columns as string[],
        rows: res.rows as Record<string, unknown>[],
      };
    });
  }

  public async executeQuery(
    rawQuery: string,
    role: UserRole = "unauthenticated",
    principal = "unauthenticated"
  ): Promise<QueryExecutionResult> {
    if (role === "unauthenticated") {
      auditLogger.log({
        principal,
        role,
        tool: "execute_analytical_sql",
        query: rawQuery,
        status: "BLOCKED_AUTH",
        reason: "Unauthenticated caller denied database execution.",
      });
      throw new Error(
        "AuthenticationRequired: valid credentials are required to execute queries."
      );
    }

    // Layer 2: Local JavaScript AST Validation
    const validation = this.validator.validate(rawQuery, role);
    if (!validation.valid) {
      auditLogger.log({
        principal,
        role,
        tool: "execute_analytical_sql",
        query: rawQuery,
        status: "BLOCKED_AST",
        reason: validation.violationReason,
      });
      throw new Error(`SecurityASTViolation: ${validation.violationReason}`);
    }

    const queryToExecute = validation.sanitizedQuery || rawQuery;
    const limitApplied = validation.limitInjected ?? SQL_LIMITS.defaultLimit;

    return this.enqueue(async () => {
      const startTime = performance.now();

      try {
        const workerRes = await this.sendWorkerRequest(
          {
            type: "query",
            sql: queryToExecute,
            role,
            rowCap: limitApplied,
          },
          this.timeoutMs
        );

        const executionTimeMs =
          Math.round((performance.now() - startTime) * 100) / 100;

        if (!workerRes.ok) {
          const isAuthz = Boolean(workerRes.isAuthorizerDenial);
          auditLogger.log({
            principal,
            role,
            tool: "execute_analytical_sql",
            query: queryToExecute,
            status: isAuthz ? "BLOCKED_AUTHORIZER" : "ERROR",
            executionTimeMs,
            reason: String(workerRes.error),
          });
          throw new Error(String(workerRes.error));
        }

        const columns = (workerRes.columns ?? []) as string[];
        const rows = (workerRes.rows ?? []) as Record<string, unknown>[];

        // Layer 3.5: Result-level PII fail-closed check
        enforceResultPolicy({
          role,
          columns,
          rows,
        });

        auditLogger.log({
          principal,
          role,
          tool: "execute_analytical_sql",
          query: queryToExecute,
          status: "SUCCESS",
          executionTimeMs,
          rowCount: rows.length,
        });

        return {
          query: queryToExecute,
          executionTimeMs,
          rowCount: rows.length,
          limitApplied,
          columns,
          rows,
          authorizerOperations: Number(workerRes.authorizerOperations ?? 0),
          sandbox: {
            engine: "SQLite (node:sqlite DatabaseSync in worker_threads)",
            workerThread: true,
            workerMaxOldGenMb: this.maxOldGenerationSizeMb,
            sqliteMaxPageCount: this.maxPageCount,
            timeoutMs: this.timeoutMs,
            externalAccess: false,
            role,
          },
        };
      } catch (err: any) {
        const executionTimeMs =
          Math.round((performance.now() - startTime) * 100) / 100;

        if (err instanceof QueryTimeoutError) {
          auditLogger.log({
            principal,
            role,
            tool: "execute_analytical_sql",
            query: queryToExecute,
            status: "TIMEOUT",
            executionTimeMs,
            reason: err.message,
          });
          throw err;
        }

        if (err instanceof SecurityResultPolicyViolation) {
          auditLogger.log({
            principal,
            role,
            tool: "execute_analytical_sql",
            query: queryToExecute,
            status: "BLOCKED_RESULT_POLICY",
            executionTimeMs,
            reason: err.message,
          });
          throw err;
        }

        throw err;
      }
    });
  }

  public getTables(role: UserRole = "unauthenticated") {
    if (role === "unauthenticated") return [];
    return Object.values(TABLE_METADATA)
      .filter((tbl) => role === "admin" || !tbl.adminOnly)
      .map((tbl) => ({
        name: tbl.name,
        description: tbl.description,
        rowCount: tbl.rowCount,
        columns: tbl.columns
          .filter((c) => role === "admin" || !c.isPII)
          .map((c) => c.name),
      }));
  }

  public getTableSchema(
    tableName: string,
    role: UserRole = "unauthenticated"
  ) {
    if (role === "unauthenticated") return null;
    const table = TABLE_METADATA[tableName.toLowerCase()];
    if (!table) return null;
    if (table.adminOnly && role !== "admin") return null;

    return {
      name: table.name,
      description: table.description,
      rowCount: table.rowCount,
      columns: table.columns.map((c) => ({
        name: c.name,
        type: c.type,
        isPII: c.isPII,
        description: c.description,
        hidden: !c.isPII || role === "admin" ? false : true,
      })),
    };
  }
}

export const dbEngine = new SecureDatabaseEngine();
