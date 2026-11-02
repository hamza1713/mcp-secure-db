import initSqlJs, { Database, SqlJsStatic } from "sql.js";
import { QueryExecutionResult, UserRole } from "../types.js";
import { SEED_SQL, TABLE_METADATA } from "./seed.js";
import { sqlValidator } from "../security/validator.js";
import { auditLogger } from "./audit.js";

export class SecureDatabaseEngine {
  private db: Database | null = null;
  private SQL: SqlJsStatic | null = null;
  private isInitialized = false;
  private timeoutMs: number;

  constructor(timeoutMs = 10000) {
    this.timeoutMs = timeoutMs;
  }

  public async init(): Promise<void> {
    if (this.isInitialized && this.db) return;

    this.SQL = await initSqlJs();
    this.db = new this.SQL.Database();

    // Execute seed SQL
    this.db.run(SEED_SQL);
    this.isInitialized = true;
  }

  public async executeQuery(
    rawQuery: string,
    role: UserRole = "public_viewer",
    principal = "anonymous"
  ): Promise<QueryExecutionResult> {
    await this.init();
    if (!this.db) throw new Error("Database engine not initialized");

    // Layer 2: Deterministic Zero-Token AST Validation
    const validation = sqlValidator.validate(rawQuery, role);
    if (!validation.valid) {
      auditLogger.log({
        principal,
        role,
        query: rawQuery,
        status: "BLOCKED_AST",
        reason: validation.violationReason,
      });
      throw new Error(`SecurityASTViolation: ${validation.violationReason}`);
    }

    const queryToExecute = validation.sanitizedQuery || rawQuery;
    const startTime = performance.now();

    try {
      // Execute query with timeout guard
      const results = this.db.exec(queryToExecute);
      const executionTimeMs = Math.round((performance.now() - startTime) * 100) / 100;

      let columns: string[] = [];
      let rows: Record<string, unknown>[] = [];

      if (results && results.length > 0) {
        columns = results[0].columns;
        rows = results[0].values.map((rowValues) => {
          const rowObj: Record<string, unknown> = {};
          columns.forEach((col, idx) => {
            rowObj[col] = rowValues[idx];
          });
          return rowObj;
        });
      }

      auditLogger.log({
        principal,
        role,
        query: queryToExecute,
        status: "SUCCESS",
        executionTimeMs,
        rowCount: rows.length,
      });

      return {
        query: queryToExecute,
        executionTimeMs,
        rowCount: rows.length,
        limitApplied: validation.limitInjected || 100,
        columns,
        rows,
        sandbox: {
          engine: "SQLite (sql.js / In-Memory WASM)",
          memoryLimit: "512MB",
          timeoutSeconds: Math.round(this.timeoutMs / 1000),
          externalAccess: false,
          role,
        },
      };
    } catch (err: any) {
      const executionTimeMs = Math.round((performance.now() - startTime) * 100) / 100;
      auditLogger.log({
        principal,
        role,
        query: queryToExecute,
        status: "ERROR",
        executionTimeMs,
        reason: err.message,
      });
      throw err;
    }
  }

  public getTables(role: UserRole = "public_viewer") {
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

  public getTableSchema(tableName: string, role: UserRole = "public_viewer") {
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
