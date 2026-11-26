import {
  QueryExecutionResult,
  SqliteWorkerPoolStats,
  UserRole,
  ValidationResult,
} from "../types.js";
import {
  buildDefaultDemoPolicy,
  loadPolicyFromFile,
  ResolvedPolicy,
} from "../policy/loader.js";
import { AuditLogger } from "./audit.js";
import { MetricsRegistry } from "../observability/metrics.js";
import { SecureDatabaseEngine, dbEngine } from "./engine.js";
import {
  PostgresQueryEngine,
  PostgresSecureAdapterOptions,
} from "./postgres-adapter.js";

export interface ExecutionContextOptions {
  requestId?: string;
  tenantId?: string;
}

export interface TableSchemaInfo {
  name: string;
  description: string;
  rowCount: number;
  columns: Array<{
    name: string;
    type: string;
    isPII: boolean;
    description: string;
    hidden: boolean;
  }>;
  redactedPiiColumnCount: number;
}

export interface FilteredCatalogEntry {
  name: string;
  description: string;
  rowCount: number;
  columns: Array<{
    name: string;
    type: string;
    isPII: boolean;
    description: string;
  }>;
  redactedPiiColumnCount: number;
}

export interface QueryEngine {
  init(): Promise<void>;
  healthCheck(): Promise<boolean>;
  getActivePolicy(): ResolvedPolicy;
  getPoolStats?(): SqliteWorkerPoolStats;
  validate(sql: string, role: UserRole): ValidationResult;
  executeQuery(
    sql: string,
    role: UserRole,
    principal: string,
    execCtx?: ExecutionContextOptions
  ): Promise<QueryExecutionResult>;
  executeParameterizedQuery(
    sql: string,
    params: unknown[],
    role: UserRole,
    principal: string,
    toolName: string,
    limitApplied?: number,
    execCtx?: ExecutionContextOptions
  ): Promise<QueryExecutionResult>;
  getTables(role?: UserRole): Array<{
    name: string;
    description: string;
    rowCount: number;
    columns: string[];
  }>;
  getTableSchema(
    tableName: string,
    role?: UserRole
  ): TableSchemaInfo | null;
  getFilteredCatalog(role: UserRole): Record<string, FilteredCatalogEntry>;
  close(): Promise<void>;
}

export interface EngineFactoryOptions {
  engineType?: "sqlite" | "postgres";
  postgresOptions?: PostgresSecureAdapterOptions;
  sqliteDbPath?: string;
  policy?: ResolvedPolicy;
  policyPath?: string;
  metrics?: MetricsRegistry;
  audit?: AuditLogger;
}

/**
 * Creates or retrieves the active database query engine based on explicit policy,
 * policy file path (`MCP_SECURE_DB_POLICY_PATH`), or environment configuration.
 * Defaults to the worker-isolated SQLite engine (SecureDatabaseEngine).
 */
export function createQueryEngine(
  options: EngineFactoryOptions = {}
): QueryEngine {
  const effectivePolicyPath =
    options.policyPath ?? process.env.MCP_SECURE_DB_POLICY_PATH?.trim();

  let policy: ResolvedPolicy | undefined = options.policy;
  if (!policy && effectivePolicyPath && !options.engineType) {
    policy = loadPolicyFromFile(effectivePolicyPath);
  }

  if (policy) {
    if (policy.engine.type === "postgres") {
      const connectionString =
        options.postgresOptions?.connectionString ??
        process.env[policy.engine.connectionStringEnv] ??
        process.env.DATABASE_URL;

      if (!connectionString && !options.postgresOptions?.host) {
        throw new Error(
          `ConfigurationError: PostgreSQL policy requires environment variable '${policy.engine.connectionStringEnv}' (or connection options) to be set.`
        );
      }

      return new PostgresQueryEngine({
        connectionString,
        allowedSchemas: policy.engine.allowedSchemas,
        statementTimeoutMs: policy.engine.statementTimeoutMs,
        maxConnections: policy.engine.maxConnections,
        ssl: policy.engine.ssl,
        roleTableAllowlist: policy.roleAllowedTables,
        policy,
        ...options.postgresOptions,
      });
    }

    return new SecureDatabaseEngine({
      timeoutMs: policy.engine.statementTimeoutMs,
      sqliteDbPath: options.sqliteDbPath ?? policy.engine.sqlitePath ?? undefined,
      extraAllowedViews: policy.extraAllowedViews,
      workerPoolSize: policy.engine.workerPoolSize,
      policy,
      metrics: options.metrics,
      audit: options.audit,
    });
  }

  const engineType =
    options.engineType ??
    (process.env.MCP_SECURE_DB_ENGINE === "postgres" ? "postgres" : "sqlite");

  if (engineType === "postgres") {
    const connectionString =
      options.postgresOptions?.connectionString ?? process.env.DATABASE_URL;

    if (!connectionString && !options.postgresOptions?.host) {
      throw new Error(
        "ConfigurationError: MCP_SECURE_DB_ENGINE=postgres requires DATABASE_URL or connection options to be specified."
      );
    }

    return new PostgresQueryEngine({
      connectionString,
      policy: buildDefaultDemoPolicy("postgres"),
      ...options.postgresOptions,
    });
  }

  if (options.sqliteDbPath || options.metrics || options.audit) {
    return new SecureDatabaseEngine({
      sqliteDbPath: options.sqliteDbPath,
      metrics: options.metrics,
      audit: options.audit,
    });
  }

  return dbEngine;
}
