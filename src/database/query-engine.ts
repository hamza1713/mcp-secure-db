import { QueryExecutionResult, UserRole } from "../types.js";
import { SecureDatabaseEngine, dbEngine } from "./engine.js";
import {
  PostgresQueryEngine,
  PostgresSecureAdapterOptions,
} from "./postgres-adapter.js";

export interface QueryEngine {
  init(): Promise<void>;
  executeQuery(
    sql: string,
    role: UserRole,
    principal: string
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
  ): {
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
  } | null;
  close(): Promise<void>;
}

export interface EngineFactoryOptions {
  engineType?: "sqlite" | "postgres";
  postgresOptions?: PostgresSecureAdapterOptions;
}

/**
 * Creates or retrieves the active database query engine based on environment configuration.
 * Defaults to the worker-isolated SQLite engine (SecureDatabaseEngine).
 */
export function createQueryEngine(options: EngineFactoryOptions = {}): QueryEngine {
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
      ...options.postgresOptions,
    });
  }

  return dbEngine;
}
