import { UserRole } from "../types.js";
import { TABLE_METADATA } from "../database/seed.js";

/**
 * Explicit SQLite scalar and aggregate function allowlist.
 * Any function not listed here is rejected by both the AST validator and
 * the SQLite compile-time authorizer callback.
 */
export const ALLOWED_FUNCTIONS_LIST = [
  "abs",
  "avg",
  "coalesce",
  "count",
  "date",
  "datetime",
  "ifnull",
  "iif",
  "julianday",
  "length",
  "like",
  "lower",
  "ltrim",
  "max",
  "min",
  "nullif",
  "replace",
  "round",
  "rtrim",
  "strftime",
  "substr",
  "substring",
  "sum",
  "time",
  "total",
  "trim",
  "typeof",
  "upper",
] as const;

export const ALLOWED_FUNCTIONS = new Set<string>(ALLOWED_FUNCTIONS_LIST);

/**
 * Explicit PostgreSQL scalar and aggregate function allowlist.
 * Unknown or administrative functions (e.g. pg_sleep, pg_read_file, lo_import,
 * dblink, set_config) are rejected by default.
 */
export const ALLOWED_FUNCTIONS_POSTGRES_LIST = [
  "abs",
  "avg",
  "coalesce",
  "count",
  "current_date",
  "current_time",
  "current_timestamp",
  "date_part",
  "date_trunc",
  "extract",
  "length",
  "lower",
  "ltrim",
  "max",
  "min",
  "now",
  "nullif",
  "replace",
  "round",
  "rtrim",
  "substr",
  "substring",
  "sum",
  "to_char",
  "to_date",
  "to_timestamp",
  "trim",
  "upper",
] as const;

export const ALLOWED_FUNCTIONS_POSTGRES = new Set<string>(
  ALLOWED_FUNCTIONS_POSTGRES_LIST
);

/**
 * High-risk function prefixes and administrative functions explicitly blocked
 * as defense-in-depth on PostgreSQL engines.
 */
export const POSTGRES_FORBIDDEN_FUNCTION_PREFIXES = [
  "pg_",
  "lo_",
  "dblink",
  "query_to_xml",
  "set_config",
  "current_setting",
  "version",
] as const;

/**
 * Explicit per-role base table allowlists.
 * SQLite internal catalog tables (sqlite_master, sqlite_schema, etc.) are excluded for all roles.
 */
export const ROLE_ALLOWED_TABLES: Record<UserRole, readonly string[]> = {
  unauthenticated: [],
  public_viewer: ["customers", "api_usage"],
  analyst: ["customers", "api_usage"],
  admin: ["customers", "api_usage", "security_incidents", "api_keys"],
};

export function getAllowedTablesForRole(
  role: UserRole,
  extraAllowedViews: readonly string[] = []
): Set<string> {
  const base = ROLE_ALLOWED_TABLES[role] ?? [];
  if (role === "unauthenticated") {
    return new Set<string>();
  }
  return new Set<string>([
    ...base.map((t) => t.toLowerCase()),
    ...extraAllowedViews.map((v) => v.toLowerCase()),
  ]);
}

/**
 * Sensitive PII/secret columns derived directly from TABLE_METADATA.
 */
export const PII_COLUMNS = new Set<string>(
  Object.values(TABLE_METADATA).flatMap((table) =>
    table.columns.filter((col) => col.isPII).map((col) => col.name.toLowerCase())
  )
);

export const TABLE_PII_COLUMNS: Record<string, Set<string>> = Object.fromEntries(
  Object.entries(TABLE_METADATA).map(([tableName, meta]) => [
    tableName.toLowerCase(),
    new Set(
      meta.columns
        .filter((col) => col.isPII)
        .map((col) => col.name.toLowerCase())
    ),
  ])
);

/**
 * SQLite and validator resource limits aligned with SQLite untrusted-SQL guidance.
 */
export const SQL_LIMITS = {
  maxSqlLength: 4096,
  maxAstDepth: 24,
  maxCompoundSelects: 4,
  maxCtes: 4,
  maxJoins: 4,
  maxFunctionArgs: 8,
  maxLikePatternLength: 64,
  maxAuthorizerOps: 250,
  maxRows: 1000,
  defaultLimit: 100,
  sqliteMaxPageCount: 4096,
  workerMaxOldGenerationSizeMb: 128,
  workerMaxYoungGenerationSizeMb: 32,
  workerCodeRangeSizeMb: 16,
  workerStackSizeMb: 4,
} as const;
