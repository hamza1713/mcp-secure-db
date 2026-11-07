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
export const DEFAULT_ROLE_ALLOWED_TABLES: Record<UserRole, readonly string[]> = {
  unauthenticated: [],
  public_viewer: ["customers", "api_usage"],
  analyst: ["customers", "api_usage"],
  admin: ["customers", "api_usage", "security_incidents", "api_keys"],
};

export const COMPANY_ROLE_ALLOWED_TABLES: Record<UserRole, readonly string[]> = {
  unauthenticated: [],
  public_viewer: ["departments", "products"],
  analyst: ["departments", "products", "orders", "employees"],
  admin: ["departments", "products", "orders", "employees", "api_secrets"],
};

export const ROLE_ALLOWED_TABLES: Record<UserRole, readonly string[]> = {
  get unauthenticated() {
    return process.env.MCP_SECURE_DB_SQLITE_PATH
      ? COMPANY_ROLE_ALLOWED_TABLES.unauthenticated
      : DEFAULT_ROLE_ALLOWED_TABLES.unauthenticated;
  },
  get public_viewer() {
    return process.env.MCP_SECURE_DB_SQLITE_PATH
      ? COMPANY_ROLE_ALLOWED_TABLES.public_viewer
      : DEFAULT_ROLE_ALLOWED_TABLES.public_viewer;
  },
  get analyst() {
    return process.env.MCP_SECURE_DB_SQLITE_PATH
      ? COMPANY_ROLE_ALLOWED_TABLES.analyst
      : DEFAULT_ROLE_ALLOWED_TABLES.analyst;
  },
  get admin() {
    return process.env.MCP_SECURE_DB_SQLITE_PATH
      ? COMPANY_ROLE_ALLOWED_TABLES.admin
      : DEFAULT_ROLE_ALLOWED_TABLES.admin;
  },
};

const DEFAULT_ALLOWED_SETS: Record<UserRole, Set<string>> = {
  unauthenticated: new Set<string>(),
  public_viewer: new Set<string>(["customers", "api_usage"]),
  analyst: new Set<string>(["customers", "api_usage"]),
  admin: new Set<string>(["customers", "api_usage", "security_incidents", "api_keys"]),
};

const COMPANY_ALLOWED_SETS: Record<UserRole, Set<string>> = {
  unauthenticated: new Set<string>(),
  public_viewer: new Set<string>(["departments", "products"]),
  analyst: new Set<string>(["departments", "products", "orders", "employees"]),
  admin: new Set<string>(["departments", "products", "orders", "employees", "api_secrets"]),
};

let cachedEnvPath: string | undefined = undefined;
let cachedActiveSets = DEFAULT_ALLOWED_SETS;

function getActiveAllowedSets(): Record<UserRole, Set<string>> {
  const currentPath = process.env.MCP_SECURE_DB_SQLITE_PATH;
  if (currentPath !== cachedEnvPath) {
    cachedEnvPath = currentPath;
    cachedActiveSets =
      currentPath && currentPath.trim().length > 0
        ? COMPANY_ALLOWED_SETS
        : DEFAULT_ALLOWED_SETS;
  }
  return cachedActiveSets;
}

export function getAllowedTablesForRole(
  role: UserRole,
  extraAllowedViews: readonly string[] = []
): Set<string> {
  if (role === "unauthenticated") {
    return new Set<string>();
  }
  const sets = getActiveAllowedSets();
  const baseSet = sets[role] ?? sets.unauthenticated;
  if (extraAllowedViews.length === 0) {
    return new Set<string>(baseSet);
  }
  const result = new Set<string>(baseSet);
  for (const view of extraAllowedViews) {
    result.add(view.toLowerCase());
  }
  return result;
}

/**
 * Sensitive PII and secret columns derived from data models.
 */
export const PII_COLUMNS = new Set<string>([
  "billing_email",
  "stripe_customer_id",
  "client_ip",
  "webhook_secret",
  "salary_usd",
  "ssn",
  "personal_email",
  "secret_token",
]);

export const TABLE_PII_COLUMNS: Record<string, Set<string>> = {
  customers: new Set(["billing_email", "stripe_customer_id"]),
  security_incidents: new Set(["client_ip"]),
  api_keys: new Set(["webhook_secret"]),
  employees: new Set(["salary_usd", "ssn", "personal_email"]),
  api_secrets: new Set(["secret_token"]),
};

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
