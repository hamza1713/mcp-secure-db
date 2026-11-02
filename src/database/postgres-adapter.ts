import { UserRole } from "../types.js";
import { SQLValidator } from "../security/validator.js";
import { ROLE_ALLOWED_TABLES } from "../security/policy.js";

/**
 * Status: EXPERIMENTAL
 *
 * PostgreSQL secure adapter configuration.
 * When deployed against a real PostgreSQL instance, this adapter enforces:
 * 1. Dedicated read-only database role (never superuser or table owner)
 * 2. Transaction-level read-only enforcement (`SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY`)
 * 3. Session-level statement timeouts (`SET statement_timeout = '3000ms'`) [E:CLAIM-043]
 * 4. Schema and system catalog restrictions (rejecting `pg_catalog`, `information_schema`, `pg_shadow`)
 * 5. Pre-execution AST validation via SQLValidator
 *
 * Caveat: In environments without a live PostgreSQL cluster, this adapter is tested
 * via protocol and configuration tests; live integration remains marked EXPERIMENTAL.
 */

export interface PostgresSecureAdapterOptions {
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  password?: string;
  ssl?: boolean;
  statementTimeoutMs?: number;
  idleTimeoutMs?: number;
  allowedSchemas?: string[];
  roleTableAllowlist?: Record<UserRole, readonly string[]>;
}

export const DEFAULT_POSTGRES_OPTIONS: Required<
  Omit<PostgresSecureAdapterOptions, "password">
> = {
  host: "127.0.0.1",
  port: 5432,
  database: "mcp_analytics",
  user: "analytics_readonly",
  ssl: true,
  statementTimeoutMs: 3000,
  idleTimeoutMs: 5000,
  allowedSchemas: ["public", "analytics"],
  roleTableAllowlist: ROLE_ALLOWED_TABLES,
};

export const FORBIDDEN_POSTGRES_SCHEMAS = new Set([
  "pg_catalog",
  "information_schema",
  "pg_toast",
  "pg_temp",
]);

export const FORBIDDEN_POSTGRES_TABLES = new Set([
  "pg_shadow",
  "pg_authid",
  "pg_database",
  "pg_user",
  "pg_roles",
  "pg_settings",
  "pg_stat_activity",
  "pg_tablespace",
]);

export class PostgresSecureAdapter {
  public readonly status = "EXPERIMENTAL" as const;
  private readonly options: Required<
    Omit<PostgresSecureAdapterOptions, "password">
  >;
  private readonly validator: SQLValidator;

  constructor(options: PostgresSecureAdapterOptions = {}) {
    this.options = {
      host: options.host ?? DEFAULT_POSTGRES_OPTIONS.host,
      port: options.port ?? DEFAULT_POSTGRES_OPTIONS.port,
      database: options.database ?? DEFAULT_POSTGRES_OPTIONS.database,
      user: options.user ?? DEFAULT_POSTGRES_OPTIONS.user,
      ssl: options.ssl ?? DEFAULT_POSTGRES_OPTIONS.ssl,
      statementTimeoutMs:
        options.statementTimeoutMs ??
        DEFAULT_POSTGRES_OPTIONS.statementTimeoutMs,
      idleTimeoutMs:
        options.idleTimeoutMs ?? DEFAULT_POSTGRES_OPTIONS.idleTimeoutMs,
      allowedSchemas:
        options.allowedSchemas ?? DEFAULT_POSTGRES_OPTIONS.allowedSchemas,
      roleTableAllowlist:
        options.roleTableAllowlist ??
        DEFAULT_POSTGRES_OPTIONS.roleTableAllowlist,
    };
    this.validator = new SQLValidator();
  }

  /**
   * Generates the mandatory session hardening commands to be executed
   * immediately upon establishing any client connection.
   */
  public buildSessionInitSql(): string[] {
    return [
      "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
      "SET LOCAL default_transaction_read_only = on",
      `SET statement_timeout = '${this.options.statementTimeoutMs}ms'`,
      `SET idle_in_transaction_session_timeout = '${this.options.idleTimeoutMs}ms'`,
      "SET search_path = public",
    ];
  }

  /**
   * Validates a SQL statement against PostgreSQL specific security constraints:
   * 1. Rejects forbidden schemas (e.g. pg_catalog, information_schema)
   * 2. Rejects sensitive system tables (e.g. pg_shadow, pg_authid)
   * 3. Runs general AST validation (SELECT-only, table allowlists, function allowlists)
   */
  public validateQuery(
    sql: string,
    role: UserRole
  ): { valid: boolean; error?: string; sanitizedSql?: string } {
    if (role === "unauthenticated") {
      return {
        valid: false,
        error: "Unauthenticated callers cannot execute queries.",
      };
    }

    const lowerSql = sql.toLowerCase();

    // Reject direct access to forbidden PostgreSQL catalogs
    for (const schema of FORBIDDEN_POSTGRES_SCHEMAS) {
      const pattern = new RegExp(`\\b${schema}\\b`, "i");
      if (pattern.test(lowerSql)) {
        return {
          valid: false,
          error: `Access to system catalog '${schema}' is forbidden.`,
        };
      }
    }

    for (const tbl of FORBIDDEN_POSTGRES_TABLES) {
      const pattern = new RegExp(`\\b${tbl}\\b`, "i");
      if (pattern.test(lowerSql)) {
        return {
          valid: false,
          error: `Access to system table '${tbl}' is forbidden.`,
        };
      }
    }

    // Run core AST validation
    const valResult = this.validator.validate(sql, role);
    if (!valResult.valid) {
      return {
        valid: false,
        error: valResult.violationReason,
      };
    }

    return {
      valid: true,
      sanitizedSql: valResult.sanitizedQuery,
    };
  }

  public getOptions() {
    return { ...this.options };
  }
}
