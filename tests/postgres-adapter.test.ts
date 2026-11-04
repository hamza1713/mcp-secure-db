import { describe, it, expect, afterAll } from "vitest";
import {
  PostgresQueryEngine,
  DEFAULT_POSTGRES_OPTIONS,
} from "../src/database/postgres-adapter.js";
import { createQueryEngine } from "../src/database/query-engine.js";

describe("PostgreSQL Secure Adapter Unit Suite", () => {
  const engine = new PostgresQueryEngine();

  afterAll(async () => {
    await engine.close();
  });

  it("marks adapter status as SUPPORTED", () => {
    expect(engine.status).toBe("SUPPORTED");
  });

  it("builds mandatory per-query transaction session hardening commands", () => {
    const sessionSql = engine.buildSessionInitSql("analyst");
    expect(sessionSql).toContain(
      "BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ"
    );
    expect(sessionSql).toContain("SET LOCAL ROLE mcp_analyst");
    expect(sessionSql).toContain(
      `SET LOCAL statement_timeout = '${DEFAULT_POSTGRES_OPTIONS.statementTimeoutMs}ms'`
    );
    expect(sessionSql).toContain("SET LOCAL lock_timeout = '500ms'");
    expect(sessionSql).toContain(
      `SET LOCAL idle_in_transaction_session_timeout = '${DEFAULT_POSTGRES_OPTIONS.idleTimeoutMs}ms'`
    );
    expect(sessionSql).toContain('SET LOCAL search_path = "public"');
  });

  it("rejects access to PostgreSQL system catalogs and sensitive tables", () => {
    const res1 = engine.validateQuery(
      "SELECT * FROM pg_catalog.pg_tables",
      "analyst"
    );
    expect(res1.valid).toBe(false);
    expect(res1.error).toContain("Access to system catalog 'pg_catalog' is forbidden");

    const res2 = engine.validateQuery("SELECT * FROM pg_shadow", "analyst");
    expect(res2.valid).toBe(false);
    expect(res2.error).toContain("Access to system table 'pg_shadow' is forbidden");
  });

  it("enforces default-deny on unauthenticated callers", () => {
    const res = engine.validateQuery(
      "SELECT id FROM customers",
      "unauthenticated"
    );
    expect(res.valid).toBe(false);
    expect(res.error).toContain("Unauthenticated callers cannot execute queries");
  });

  it("allows valid SELECT queries on allowlisted tables for authorized roles", () => {
    const res = engine.validateQuery(
      "SELECT id, name FROM customers",
      "analyst"
    );
    expect(res.valid).toBe(true);
    expect(res.sanitizedSql).toBeDefined();
  });

  it("validates PostgreSQL specific syntax (type casts, double quotes)", () => {
    const res = engine.validateQuery(
      'SELECT id, name, created_at::TEXT FROM "customers" WHERE id = 1',
      "analyst"
    );
    expect(res.valid).toBe(true);
    expect(res.sanitizedSql).toBeDefined();
  });

  it("rejects dangerous or unapproved PostgreSQL administrative functions", () => {
    const res1 = engine.validateQuery("SELECT pg_sleep(5)", "analyst");
    expect(res1.valid).toBe(false);
    expect(res1.error).toContain("not in the permitted PostgreSQL function allowlist");

    const res2 = engine.validateQuery(
      "SELECT set_config('statement_timeout', '10000', false)",
      "analyst"
    );
    expect(res2.valid).toBe(false);
    expect(res2.error).toContain("not in the permitted PostgreSQL function allowlist");
  });

  it("createQueryEngine switches engine based on configuration", () => {
    const sqliteEng = createQueryEngine({ engineType: "sqlite" });
    expect(sqliteEng).toBeDefined();
    expect(sqliteEng.getTables("analyst")).toHaveLength(2);

    expect(() => {
      createQueryEngine({ engineType: "postgres", postgresOptions: {} });
    }).toThrow("ConfigurationError");

    const pgEng = createQueryEngine({
      engineType: "postgres",
      postgresOptions: { connectionString: "postgres://test:test@localhost:5432/db" },
    });
    expect(pgEng).toBeInstanceOf(PostgresQueryEngine);
    void pgEng.close();
  });
});
