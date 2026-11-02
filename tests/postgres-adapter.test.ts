import { describe, it, expect } from "vitest";
import {
  PostgresSecureAdapter,
  DEFAULT_POSTGRES_OPTIONS,
} from "../src/database/postgres-adapter.js";

describe("PostgreSQL Secure Adapter (P4 - EXPERIMENTAL)", () => {
  const adapter = new PostgresSecureAdapter();

  it("marks adapter status as EXPERIMENTAL", () => {
    expect(adapter.status).toBe("EXPERIMENTAL");
  });

  it("builds mandatory session hardening SQL commands", () => {
    const sessionSql = adapter.buildSessionInitSql();
    expect(sessionSql).toContain(
      "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"
    );
    expect(sessionSql).toContain(
      "SET LOCAL default_transaction_read_only = on"
    );
    expect(sessionSql).toContain(
      `SET statement_timeout = '${DEFAULT_POSTGRES_OPTIONS.statementTimeoutMs}ms'`
    );
  });

  it("rejects access to PostgreSQL system catalogs and sensitive tables", () => {
    const res1 = adapter.validateQuery(
      "SELECT * FROM pg_catalog.pg_tables",
      "analyst"
    );
    expect(res1.valid).toBe(false);
    expect(res1.error).toContain("Access to system catalog 'pg_catalog' is forbidden");

    const res2 = adapter.validateQuery("SELECT * FROM pg_shadow", "analyst");
    expect(res2.valid).toBe(false);
    expect(res2.error).toContain("Access to system table 'pg_shadow' is forbidden");
  });

  it("enforces default-deny on unauthenticated callers", () => {
    const res = adapter.validateQuery(
      "SELECT id FROM customers",
      "unauthenticated"
    );
    expect(res.valid).toBe(false);
    expect(res.error).toContain("Unauthenticated callers cannot execute queries");
  });

  it("allows valid SELECT queries on allowlisted tables for authorized roles", () => {
    const res = adapter.validateQuery(
      "SELECT id, name FROM customers",
      "analyst"
    );
    expect(res.valid).toBe(true);
    expect(res.sanitizedSql).toBeDefined();
  });
});
