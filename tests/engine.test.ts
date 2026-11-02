import { describe, it, expect, beforeAll } from "vitest";
import { SecureDatabaseEngine } from "../src/database/engine.js";
import { auditLogger } from "../src/database/audit.js";

describe("SecureDatabaseEngine Sandbox", () => {
  let engine: SecureDatabaseEngine;

  beforeAll(async () => {
    engine = new SecureDatabaseEngine(5000);
    await engine.init();
  });

  it("should initialize pre-seeded tables accurately", async () => {
    const tables = engine.getTables("admin");
    expect(tables.length).toBe(4);
    const names = tables.map((t) => t.name);
    expect(names).toContain("customers");
    expect(names).toContain("api_usage");
    expect(names).toContain("security_incidents");
    expect(names).toContain("api_keys");
  });

  it("should filter out admin-only tables for public_viewer", () => {
    const tables = engine.getTables("public_viewer");
    expect(tables.length).toBe(2);
    const names = tables.map((t) => t.name);
    expect(names).toContain("customers");
    expect(names).toContain("api_usage");
    expect(names).not.toContain("security_incidents");
    expect(names).not.toContain("api_keys");
  });

  it("should execute valid analytical queries and return structured output", async () => {
    const res = await engine.executeQuery(
      "SELECT id, name, plan FROM customers WHERE plan = 'enterprise'",
      "analyst",
      "test-analyst"
    );

    expect(res.rowCount).toBe(2);
    expect(res.columns).toEqual(["id", "name", "plan"]);
    expect(res.rows[0].name).toBe("Acme Corp");
    expect(res.sandbox.externalAccess).toBe(false);
    expect(res.executionTimeMs).toBeGreaterThan(0);
  });

  it("should record successful and blocked executions in the audit ring buffer", async () => {
    auditLogger.clear();

    // Successful query
    await engine.executeQuery("SELECT id, name FROM customers", "analyst", "analyst_1");

    // Blocked mutating query
    await expect(
      engine.executeQuery("DROP TABLE customers", "analyst", "analyst_1")
    ).rejects.toThrow("SecurityASTViolation");

    const entries = auditLogger.getEntries(10);
    expect(entries.length).toBe(2);
    expect(entries[0].status).toBe("BLOCKED_AST");
    expect(entries[1].status).toBe("SUCCESS");

    const stats = auditLogger.getStats();
    expect(stats.success).toBe(1);
    expect(stats.blockedAst).toBe(1);
  });
});
