import { describe, it, expect, afterAll } from "vitest";
import {
  SecureDatabaseEngine,
  QueryTimeoutError,
} from "../src/database/engine.js";
import { auditLogger } from "../src/database/audit.js";

describe("Worker-Isolated SQLite Hardening Controls (P0-1 & P0-2)", () => {
  const engine = new SecureDatabaseEngine({
    timeoutMs: 2500,
    extraSeedSql: `
      CREATE VIEW v_public_customers AS SELECT id, name, plan FROM customers;
      CREATE VIEW v_customer_contacts AS SELECT id, name, billing_email AS public_contact FROM customers;
    `,
    extraAllowedViews: ["v_public_customers", "v_customer_contacts"],
  });

  afterAll(async () => {
    await engine.close();
  });

  it("enforces a hard worker-thread deadline by terminating the worker on a slow recursive CTE", async () => {
    const shortDeadlineEngine = new SecureDatabaseEngine({ timeoutMs: 200 });
    try {
      await shortDeadlineEngine.init();
      auditLogger.clear();

      const slowRecursiveCte = `
        WITH RECURSIVE spin(n) AS (
          SELECT 1
          UNION ALL
          SELECT n + 1 FROM spin WHERE n < 500000000
        )
        SELECT SUM(n) AS total FROM spin
      `;

      const started = performance.now();
      await expect(
        shortDeadlineEngine.executeQuery(
          slowRecursiveCte,
          "analyst",
          "deadline-tester"
        )
      ).rejects.toThrow(QueryTimeoutError);
      const elapsedMs = performance.now() - started;

      // Proves the main thread killed the worker rather than waiting for 500M rows
      expect(elapsedMs).toBeLessThan(2500);
      expect(shortDeadlineEngine.getWorkerTerminationCount()).toBe(1);

      const logs = auditLogger.getEntries(5);
      expect(logs[0]?.status).toBe("TIMEOUT");

      // Proves a clean worker is respawned automatically for subsequent queries
      const recovery = await shortDeadlineEngine.executeQuery(
        "SELECT id, name FROM customers WHERE id = 1",
        "analyst",
        "deadline-tester"
      );
      expect(recovery.rowCount).toBe(1);
      expect(recovery.rows[0]?.name).toBe("Acme Corp");
    } finally {
      await shortDeadlineEngine.close();
    }
  });

  it("verifies all SQLite recommended security pragmas, defensive mode, and worker resource limits are active", async () => {
    const report = await engine.inspectSecurityControls();

    expect(report.workerThread).toBe(true);
    expect(report.defensiveMode).toBe(true);
    expect(report.loadExtensionDisabled).toBe(true);
    expect(report.queryOnlyPragma).toBe(1);
    expect(report.trustedSchemaPragma).toBe(0);
    expect(report.cellSizeCheckPragma).toBe(1);
    expect(report.maxPageCountPragma).toBe(4096);
    expect(report.tempStorePragma).toBe(2); // 2 = MEMORY in SQLite
    expect(report.authorizerActive).toBe(true);
    expect(report.workerResourceLimits.maxOldGenerationSizeMb).toBe(128);
    expect(report.workerResourceLimits.maxYoungGenerationSizeMb).toBe(32);
  });

  it("blocks DDL, DML, PRAGMA, ATTACH, sqlite_master, and non-allowlisted functions directly inside SQLite setAuthorizer", async () => {
    await expect(
      engine.executeRawInWorkerForTest(
        "INSERT INTO customers VALUES (99, 'X', 'x@y.com', 'cus_x', 'pro', 'now')",
        "admin"
      )
    ).rejects.toThrow(/SQLiteAuthorizerDenied/);

    await expect(
      engine.executeRawInWorkerForTest("PRAGMA table_info(customers)", "admin")
    ).rejects.toThrow(/SQLiteAuthorizerDenied/);

    await expect(
      engine.executeRawInWorkerForTest(
        "ATTACH DATABASE ':memory:' AS extra",
        "admin"
      )
    ).rejects.toThrow(/SQLiteAuthorizerDenied/);

    await expect(
      engine.executeRawInWorkerForTest(
        "SELECT sql FROM sqlite_master",
        "admin"
      )
    ).rejects.toThrow(/SQLiteAuthorizerDenied/);

    await expect(
      engine.executeRawInWorkerForTest(
        "SELECT printf('%s', name) FROM customers",
        "analyst"
      )
    ).rejects.toThrow(/SQLiteAuthorizerDenied/);

    await expect(
      engine.executeRawInWorkerForTest("SELECT randomblob(32)", "analyst")
    ).rejects.toThrow(/SQLiteAuthorizerDenied/);

    await expect(
      engine.executeRawInWorkerForTest("SELECT sqlite_version()", "analyst")
    ).rejects.toThrow(/SQLiteAuthorizerDenied/);
  });

  it("blocks underlying PII columns resolved through a SQL VIEW via SQLite setAuthorizer", async () => {
    // Analyst can query a safe view whose DDL touches only non-PII columns
    const safeRes = await engine.executeQuery(
      "SELECT id, name, plan FROM v_public_customers",
      "analyst",
      "view-analyst"
    );
    expect(safeRes.rowCount).toBe(5);

    // Any view whose definition touches customers.billing_email fails closed at SQLite compile time!
    await expect(
      engine.executeQuery(
        "SELECT id, public_contact FROM v_customer_contacts",
        "analyst",
        "view-analyst"
      )
    ).rejects.toThrow(/SQLiteAuthorizerDenied.*customers\.billing_email/);
  });

  it("enforces compile-time authorizer operation cap on overly complex statements", async () => {
    const tightOpsEngine = new SecureDatabaseEngine({ maxAuthorizerOps: 6 });
    try {
      await expect(
        tightOpsEngine.executeRawInWorkerForTest(
          "SELECT LOWER(TRIM(COALESCE(UPPER(SUBSTR(name, 1, 4)), plan))) FROM customers WHERE id > 0",
          "analyst"
        )
      ).rejects.toThrow(/maxAuthorizerOps/);
    } finally {
      await tightOpsEngine.close();
    }
  });
});
