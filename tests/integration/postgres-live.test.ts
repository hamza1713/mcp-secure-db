import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PostgresQueryEngine } from "../../src/database/postgres-adapter.js";
import { QueryTimeoutError } from "../../src/database/engine.js";

describe("Live PostgreSQL Integration Suite (Container Verified)", () => {
  let engine: PostgresQueryEngine;
  const connectionString = process.env.PG_TEST_URL!;

  beforeAll(async () => {
    engine = new PostgresQueryEngine({
      connectionString,
      statementTimeoutMs: 1500,
      maxConnections: 5,
    });
    await engine.init();
  });

  afterAll(async () => {
    await engine.close();
  });

  it("permits authorized queries and annotates outputs with untrustedData", async () => {
    const res = await engine.executeQuery(
      "SELECT id, name, plan, created_at FROM customers ORDER BY id ASC",
      "analyst",
      "live-analyst"
    );

    expect(res.rowCount).toBe(5);
    expect(res.untrustedData).toBe(true);
    expect(res.untrustedDataNotice).toContain("untrusted user/system content");
    expect(res.rows[0].name).toBe("Acme Corp");
    expect(res.rows[0].billing_email).toBeUndefined();
  });

  it("enforces column-level database permissions: analyst reading PII fails at database level (SQLSTATE 42501)", async () => {
    // Bypass validator to prove PostgreSQL database itself denies access to billing_email for mcp_analyst
    await expect(
      engine.executeRawForTest(
        "SELECT id, billing_email FROM customers",
        "analyst",
        "live-analyst-direct"
      )
    ).rejects.toThrow(/DatabaseAuthorizationDenied/);
  });

  it("enforces database-level permission denial through CTEs (SQLSTATE 42501)", async () => {
    // Bypass validator with a CTE attempting to project restricted PII
    await expect(
      engine.executeRawForTest(
        "WITH pii_cte AS (SELECT stripe_customer_id FROM customers) SELECT * FROM pii_cte",
        "analyst",
        "live-cte-bypass"
      )
    ).rejects.toThrow(/DatabaseAuthorizationDenied/);
  });

  it("enforces read-only transaction: mutating INSERT fails at database level (SQLSTATE 25006)", async () => {
    // Bypass validator with INSERT; transaction MUST reject with 25006
    await expect(
      engine.executeRawForTest(
        "INSERT INTO customers (id, name, billing_email, stripe_customer_id, plan, created_at) VALUES (99, 'Rogue', 'r@r.com', 'cus_99', 'pro', NOW())",
        "admin",
        "live-mutation-test"
      )
    ).rejects.toThrow(/DatabaseAuthorizationDenied/);
  });

  it("enforces read-only transaction: mutating DELETE fails even for admin (SQLSTATE 25006)", async () => {
    await expect(
      engine.executeRawForTest(
        "DELETE FROM customers WHERE id = 1",
        "admin",
        "live-delete-test"
      )
    ).rejects.toThrow(/DatabaseAuthorizationDenied/);
  });

  it("cancels long-running queries via PostgreSQL statement_timeout (SQLSTATE 57014)", async () => {
    // Bypass validator to run pg_sleep with a 1500ms statement_timeout
    const timeoutEngine = new PostgresQueryEngine({
      connectionString,
      statementTimeoutMs: 800,
    });

    try {
      await expect(
        timeoutEngine.executeRawForTest(
          "SELECT pg_sleep(5)",
          "analyst",
          "live-timeout-test"
        )
      ).rejects.toThrow(QueryTimeoutError);

      // Verify connection pool recovered cleanly and can execute subsequent query
      const followUp = await timeoutEngine.executeQuery(
        "SELECT id, name FROM customers LIMIT 1",
        "analyst",
        "live-followup"
      );
      expect(followUp.rowCount).toBe(1);
    } finally {
      await timeoutEngine.close();
    }
  });

  it("terminates runaway recursive CTEs via statement_timeout (SQLSTATE 57014)", async () => {
    const timeoutEngine = new PostgresQueryEngine({
      connectionString,
      statementTimeoutMs: 800,
    });

    try {
      await expect(
        timeoutEngine.executeRawForTest(
          "WITH RECURSIVE r(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM r) SELECT * FROM r",
          "analyst",
          "live-cte-timeout"
        )
      ).rejects.toThrow(QueryTimeoutError);
    } finally {
      await timeoutEngine.close();
    }
  });

  it("denies table reads for viewer role at database level (SQLSTATE 42501)", async () => {
    // mcp_viewer has no table SELECT grants
    await expect(
      engine.executeRawForTest(
        "SELECT id, name FROM customers",
        "public_viewer",
        "live-viewer"
      )
    ).rejects.toThrow(/DatabaseAuthorizationDenied/);
  });

  it("handles concurrent query load over constrained connection pool without leaks", async () => {
    const concurrentRequests = 15;
    const promises = Array.from({ length: concurrentRequests }).map((_, i) =>
      engine.executeQuery(
        `SELECT id, name, plan FROM customers WHERE id = ${(i % 5) + 1}`,
        "analyst",
        `concurrent-agent-${i}`
      )
    );

    const results = await Promise.all(promises);
    expect(results).toHaveLength(concurrentRequests);
    for (const r of results) {
      expect(r.rowCount).toBe(1);
      expect(r.untrustedData).toBe(true);
    }
  });
});
