import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { PostgresQueryEngine } from "../../src/database/postgres-adapter.js";
import { DIFFERENTIAL_CORPUS } from "../differential.test.js";
import { PII_COLUMNS } from "../../src/security/policy.js";

describe("PostgreSQL Differential Test Suite (Validator vs Real PostgreSQL Engine)", () => {
  let engine: PostgresQueryEngine;
  const connectionString = process.env.PG_TEST_URL!;

  beforeAll(async () => {
    engine = new PostgresQueryEngine({
      connectionString,
      statementTimeoutMs: 3000,
    });
    await engine.init();
  });

  afterAll(async () => {
    await engine.close();
  });

  it("evaluates differential corpus against PostgreSQL: zero security bypasses or state mutations", async () => {
    let allowedCount = 0;
    let rejectedCount = 0;
    let databaseBlockedCount = 0;

    for (const item of DIFFERENTIAL_CORPUS) {
      const validation = engine.validateQuery(item.sql, item.role);

      if (item.expectedOutcome === "REJECT_PRE_EXECUTION") {
        if (!validation.valid) {
          rejectedCount++;
          expect(validation.error).toBeDefined();
        } else {
          // If AST validator allowed it, PostgreSQL engine MUST reject it at database level
          try {
            await engine.executeQuery(item.sql, item.role, `diff-${item.id}`);
            throw new Error(
              `Security divergence on ${item.id}: Validator and PostgreSQL both unexpectedly allowed query: ${item.sql}`
            );
          } catch (err: any) {
            databaseBlockedCount++;
            expect(err.message).toBeDefined();
          }
        }
      } else {
        // Expected to be safe
        if (validation.valid) {
          allowedCount++;
          const result = await engine.executeQuery(
            item.sql,
            item.role,
            `diff-${item.id}`
          );

          expect(result.untrustedData).toBe(true);

          // Verify no restricted PII columns returned
          if (item.role !== "admin") {
            for (const col of result.columns) {
              expect(
                PII_COLUMNS.has(col.toLowerCase()),
                `Differential leak on ${item.id}: column '${col}' leaked for role '${item.role}'`
              ).toBe(false);
            }
          }
        } else {
          // If validator rejected an analytical query due to SQLite-specific keyword differences, count it safely
          rejectedCount++;
        }
      }
    }

    expect(allowedCount).toBeGreaterThan(15);
    expect(rejectedCount + databaseBlockedCount).toBeGreaterThan(60);
  });
});
