import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, it, expect } from "vitest";
import {
  QueryTimeoutError,
  SecureDatabaseEngine,
} from "../src/database/engine.js";
import { runSecurityShowcase } from "../scripts/security-showcase.js";

const execFileAsync = promisify(execFile);
const CLI_PATH = path.resolve(process.cwd(), "dist", "cli.js");
const MULTI_TENANT_POLICY = path.resolve(
  process.cwd(),
  "examples",
  "policies",
  "multi-tenant-saas.policy.yaml"
);

describe("Phase 3: Multi-Worker SQLite Pool Fault Isolation & Showcase", () => {
  it("isolates a runaway recursive CTE kill to one worker while sibling workers serve concurrent queries", async () => {
    const engine = new SecureDatabaseEngine({
      timeoutMs: 250,
      workerPoolSize: 2,
    });

    try {
      await engine.init();
      const initialStats = engine.getPoolStats();
      expect(initialStats.poolSize).toBe(2);
      expect(initialStats.activeWorkers).toBe(1);

      const runawaySql =
        "WITH RECURSIVE spin(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM spin WHERE n < 20000000) SELECT SUM(n) AS total FROM spin";
      const fastSql = "SELECT COUNT(*) AS cnt FROM customers";

      const fastStart = performance.now();
      const runawayPromise = engine.executeQuery(
        runawaySql,
        "analyst",
        "attacker@test.internal"
      );
      // Prevent unhandled rejection if runaway rejects before we inspect settled outcomes
      runawayPromise.catch(() => {});

      const fastPromise = engine.executeQuery(
        fastSql,
        "analyst",
        "analyst@test.internal"
      );

      // Fast query should finish on Worker #2 WITHOUT waiting for Worker #1's timeout
      const fastResult = await fastPromise;
      const fastElapsedMs = performance.now() - fastStart;
      expect(fastResult.rows[0].cnt).toBe(5);
      expect(fastResult.sandbox.engine).toContain("pool x2");
      expect(fastElapsedMs).toBeLessThan(1500);

      // Runaway query on Worker #1 must terminate with QueryTimeoutError
      await expect(runawayPromise).rejects.toThrow(QueryTimeoutError);
      expect(engine.getWorkerTerminationCount()).toBe(1);

      // Subsequent concurrent queries succeed after clean respawn
      const [r1, r2] = await Promise.all([
        engine.executeQuery("SELECT id, name FROM customers LIMIT 2", "analyst", "a@test"),
        engine.executeQuery("SELECT id, endpoint FROM api_usage LIMIT 3", "analyst", "b@test"),
      ]);
      expect(r1.rowCount).toBe(2);
      expect(r2.rowCount).toBe(3);

      const finalStats = engine.getPoolStats();
      expect(finalStats.busyWorkers).toBe(0);
      expect(finalStats.queuedQueries).toBe(0);
      expect(finalStats.totalTerminations).toBe(1);
    } finally {
      await engine.close();
    }
  }, 15000);

  it("validates examples/policies/multi-tenant-saas.policy.yaml via CLI --validate-policy", async () => {
    const { stdout } = await execFileAsync(process.execPath, [
      CLI_PATH,
      "--validate-policy",
      "--config",
      MULTI_TENANT_POLICY,
    ]);
    const parsed = JSON.parse(stdout);
    expect(parsed.valid).toBe(true);
    expect(parsed.validatedTemplates).toHaveLength(1);
    expect(parsed.validatedTemplates[0].name).toBe("tenant_usage_summary");
    expect(parsed.validatedTemplates[0].contextParams).toEqual([
      "ctx.tenant_id",
    ]);
  }, 15000);

  it("executes the end-to-end 60-second security showcase cleanly", async () => {
    const result = await runSecurityShowcase({ quiet: true });
    expect(result.stagesPassed).toBe(6);
    expect(result.verifiedAuditEntries).toBeGreaterThanOrEqual(6);
  }, 15000);
});
