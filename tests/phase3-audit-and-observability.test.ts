import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, it, expect, afterEach } from "vitest";
import {
  AUDIT_GENESIS_HASH,
  AuditLogger,
  verifyAuditLogFile,
} from "../src/database/audit.js";
import { MetricsRegistry } from "../src/observability/metrics.js";
import { StructuredLogger } from "../src/observability/logger.js";
import { createSecureMcpServer } from "../src/index.js";

const execFileAsync = promisify(execFile);
const CLI_PATH = path.resolve(process.cwd(), "dist", "cli.js");

function makeTempAuditPath(prefix: string): { dir: string; file: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  return { dir, file: path.join(dir, "audit.jsonl") };
}

describe("Phase 3: Tamper-Evident Audit Chain & Zero-Dependency Observability", () => {
  const cleanupDirs: string[] = [];

  afterEach(() => {
    while (cleanupDirs.length > 0) {
      const dir = cleanupDirs.pop()!;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  describe("Tamper-Evident SHA-256 / HMAC-SHA256 Audit Chaining", () => {
    it("chains entries sequentially with SHA-256, resumes across restarts, and links rotated segments with ROTATION_ANCHOR", () => {
      const { dir, file } = makeTempAuditPath("mcp-audit-chain-");
      cleanupDirs.push(dir);

      const logger1 = new AuditLogger({
        logFilePath: file,
        maxFileBytes: 1024 * 1024,
        hmacKey: "",
      });
      const e1 = logger1.log({
        requestId: "req_1",
        principal: "alice@corp.internal",
        role: "analyst",
        tenantId: "tenant_acme",
        tool: "execute_analytical_sql",
        query: "SELECT id FROM customers",
        status: "SUCCESS",
        rowCount: 5,
      });
      const e2 = logger1.log({
        requestId: "req_2",
        principal: "alice@corp.internal",
        role: "analyst",
        tenantId: "tenant_acme",
        tool: "execute_analytical_sql",
        query: "SELECT billing_email FROM customers",
        status: "BLOCKED_AST",
        reason: "PII column forbidden",
      });

      expect(e1.seq).toBe(1);
      expect(e1.prevHash).toBe(AUDIT_GENESIS_HASH);
      expect(e1.hashAlg).toBe("sha256");
      expect(e2.seq).toBe(2);
      expect(e2.prevHash).toBe(e1.entryHash);

      // Simulate process restart with a fresh AuditLogger instance targeting the same file
      const logger2 = new AuditLogger({
        logFilePath: file,
        maxFileBytes: 1024 * 1024,
        hmacKey: "",
      });
      const e3 = logger2.log({
        requestId: "req_3",
        principal: "admin@corp.internal",
        role: "admin",
        tool: "get_security_audit_log",
        query: "CALL get_security_audit_log",
        status: "SUCCESS",
      });
      expect(e3.seq).toBe(3);
      expect(e3.prevHash).toBe(e2.entryHash);

      const report = verifyAuditLogFile(file, { hmacKey: "" });
      expect(report.valid).toBe(true);
      expect(report.totalEntries).toBe(3);
      expect(report.firstSeq).toBe(1);
      expect(report.lastSeq).toBe(3);
      expect(report.lastHash).toBe(e3.entryHash);
      expect(report.algorithm).toBe("sha256");

      // Trigger size-based rotation and verify ROTATION_ANCHOR links prior segment's lastHash
      const loggerRot = new AuditLogger({
        logFilePath: file,
        maxFileBytes: 200,
        hmacKey: "",
      });
      const e5 = loggerRot.log({
        requestId: "req_4",
        principal: "admin@corp.internal",
        role: "admin",
        tool: "execute_analytical_sql",
        query: "SELECT COUNT(*) FROM customers",
        status: "SUCCESS",
      });

      const rotatedFile = `${file}.1`;
      expect(fs.existsSync(rotatedFile)).toBe(true);

      const priorReport = verifyAuditLogFile(rotatedFile, { hmacKey: "" });
      expect(priorReport.valid).toBe(true);
      expect(priorReport.lastHash).toBe(e3.entryHash);

      // Verify new segment links cryptographically to prior segment's final hash
      const activeReport = verifyAuditLogFile(file, {
        hmacKey: "",
        expectedPrevHash: priorReport.lastHash!,
        expectedStartSeq: priorReport.lastSeq! + 1,
      });
      expect(activeReport.valid).toBe(true);
      expect(activeReport.firstSeq).toBe(4); // ROTATION_ANCHOR
      expect(activeReport.lastSeq).toBe(5);
      expect(activeReport.lastHash).toBe(e5.entryHash);
    });

    it("supports keyed HMAC-SHA256 chaining and rejects missing or wrong keys", () => {
      const { dir, file } = makeTempAuditPath("mcp-audit-hmac-");
      cleanupDirs.push(dir);

      const secret = "super-secret-hmac-key-phase3";
      const logger = new AuditLogger({ logFilePath: file, hmacKey: secret });
      logger.log({
        principal: "secops@corp.internal",
        role: "admin",
        query: "SELECT 1",
        status: "SUCCESS",
      });
      logger.log({
        principal: "attacker@evil.test",
        role: "unauthenticated",
        query: "DROP TABLE customers",
        status: "BLOCKED_AUTH",
      });

      expect(verifyAuditLogFile(file, { hmacKey: secret }).valid).toBe(true);
      expect(verifyAuditLogFile(file, { hmacKey: secret }).algorithm).toBe(
        "hmac-sha256"
      );

      const missingKeyRes = verifyAuditLogFile(file, { hmacKey: "" });
      expect(missingKeyRes.valid).toBe(false);
      expect(missingKeyRes.error).toContain("MCP_SECURE_DB_AUDIT_HMAC_KEY");

      const wrongKeyRes = verifyAuditLogFile(file, { hmacKey: "wrong-key" });
      expect(wrongKeyRes.valid).toBe(false);
      expect(wrongKeyRes.failureSeq).toBe(1);
    });

    it("detects 1-byte edits, deleted lines, swapped lines, and unsigned appended entries", () => {
      const { dir, file } = makeTempAuditPath("mcp-audit-tamper-");
      cleanupDirs.push(dir);

      const logger = new AuditLogger({ logFilePath: file, hmacKey: "" });
      for (let i = 1; i <= 4; i++) {
        logger.log({
          principal: "analyst@corp.internal",
          role: "analyst",
          query: `SELECT id FROM customers LIMIT ${i}`,
          status: i === 2 ? "BLOCKED_AST" : "SUCCESS",
        });
      }

      const origLines = fs
        .readFileSync(file, "utf8")
        .trim()
        .split("\n");
      expect(origLines).toHaveLength(4);

      // (a) 1-byte modification on line 2
      const editFile = path.join(dir, "edit.jsonl");
      const edited = [...origLines];
      edited[1] = edited[1].replace("BLOCKED_AST", "SUCCESS_MOD");
      fs.writeFileSync(editFile, edited.join("\n") + "\n", "utf8");
      const editRes = verifyAuditLogFile(editFile, { hmacKey: "" });
      expect(editRes.valid).toBe(false);
      expect(editRes.failureLine).toBe(2);
      expect(editRes.failureSeq).toBe(2);

      // (b) Deleted middle line (line 2 removed)
      const delFile = path.join(dir, "delete.jsonl");
      fs.writeFileSync(
        delFile,
        [origLines[0], origLines[2], origLines[3]].join("\n") + "\n",
        "utf8"
      );
      const delRes = verifyAuditLogFile(delFile, { hmacKey: "" });
      expect(delRes.valid).toBe(false);
      expect(delRes.failureLine).toBe(2);

      // (c) Swapped lines 2 & 3
      const swapFile = path.join(dir, "swap.jsonl");
      fs.writeFileSync(
        swapFile,
        [origLines[0], origLines[2], origLines[1], origLines[3]].join("\n") + "\n",
        "utf8"
      );
      const swapRes = verifyAuditLogFile(swapFile, { hmacKey: "" });
      expect(swapRes.valid).toBe(false);
      expect(swapRes.failureLine).toBe(2);

      // (d) Appended unsigned forged entry
      const forgeFile = path.join(dir, "forge.jsonl");
      fs.writeFileSync(
        forgeFile,
        [...origLines, JSON.stringify({ id: "fake", status: "SUCCESS" })].join(
          "\n"
        ) + "\n",
        "utf8"
      );
      const forgeRes = verifyAuditLogFile(forgeFile, { hmacKey: "" });
      expect(forgeRes.valid).toBe(false);
      expect(forgeRes.failureLine).toBe(5);
    });

    it("verifies intact and tampered audit logs via CLI --verify-audit with exit codes 0 and 1", async () => {
      const { dir, file } = makeTempAuditPath("mcp-audit-cli-");
      cleanupDirs.push(dir);

      const logger = new AuditLogger({ logFilePath: file, hmacKey: "" });
      logger.log({
        principal: "admin@corp.internal",
        role: "admin",
        query: "SELECT id FROM customers",
        status: "SUCCESS",
      });

      const okRun = await execFileAsync(
        process.execPath,
        [CLI_PATH, "--verify-audit", file],
        { env: { ...process.env, MCP_SECURE_DB_AUDIT_HMAC_KEY: "" } }
      );
      const okJson = JSON.parse(okRun.stdout);
      expect(okJson.valid).toBe(true);
      expect(okJson.totalEntries).toBe(1);

      // Tamper and assert non-zero exit code 1
      fs.writeFileSync(
        file,
        fs.readFileSync(file, "utf8").replace("SUCCESS", "TAMPERD"),
        "utf8"
      );

      let exitCode = 0;
      let stdoutOnFail = "";
      try {
        await execFileAsync(
          process.execPath,
          [CLI_PATH, "--verify-audit", file],
          { env: { ...process.env, MCP_SECURE_DB_AUDIT_HMAC_KEY: "" } }
        );
      } catch (err: any) {
        exitCode = err.code ?? 1;
        stdoutOnFail = err.stdout ?? "";
      }
      expect(exitCode).toBe(1);
      const failJson = JSON.parse(stdoutOnFail);
      expect(failJson.valid).toBe(false);
      expect(failJson.failureLine).toBe(1);
    });
  });

  describe("Authenticated Prometheus /metrics & Structured requestId Correlation", () => {
    it("enforces /metrics auth (401 unauth, 403 analyst, 200 admin & METRICS_TOKEN) and emits low-cardinality Prometheus metrics", async () => {
      const { dir, file } = makeTempAuditPath("mcp-metrics-");
      cleanupDirs.push(dir);

      const prevMetricsToken = process.env.MCP_SECURE_DB_METRICS_TOKEN;
      const prevMetricsPublic = process.env.MCP_SECURE_DB_METRICS_PUBLIC;
      const prevDemo = process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS;
      process.env.MCP_SECURE_DB_METRICS_TOKEN = "metrics-secret-token-99";
      process.env.MCP_SECURE_DB_METRICS_PUBLIC = "false";
      process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS = "true";

      const logLines: string[] = [];
      const customLogger = new StructuredLogger({
        enabled: true,
        sink: (line) => logLines.push(line),
      });
      const customMetrics = new MetricsRegistry();
      const customAudit = new AuditLogger({ logFilePath: file, hmacKey: "" });

      const instance = createSecureMcpServer({
        metrics: customMetrics,
        logger: customLogger,
        audit: customAudit,
      });

      try {
        // 1. Unauthenticated /metrics -> 401
        const unauthRes = await instance.server.fetch(
          new Request("http://localhost/metrics")
        );
        expect(unauthRes.status).toBe(401);

        // 2. Analyst /metrics -> 403
        const analystRes = await instance.server.fetch(
          new Request("http://localhost/metrics", {
            headers: { authorization: "Bearer token-analyst-demo" },
          })
        );
        expect(analystRes.status).toBe(403);

        // 3. Execute a legitimate tool call and a denied call to populate counters, logs, and requestId
        const execRes = await instance.handleExecuteAnalyticalSql({
          query: "SELECT id, name FROM customers LIMIT 2",
          token: "token-analyst-demo",
        });
        expect((execRes as any).isError).toBeUndefined();
        const execBody = JSON.parse(execRes.content[0].text);
        expect(execBody.requestId).toMatch(/^req_/);

        // Structured NDJSON log captured the exact correlated requestId
        const parsedLogs = logLines.map((l) => JSON.parse(l));
        const matchedLog = parsedLogs.find(
          (l) => l.requestId === execBody.requestId && l.event === "query_executed"
        );
        expect(matchedLog).toBeDefined();
        expect(matchedLog.tool).toBe("execute_analytical_sql");
        expect(matchedLog.rowCount).toBe(2);

        // 4. Admin role can scrape /metrics -> 200
        const adminMetricsRes = await instance.server.fetch(
          new Request("http://localhost/metrics", {
            headers: { authorization: "Bearer token-admin-demo" },
          })
        );
        expect(adminMetricsRes.status).toBe(200);
        expect(adminMetricsRes.headers.get("content-type")).toContain(
          "text/plain"
        );
        const promText = await adminMetricsRes.text();
        expect(promText).toContain("mcp_secure_db_requests_total");
        expect(promText).toContain('tool="execute_analytical_sql"');
        expect(promText).toContain("mcp_secure_db_validation_duration_ms_bucket");
        expect(promText).toContain("mcp_secure_db_execution_duration_ms_bucket");
        expect(promText).toContain("mcp_secure_db_sqlite_pool_workers");
        // Verify zero high-cardinality SQL or principal leakage in Prometheus text
        expect(promText).not.toContain("analyst@demo.internal");
        expect(promText).not.toContain("SELECT id");

        // 5. Dedicated MCP_SECURE_DB_METRICS_TOKEN can scrape /metrics -> 200
        const tokenMetricsRes = await instance.server.fetch(
          new Request("http://localhost/metrics", {
            headers: { authorization: "Bearer metrics-secret-token-99" },
          })
        );
        expect(tokenMetricsRes.status).toBe(200);
      } finally {
        await instance.engine.close();
        if (prevMetricsToken === undefined)
          delete process.env.MCP_SECURE_DB_METRICS_TOKEN;
        else process.env.MCP_SECURE_DB_METRICS_TOKEN = prevMetricsToken;
        if (prevMetricsPublic === undefined)
          delete process.env.MCP_SECURE_DB_METRICS_PUBLIC;
        else process.env.MCP_SECURE_DB_METRICS_PUBLIC = prevMetricsPublic;
        if (prevDemo === undefined)
          delete process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS;
        else process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS = prevDemo;
      }
    });
  });
});
