import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { AuditLogger, redactSensitiveLiterals } from "../src/database/audit.js";

describe("Persistent Redacted Audit Logger (P4)", () => {
  const tempLogPath = path.resolve(process.cwd(), "tests", "scratch", "test-audit.jsonl");
  let logger: AuditLogger;

  beforeEach(() => {
    if (fs.existsSync(tempLogPath)) {
      fs.unlinkSync(tempLogPath);
    }
    logger = new AuditLogger({
      maxSize: 10,
      logFilePath: tempLogPath,
      enablePersistence: true,
    });
  });

  afterEach(() => {
    if (fs.existsSync(tempLogPath)) {
      try {
        fs.unlinkSync(tempLogPath);
      } catch {
        // ignore cleanup error
      }
    }
  });

  it("redacts sensitive literals (email, stripe tokens, bearer tokens, IP addresses)", () => {
    const rawSql =
      "SELECT * FROM customers WHERE email = 'alice@example.com' AND stripe_id = 'cus_1234567890abc' AND ip = '192.168.1.50' -- auth Bearer secret_token_xyz_12345678";
    const redacted = redactSensitiveLiterals(rawSql);

    expect(redacted).not.toContain("alice@example.com");
    expect(redacted).not.toContain("cus_1234567890abc");
    expect(redacted).not.toContain("192.168.1.50");
    expect(redacted).toContain("[REDACTED_EMAIL]");
    expect(redacted).toContain("[REDACTED_TOKEN]");
    expect(redacted).toContain("[REDACTED_IP]");
  });

  it("appends redacted entries to persistent JSONL file and maintains in-memory buffer", () => {
    const entry = logger.log({
      principal: "agent-test",
      role: "analyst",
      tool: "execute_analytical_sql",
      query: "SELECT id FROM customers WHERE email = 'target@corp.com'",
      status: "SUCCESS",
      rowCount: 5,
      executionTimeMs: 1.25,
    });

    expect(entry.persisted).toBe(true);
    expect(entry.query).toContain("[REDACTED_EMAIL]");

    // Verify in-memory buffer
    const inMem = logger.getEntries();
    expect(inMem).toHaveLength(1);
    expect(inMem[0].id).toBe(entry.id);

    // Verify persistent file
    expect(fs.existsSync(tempLogPath)).toBe(true);
    const persistent = logger.getPersistentEntries();
    expect(persistent).toHaveLength(1);
    expect(persistent[0].query).toContain("[REDACTED_EMAIL]");
    expect(persistent[0].query).not.toContain("target@corp.com");
  });

  it("sets ruleFired automatically on blocked security status", () => {
    const entry = logger.log({
      principal: "adversary",
      role: "unauthenticated",
      tool: "execute_analytical_sql",
      query: "DROP TABLE customers",
      status: "BLOCKED_AST",
      reason: "Only SELECT queries are allowed.",
    });

    expect(entry.ruleFired).toBe("BLOCKED_AST");
  });
});
