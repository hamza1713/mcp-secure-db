import { describe, it, expect, afterAll } from "vitest";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { SQLValidator } from "../src/security/validator.js";
import { RBACManager } from "../src/security/rbac.js";
import { RateLimiter } from "../src/security/rate-limiter.js";
import {
  enforceResultPolicy,
  SecurityResultPolicyViolation,
} from "../src/security/result-policy.js";
import { AuditLogger, redactSensitiveLiterals } from "../src/database/audit.js";
import { SecureDatabaseEngine } from "../src/database/engine.js";
import { PostgresQueryEngine } from "../src/database/postgres-adapter.js";
import { disambiguateColumnNames } from "../src/database/row-utils.js";
import server, {
  handleExecuteAnalyticalSql,
  handleVerifyQuerySafety,
} from "../src/index.js";
import {
  defaultRateLimiter,
  validationRateLimiter,
} from "../src/security/rate-limiter.js";
import { seedCompanyDatabase } from "../scripts/seed-company-db.js";

async function sendWireRpc(
  body: Record<string, unknown>,
  headers: Record<string, string> = {}
) {
  const req = new Request("http://localhost/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const res = await server.fetch(req);
  const text = await res.text();
  if (text.trim().startsWith("{")) {
    return JSON.parse(text);
  }
  const dataLines = text
    .split(/\r?\n/)
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim())
    .filter(Boolean);
  return JSON.parse(dataLines[dataLines.length - 1]);
}

describe("Phase 1 Security Hardening & Silent Bug Regression Suite", () => {
  const sqliteVal = new SQLValidator({ dialect: "sqlite" });
  const pgVal = new SQLValidator({ dialect: "postgresql" });
  const pgEngine = new PostgresQueryEngine({
    connectionString: "postgres://u:p@127.0.0.1:5432/db",
    ssl: { rejectUnauthorized: true },
  });
  const sqliteEngine = new SecureDatabaseEngine({ timeoutMs: 2500 });

  afterAll(async () => {
    await sqliteEngine.close();
    await pgEngine.close();
  });

  describe("1. PostgreSQL AST Clause Bypasses Closed (WINDOW, FILTER, DISTINCT ON, Aggregate ORDER BY)", () => {
    const bypassVectors = [
      {
        name: "WINDOW clause calling set_config('statement_timeout', '0', TRUE)",
        sql: "SELECT id, COUNT(*) OVER w FROM customers WINDOW w AS (ORDER BY set_config('statement_timeout', '0', TRUE))",
      },
      {
        name: "WINDOW clause calling pg_sleep(5)",
        sql: "SELECT id, COUNT(*) OVER w FROM customers WINDOW w AS (ORDER BY pg_sleep(5))",
      },
      {
        name: "WINDOW clause PARTITION BY PII column",
        sql: "SELECT id, COUNT(*) OVER w FROM customers WINDOW w AS (PARTITION BY billing_email)",
      },
      {
        name: "WINDOW clause subquery reading admin table api_keys",
        sql: "SELECT id, COUNT(*) OVER w FROM customers WINDOW w AS (ORDER BY (SELECT webhook_secret FROM api_keys LIMIT 1))",
      },
      {
        name: "FILTER (WHERE pg_sleep(5) IS NULL)",
        sql: "SELECT COUNT(*) FILTER (WHERE pg_sleep(5) IS NULL) FROM customers",
      },
      {
        name: "FILTER (WHERE billing_email LIKE 'b%')",
        sql: "SELECT COUNT(*) FILTER (WHERE billing_email LIKE 'b%') FROM customers",
      },
      {
        name: "FILTER (WHERE EXISTS (SELECT 1 FROM api_keys))",
        sql: "SELECT COUNT(*) FILTER (WHERE EXISTS (SELECT 1 FROM api_keys)) FROM customers",
      },
      {
        name: "DISTINCT ON (billing_email)",
        sql: "SELECT DISTINCT ON (billing_email) id, name FROM customers",
      },
      {
        name: "DISTINCT ON subquery accessing api_keys",
        sql: "SELECT DISTINCT ON ((SELECT webhook_secret FROM api_keys LIMIT 1)) id FROM customers",
      },
      {
        name: "Aggregate ORDER BY referencing PII column",
        sql: "SELECT COUNT(name ORDER BY billing_email) FROM customers",
      },
      {
        name: "Aggregate ORDER BY calling pg_sleep(5)",
        sql: "SELECT COUNT(name ORDER BY pg_sleep(5)) FROM customers",
      },
    ];

    for (const vec of bypassVectors) {
      it(`rejects ${vec.name}`, () => {
        expect(pgVal.validate(vec.sql, "analyst").valid).toBe(false);
        expect(pgEngine.validateQuery(vec.sql, "analyst").valid).toBe(false);
      });
    }
  });

  describe("2. LIMIT offset,count & OFFSET Bounding + Worker rowCap(0)", () => {
    it("clamps count in SQLite LIMIT offset, count syntax and reports real limitInjected", () => {
      const res = sqliteVal.validate(
        "SELECT id, name FROM customers LIMIT 0, 9999999",
        "analyst"
      );
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(1000);
      expect(res.sanitizedQuery).toContain("LIMIT 0, 1000");
    });

    it("rejects excessive OFFSET in both LIMIT count OFFSET offset and LIMIT offset, count forms", () => {
      expect(
        sqliteVal.validate(
          "SELECT id FROM customers LIMIT 10 OFFSET 999999999",
          "analyst"
        ).valid
      ).toBe(false);
      expect(
        sqliteVal.validate(
          "SELECT id FROM customers LIMIT 999999999, 10",
          "analyst"
        ).valid
      ).toBe(false);
      expect(
        pgVal.validate(
          "SELECT id FROM customers LIMIT 10 OFFSET 999999999",
          "analyst"
        ).valid
      ).toBe(false);
    });

    it("returns 0 rows for LIMIT 0 instead of falling back to maxRows", async () => {
      const res = await sqliteEngine.executeQuery(
        "SELECT id, name FROM customers LIMIT 0",
        "analyst",
        "limit-zero-tester"
      );
      expect(res.limitApplied).toBe(0);
      expect(res.rowCount).toBe(0);
      expect(res.rows).toEqual([]);
    });
  });

  describe("3. Cartesian Join Protection & Operator/LIKE Hardening", () => {
    const cartesianBypasses = [
      "SELECT c.id, u.id AS uid FROM customers c JOIN api_usage u ON c.id IS NOT NULL",
      "SELECT c.id, u.id AS uid FROM customers c JOIN api_usage u ON c.id = c.id + 0",
      "SELECT c.id, u.id AS uid FROM customers c JOIN api_usage u ON (c.id) = c.id",
      "SELECT c.id, u.id AS uid FROM customers c JOIN api_usage u ON c.id != -1",
      "SELECT c.id, u.id AS uid FROM customers c JOIN api_usage u ON c.id = u.customer_id OR c.id IS NOT NULL",
      "SELECT c.id, u1.id AS u1id, u2.id AS u2id FROM customers c JOIN api_usage u1 ON c.id = u1.customer_id JOIN api_usage u2 ON c.id = u1.customer_id",
    ];

    for (const sql of cartesianBypasses) {
      it(`rejects non-correlating Cartesian join: ${sql}`, () => {
        const res = sqliteVal.validate(sql, "analyst");
        expect(res.valid).toBe(false);
        expect(res.violationReason).toContain("tautological");
      });
    }

    it("allows valid joins with extra single-table AND filters", () => {
      const res = sqliteVal.validate(
        "SELECT c.id, u.endpoint FROM customers c JOIN api_usage u ON c.id = u.customer_id AND c.plan = 'enterprise'",
        "analyst"
      );
      expect(res.valid).toBe(true);
    });

    it("rejects SQLite JSON arrow operators (-> and ->>) at Layer 2 AST", () => {
      expect(
        sqliteVal.validate("SELECT name -> 'a' FROM customers", "analyst").valid
      ).toBe(false);
      expect(
        sqliteVal.validate("SELECT name ->> 'a' FROM customers", "analyst")
          .valid
      ).toBe(false);
    });

    it("rejects dynamic/concatenated LIKE patterns bypassing maxLikePatternLength", () => {
      expect(
        sqliteVal.validate(
          "SELECT name FROM customers WHERE name LIKE 'a' || 'b' || 'c'",
          "analyst"
        ).valid
      ).toBe(false);
    });
  });

  describe("4. RBAC Hardening (Prototype Safety, Production Demo-Token Gate, Env API Keys)", () => {
    const rbac = new RBACManager();

    it("fails closed without crashing on Object.prototype keys like toString and constructor", async () => {
      for (const protoKey of [
        "toString",
        "constructor",
        "__proto__",
        "valueOf",
      ]) {
        const ctx = rbac.resolveContext(`Bearer ${protoKey}`);
        expect(ctx.role).toBe("unauthenticated");
        expect(ctx.authenticated).toBe(false);
      }

      // Wire-level verification
      const rpc = await sendWireRpc(
        { jsonrpc: "2.0", id: 201, method: "tools/list", params: {} },
        { authorization: "Bearer toString" }
      );
      expect(rpc.error).toBeUndefined();
      expect(rpc.result.tools.map((t: any) => t.name)).toEqual(["whoami"]);
    });

    it("disables static demo tokens unless explicitly enabled and ALWAYS disables them in NODE_ENV=production", () => {
      const savedNodeEnv = process.env.NODE_ENV;
      const savedDemo = process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS;
      try {
        delete process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS;
        process.env.NODE_ENV = "development";
        expect(rbac.resolveContext("token-admin-demo").role).toBe(
          "unauthenticated"
        );

        process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS = "true";
        expect(rbac.resolveContext("token-admin-demo").role).toBe("admin");

        // Even with ALLOW_DEMO_TOKENS=true, NODE_ENV=production MUST fail closed
        process.env.NODE_ENV = "production";
        expect(
          rbac.resolveContext("token-admin-demo", { allowDemoTokens: true })
            .role
        ).toBe("unauthenticated");
      } finally {
        if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = savedNodeEnv;
        if (savedDemo === undefined)
          delete process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS;
        else process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS = savedDemo;
      }
    });

    it("authenticates production API keys configured via MCP_SECURE_DB_API_KEYS using SHA-256 constant-time matching", () => {
      const savedNodeEnv = process.env.NODE_ENV;
      const savedApiKeys = process.env.MCP_SECURE_DB_API_KEYS;
      const secret = "prod_key_9f8e7d6c5b4a3210";
      const hash = crypto
        .createHash("sha256")
        .update(secret, "utf8")
        .digest("hex");

      try {
        process.env.NODE_ENV = "production";
        process.env.MCP_SECURE_DB_API_KEYS = JSON.stringify([
          {
            tokenSha256: hash,
            principal: "bi-pipeline@prod.internal",
            role: "analyst",
          },
        ]);

        const ok = rbac.resolveContext(`Bearer ${secret}`);
        expect(ok.authenticated).toBe(true);
        expect(ok.role).toBe("analyst");
        expect(ok.principal).toBe("bi-pipeline@prod.internal");

        // Demo tokens remain blocked in production
        expect(rbac.resolveContext("Bearer token-admin-demo").role).toBe(
          "unauthenticated"
        );
      } finally {
        if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = savedNodeEnv;
        if (savedApiKeys === undefined)
          delete process.env.MCP_SECURE_DB_API_KEYS;
        else process.env.MCP_SECURE_DB_API_KEYS = savedApiKeys;
      }
    });
  });

  describe("5. Wire-Level Protection for Resources & Prompts + Argument Token Gate", () => {
    it("hides resources and prompts from unauthenticated callers and rejects direct reads/gets", async () => {
      const resList = await sendWireRpc({
        jsonrpc: "2.0",
        id: 210,
        method: "resources/list",
        params: {},
      });
      expect(resList.result.resources).toEqual([]);

      const promptList = await sendWireRpc({
        jsonrpc: "2.0",
        id: 211,
        method: "prompts/list",
        params: {},
      });
      expect(promptList.result.prompts).toEqual([]);

      const readPolicy = await sendWireRpc({
        jsonrpc: "2.0",
        id: 212,
        method: "resources/read",
        params: { uri: "policy://security-rules" },
      });
      expect(readPolicy.error).toBeDefined();
      expect(readPolicy.error.message).toContain("AuthenticationRequired");

      const getPrompt = await sendWireRpc({
        jsonrpc: "2.0",
        id: 213,
        method: "prompts/get",
        params: {
          name: "executive_analytics",
          arguments: { focus: "compute" },
        },
      });
      expect(getPrompt.error).toBeDefined();
      expect(getPrompt.error.message).toContain("AuthenticationRequired");
    });

    it("grants role-appropriate resources and prompts to authenticated callers", async () => {
      const viewerPrompts = await sendWireRpc(
        { jsonrpc: "2.0", id: 214, method: "prompts/list", params: {} },
        { authorization: "Bearer token-viewer-demo" }
      );
      expect(viewerPrompts.result.prompts).toEqual([]);

      const analystPrompts = await sendWireRpc(
        { jsonrpc: "2.0", id: 215, method: "prompts/list", params: {} },
        { authorization: "Bearer token-analyst-demo" }
      );
      expect(analystPrompts.result.prompts.map((p: any) => p.name)).toEqual([
        "executive_analytics",
      ]);

      const adminPrompts = await sendWireRpc(
        { jsonrpc: "2.0", id: 216, method: "prompts/list", params: {} },
        { authorization: "Bearer token-admin-demo" }
      );
      expect(adminPrompts.result.prompts.length).toBe(2);
    });

    it("ignores tool-argument tokens when NODE_ENV=production while still honoring HTTP Authorization headers", async () => {
      const savedNodeEnv = process.env.NODE_ENV;
      const savedApiKeys = process.env.MCP_SECURE_DB_API_KEYS;
      const secret = "prod_header_only_key_123456";
      const hash = crypto
        .createHash("sha256")
        .update(secret, "utf8")
        .digest("hex");

      try {
        process.env.NODE_ENV = "production";
        process.env.MCP_SECURE_DB_API_KEYS = JSON.stringify([
          {
            tokenSha256: hash,
            principal: "svc@prod.internal",
            role: "analyst",
          },
        ]);

        // Argument token must be ignored in NODE_ENV=production
        const argAttempt = await sendWireRpc({
          jsonrpc: "2.0",
          id: 217,
          method: "tools/call",
          params: { name: "list_tables", arguments: { token: secret } },
        });
        expect(argAttempt.result.isError).toBe(true);
        expect(argAttempt.result.content[0].text).toContain(
          "AuthenticationRequired"
        );

        // HTTP Authorization header succeeds with the exact same production API key
        const headerAttempt = await sendWireRpc(
          {
            jsonrpc: "2.0",
            id: 218,
            method: "tools/call",
            params: { name: "list_tables", arguments: {} },
          },
          { authorization: `Bearer ${secret}` }
        );
        expect(headerAttempt.result.isError).toBeUndefined();
      } finally {
        if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = savedNodeEnv;
        if (savedApiKeys === undefined)
          delete process.env.MCP_SECURE_DB_API_KEYS;
        else process.env.MCP_SECURE_DB_API_KEYS = savedApiKeys;
      }
    });
  });

  describe("6. Atomic Rate Limiting (Failed/Timeout Queries Counted & Bounded Memory)", () => {
    it("counts blocked/failed queries atomically against rate limit quota", async () => {
      const limiter = new RateLimiter(
        {
          unauthenticated: { maxQueriesPerMinute: 0, maxRowsPerHour: 0 },
          public_viewer: { maxQueriesPerMinute: 2, maxRowsPerHour: 100 },
          analyst: { maxQueriesPerMinute: 3, maxRowsPerHour: 100 },
          admin: { maxQueriesPerMinute: 5, maxRowsPerHour: 100 },
        },
        60_000,
        3_600_000,
        5
      );

      const now = 5_000_000;
      expect(limiter.consumeQuerySlot("burst-user", "analyst", now).allowed).toBe(true);
      expect(limiter.consumeQuerySlot("burst-user", "analyst", now).allowed).toBe(true);
      expect(limiter.consumeQuerySlot("burst-user", "analyst", now).allowed).toBe(true);
      expect(limiter.consumeQuerySlot("burst-user", "analyst", now).allowed).toBe(false);

      // Eviction bounds tracked principals when capacity exceeded
      for (let i = 0; i < 12; i++) {
        limiter.consumeQuerySlot(`user-${i}`, "analyst", now + i * 10);
      }
      expect(limiter.getTrackedPrincipalCount()).toBeLessThanOrEqual(6);
    });

    it("enforces rate limiting on failed execute_analytical_sql and verify_query_safety calls", async () => {
      defaultRateLimiter.reset("analyst@demo.internal");
      validationRateLimiter.reset("viewer@demo.internal");

      // Trigger 60 failing queries — they MUST exhaust analyst's 60/min quota
      for (let i = 0; i < 60; i++) {
        const res: any = await handleExecuteAnalyticalSql(
          { query: "DROP TABLE customers", token: "token-analyst-demo" },
          {}
        );
        expect(res.isError).toBe(true);
      }
      const blocked: any = await handleExecuteAnalyticalSql(
        { query: "SELECT id FROM customers", token: "token-analyst-demo" },
        {}
      );
      expect(blocked.isError).toBe(true);
      expect(blocked.content[0].text).toContain("RateLimitExceeded");

      // Clean up shared singleton state for subsequent tests
      defaultRateLimiter.reset("analyst@demo.internal");

      // Verify verify_query_safety is also throttled (viewer tier = 60/min)
      for (let i = 0; i < 60; i++) {
        await handleVerifyQuerySafety(
          { query: "SELECT id FROM customers", token: "token-viewer-demo" },
          {}
        );
      }
      const valBlocked: any = await handleVerifyQuerySafety(
        { query: "SELECT id FROM customers", token: "token-viewer-demo" },
        {}
      );
      expect(valBlocked.isError).toBe(true);
      expect(valBlocked.content[0].text).toContain("RateLimitExceeded");
      validationRateLimiter.reset("viewer@demo.internal");
    });
  });

  describe("7. PostgreSQL Adapter Fixes (search_path, ssl, public.table, literals, pool error handler)", () => {
    it("allows public.customers and string literals containing pg_user", () => {
      const q1 = pgEngine.validateQuery(
        "SELECT id, name FROM public.customers LIMIT 5",
        "analyst"
      );
      expect(q1.valid).toBe(true);
      expect(q1.limitInjected).toBe(5);

      const q2 = pgEngine.validateQuery(
        "SELECT id, name FROM customers WHERE name = 'pg_user'",
        "analyst"
      );
      expect(q2.valid).toBe(true);
    });

    it("preserves ssl config when connectionString is provided and registers a pool error listener", () => {
      const pool: any = (pgEngine as any).pool;
      expect(pool.options.ssl).toEqual({ rejectUnauthorized: true });
      expect(pool.listenerCount("error")).toBeGreaterThanOrEqual(1);
    });

    it("rejects invalid or forbidden schema names in allowedSchemas", () => {
      expect(
        () =>
          new PostgresQueryEngine({
            connectionString: "postgres://u:p@127.0.0.1:5432/db",
            allowedSchemas: ["pg_catalog"],
          })
      ).toThrow(/ConfigurationError/);

      expect(
        () =>
          new PostgresQueryEngine({
            connectionString: "postgres://u:p@127.0.0.1:5432/db",
            allowedSchemas: ['public"; DROP TABLE customers; --'],
          })
      ).toThrow(/ConfigurationError/);
    });
  });

  describe("8. SQLite Engine Fixes (Duplicate Columns, Read-Only Open, No Global Env Mutation)", () => {
    it("disambiguates duplicate column names without overwriting values", async () => {
      expect(disambiguateColumnNames(["id", "name", "id", "id"])).toEqual([
        "id",
        "name",
        "id_2",
        "id_3",
      ]);

      const res = await sqliteEngine.executeQuery(
        "SELECT c.id, u.id FROM customers c JOIN api_usage u ON c.id = u.customer_id WHERE u.id = 2 LIMIT 1",
        "analyst",
        "dup-col-tester"
      );
      expect(res.columns).toEqual(["id", "id_2"]);
      expect(res.rows[0]).toEqual({ id: 1, id_2: 2 });
    });

    it("opens file-backed SQLite DBs read-only without mutating process.env globally", async () => {
      const savedEnv = process.env.MCP_SECURE_DB_SQLITE_PATH;
      delete process.env.MCP_SECURE_DB_SQLITE_PATH;
      const tmpDb = path.resolve(
        process.cwd(),
        "tests",
        "scratch",
        "phase1-ro-test.db"
      );
      seedCompanyDatabase(tmpDb);

      const fileEngine = new SecureDatabaseEngine({ sqliteDbPath: tmpDb });
      try {
        expect(process.env.MCP_SECURE_DB_SQLITE_PATH).toBeUndefined();
        const controls = await fileEngine.inspectSecurityControls();
        expect(controls.readOnlyOpen).toBe(true);
        expect(controls.defensiveMode).toBe(true);

        // Concurrent in-memory engine stays completely isolated on default schema
        const memTables = sqliteEngine.getTables("analyst").map((t) => t.name);
        const fileTables = fileEngine.getTables("analyst").map((t) => t.name);
        expect(memTables).toContain("customers");
        expect(fileTables).toContain("departments");
        expect(fileTables).not.toContain("customers");
      } finally {
        await fileEngine.close();
        if (savedEnv !== undefined) process.env.MCP_SECURE_DB_SQLITE_PATH = savedEnv;
        await new Promise((r) => setTimeout(r, 50));
        if (fs.existsSync(tmpDb)) {
          try {
            fs.unlinkSync(tmpDb);
          } catch {
            // ignore cleanup lock
          }
        }
      }
    });
  });

  describe("9. Result Policy & Audit Logger Hardening", () => {
    it("allows software version numbers like 1.2.3.4 in version columns without IPv4 false positives", () => {
      expect(() =>
        enforceResultPolicy({
          role: "analyst",
          columns: ["app_version"],
          rows: [{ app_version: "1.2.3.4" }],
        })
      ).not.toThrow();

      // Still blocks real IPv4 values in non-version columns
      expect(() =>
        enforceResultPolicy({
          role: "analyst",
          columns: ["source_host"],
          rows: [{ source_host: "198.51.100.44" }],
        })
      ).toThrow(SecurityResultPolicyViolation);
    });

    it("writes persisted:true on disk, redacts reason + SSNs + JWTs, and tail-reads accurately", () => {
      const logPath = path.resolve(
        process.cwd(),
        "tests",
        "scratch",
        "phase1-audit-verify.jsonl"
      );
      if (fs.existsSync(logPath)) fs.unlinkSync(logPath);

      const logger = new AuditLogger({
        maxSize: 5,
        logFilePath: logPath,
        enablePersistence: true,
        tailReadBytes: 2048,
      });

      const entry = logger.log({
        principal: "sec-tester",
        role: "analyst",
        tool: "execute_analytical_sql",
        query:
          "SELECT '982-41-1029', 'stripe_mock_secret_998124018274' FROM customers",
        status: "BLOCKED_RESULT_POLICY",
        reason:
          "Leaked SSN 982-41-1029 and token token-admin-demo and JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
      });

      expect(entry.persisted).toBe(true);
      expect(entry.reason).toContain("[REDACTED_SSN]");
      expect(entry.reason).toContain("[REDACTED_TOKEN]");
      expect(entry.reason).toContain("[REDACTED_JWT]");

      const diskLines = fs
        .readFileSync(logPath, "utf8")
        .trim()
        .split("\n")
        .map((l) => JSON.parse(l));
      expect(diskLines[0].persisted).toBe(true);
      expect(diskLines[0].query).toContain("[REDACTED_SSN]");
      expect(diskLines[0].query).toContain("[REDACTED_TOKEN]");

      // Redact helper standalone check
      expect(redactSensitiveLiterals("SSN 123-45-6789")).toBe(
        "SSN [REDACTED_SSN]"
      );

      if (fs.existsSync(logPath)) fs.unlinkSync(logPath);
    });
  });
});
