import { describe, it, expect } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import {
  loadPolicyFromFile,
  resolvePolicyObject,
} from "../src/policy/loader.js";
import { createSecureMcpServer } from "../src/index.js";

const ROOT_DIR = path.resolve(process.cwd());
const CLI_PATH = path.join(ROOT_DIR, "dist", "cli.js");
const DEMO_SAAS_POLICY = path.join(
  ROOT_DIR,
  "examples",
  "policies",
  "demo-saas.policy.yaml"
);
const COMPANY_POLICY = path.join(
  ROOT_DIR,
  "examples",
  "policies",
  "company-sqlite.policy.yaml"
);
const PG_TEMPLATES_POLICY = path.join(
  ROOT_DIR,
  "examples",
  "policies",
  "postgres-templates-only.policy.yaml"
);

async function sendRpc(
  srv: { fetch: (req: Request) => Promise<Response> },
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
  const res = await srv.fetch(req);
  const text = await res.text();
  if (text.trim().startsWith("{")) return JSON.parse(text);
  const dataLines = text
    .split(/\r?\n/)
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim())
    .filter(Boolean);
  return JSON.parse(dataLines[dataLines.length - 1]);
}

function runStdioSession(
  args: string[],
  requests: Record<string, unknown>[],
  extraEnv: Record<string, string> = {}
): Promise<{ responses: any[]; stderr: string; exitCode: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI_PATH, ...args], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        MCP_SECURE_DB_AUDIT_PATH: "tests/scratch/vitest-stdio-audit.jsonl",
        ...extraEnv,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdoutBuf = "";
    let stderrBuf = "";
    child.stdout.on("data", (chunk) => {
      stdoutBuf += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderrBuf += chunk.toString("utf8");
    });
    child.on("error", reject);

    for (const req of requests) {
      child.stdin.write(JSON.stringify(req) + "\n");
    }
    child.stdin.end();

    child.on("close", (code) => {
      const lines = stdoutBuf
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      try {
        const responses = lines.map((l) => JSON.parse(l));
        resolve({ responses, stderr: stderrBuf, exitCode: code });
      } catch (err) {
        reject(
          new Error(
            `Non-JSON stdout leaked in stdio transport: ${stdoutBuf}\nstderr: ${stderrBuf}\nerr: ${err}`
          )
        );
      }
    });
  });
}

describe("Phase 2: Parameterized Safe Templates, Health Probes & Stdio CLI", () => {
  describe("Hybrid Parameterized Templates & Templates-Only Mode", () => {
    it("binds SQL injection payloads safely as native parameters without injection", async () => {
      const policy = loadPolicyFromFile(DEMO_SAAS_POLICY);
      const instance = createSecureMcpServer({ policy });
      try {
        await instance.validateTemplates();

        // Legitimate call succeeds
        const okRpc = await sendRpc(
          instance.server,
          {
            jsonrpc: "2.0",
            id: 1,
            method: "tools/call",
            params: {
              name: "get_customer_usage_summary",
              arguments: { plan: "enterprise" },
            },
          },
          { authorization: "Bearer token-viewer-demo" }
        );
        expect(okRpc.result.isError).toBeUndefined();
        const okBody = JSON.parse(okRpc.result.content[0].text);
        expect(okBody.rowCount).toBe(2);

        // Injection payload in enum field is rejected by Zod before touching DB
        const injEnumRpc = await sendRpc(
          instance.server,
          {
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
              name: "get_customer_usage_summary",
              arguments: { plan: "enterprise' OR '1'='1'; DROP TABLE customers; --" },
            },
          },
          { authorization: "Bearer token-viewer-demo" }
        );
        expect(injEnumRpc.error || injEnumRpc.result?.isError).toBeTruthy();

        // Verify customers table is completely intact
        const check = await instance.engine.executeQuery(
          "SELECT COUNT(*) AS cnt FROM customers",
          "analyst",
          "verifier"
        );
        expect(check.rows[0].cnt).toBe(5);
      } finally {
        await instance.engine.close();
      }
    });

    it("fails fast during validateTemplates() if a template attempts mutation or exposes PII to non-admins", async () => {
      const badMutationPolicy = resolvePolicyObject(
        {
          version: 1,
          engine: { type: "sqlite" },
          roles: {
            public_viewer: { tables: ["customers"] },
            analyst: { tables: ["customers"] },
            admin: { tables: ["customers"], allow_pii: true },
          },
          templates: [
            {
              name: "rogue_delete",
              description: "Should fail startup validation",
              allowed_roles: ["admin"],
              sql: "DELETE FROM customers WHERE id = :id",
              parameters: { id: { type: "integer" } },
            },
          ],
        },
        ROOT_DIR
      );

      const inst1 = createSecureMcpServer({ policy: badMutationPolicy });
      await expect(inst1.validateTemplates()).rejects.toThrow(
        /TemplateSecurityViolation/
      );
      await inst1.engine.close();

      const badPiiPolicy = resolvePolicyObject(
        {
          version: 1,
          engine: { type: "sqlite" },
          roles: {
            public_viewer: { tables: ["customers"] },
            analyst: { tables: ["customers"] },
            admin: { tables: ["customers"], allow_pii: true },
          },
          pii: {
            columns: { customers: ["billing_email"] },
          },
          templates: [
            {
              name: "leak_emails",
              description: "Exposes PII to analyst",
              allowed_roles: ["analyst"],
              sql: "SELECT id, billing_email FROM customers LIMIT 10",
            },
          ],
        },
        ROOT_DIR
      );

      const inst2 = createSecureMcpServer({ policy: badPiiPolicy });
      await expect(inst2.validateTemplates()).rejects.toThrow(
        /TemplateSecurityViolation.*billing_email/
      );
      await inst2.engine.close();
    });

    it("locks down to templates-only mode when adhoc_sql.enabled is false", async () => {
      const lockedPolicy = resolvePolicyObject(
        {
          version: 1,
          engine: { type: "sqlite" },
          adhoc_sql: { enabled: false },
          roles: {
            public_viewer: { tables: ["customers"] },
            analyst: { tables: ["customers", "api_usage"] },
            admin: { tables: ["customers", "api_usage"], allow_pii: true },
          },
          templates: [
            {
              name: "safe_plan_counts",
              description: "Count customers by subscription plan",
              allowed_roles: ["analyst", "admin"],
              sql: "SELECT plan, COUNT(id) AS cnt FROM customers GROUP BY plan LIMIT 10",
            },
          ],
        },
        ROOT_DIR
      );

      const inst = createSecureMcpServer({ policy: lockedPolicy });
      try {
        await inst.validateTemplates();

        const listRpc = await sendRpc(
          inst.server,
          { jsonrpc: "2.0", id: 10, method: "tools/list", params: {} },
          { authorization: "Bearer token-analyst-demo" }
        );
        const toolNames = listRpc.result.tools.map((t: any) => t.name);
        expect(toolNames).toContain("safe_plan_counts");
        expect(toolNames).not.toContain("execute_analytical_sql");
        expect(toolNames).not.toContain("verify_query_safety");

        // Direct call to execute_analytical_sql is blocked
        const blockedCall = await sendRpc(
          inst.server,
          {
            jsonrpc: "2.0",
            id: 11,
            method: "tools/call",
            params: {
              name: "execute_analytical_sql",
              arguments: { query: "SELECT id FROM customers" },
            },
          },
          { authorization: "Bearer token-analyst-demo" }
        );
        expect(blockedCall.result.isError).toBe(true);
        expect(blockedCall.result.content[0].text).toContain(
          "RBACPermissionDenied"
        );

        // Parameterized template still succeeds
        const tmplCall = await sendRpc(
          inst.server,
          {
            jsonrpc: "2.0",
            id: 12,
            method: "tools/call",
            params: { name: "safe_plan_counts", arguments: {} },
          },
          { authorization: "Bearer token-analyst-demo" }
        );
        expect(tmplCall.result.isError).toBeUndefined();
      } finally {
        await inst.engine.close();
      }
    });
  });

  describe("Operational HTTP Endpoints (/healthz & /readyz)", () => {
    it("responds 200 OK on /healthz and /readyz without leaking schema metadata", async () => {
      const policy = loadPolicyFromFile(DEMO_SAAS_POLICY);
      const inst = createSecureMcpServer({ policy });
      try {
        const healthRes = await inst.server.fetch(
          new Request("http://localhost/healthz", { method: "GET" })
        );
        expect(healthRes.status).toBe(200);
        const healthJson = await healthRes.json();
        expect(healthJson.status).toBe("ok");
        expect(healthJson.engine).toBe("sqlite");
        expect(healthJson.templateCount).toBe(2);

        const readyRes = await inst.server.fetch(
          new Request("http://localhost/readyz", { method: "GET" })
        );
        expect(readyRes.status).toBe(200);
        const readyJson = await readyRes.json();
        expect(readyJson.status).toBe("ready");
      } finally {
        await inst.engine.close();
      }
    });
  });

  describe("CLI --validate-policy & Real Child-Process Stdio Transport", () => {
    it("validates all 3 bundled example policies via CLI --validate-policy", () => {
      const r1 = spawnSync(
        process.execPath,
        [CLI_PATH, "--validate-policy", "--config", DEMO_SAAS_POLICY],
        { cwd: ROOT_DIR, encoding: "utf8" }
      );
      expect(r1.status, r1.stderr).toBe(0);
      expect(JSON.parse(r1.stdout).valid).toBe(true);

      const r2 = spawnSync(
        process.execPath,
        [CLI_PATH, "--validate-policy", "--config", COMPANY_POLICY],
        { cwd: ROOT_DIR, encoding: "utf8" }
      );
      expect(r2.status, r2.stderr).toBe(0);
      expect(JSON.parse(r2.stdout).valid).toBe(true);

      const r3 = spawnSync(
        process.execPath,
        [
          CLI_PATH,
          "--validate-policy",
          "--offline",
          "--config",
          PG_TEMPLATES_POLICY,
        ],
        { cwd: ROOT_DIR, encoding: "utf8" }
      );
      expect(r3.status, r3.stderr).toBe(0);
      const pgOut = JSON.parse(r3.stdout);
      expect(pgOut.valid).toBe(true);
      expect(pgOut.adhocSqlEnabled).toBe(false);
      expect(pgOut.validatedTemplates.length).toBe(2);
    });

    it("enforces default-deny over stdio when no token or --stdio-role is supplied", async () => {
      const { responses, exitCode } = await runStdioSession(
        ["--config", DEMO_SAAS_POLICY, "--transport", "stdio"],
        [{ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }],
        { MCP_SECURE_DB_TOKEN: "", MCP_SECURE_DB_INSECURE_DEMO: "false" }
      );

      expect(exitCode).toBe(0);
      expect(responses).toHaveLength(1);
      expect(responses[0].result.tools.map((t: any) => t.name)).toEqual([
        "whoami",
      ]);
    });

    it("authenticates via explicit --stdio-role analyst and executes a safe template over clean JSON-RPC stdout", async () => {
      const { responses, stderr, exitCode } = await runStdioSession(
        [
          "--config",
          DEMO_SAAS_POLICY,
          "--transport",
          "stdio",
          "--stdio-role",
          "analyst",
        ],
        [
          { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
          {
            jsonrpc: "2.0",
            id: 2,
            method: "tools/call",
            params: {
              name: "get_customer_usage_summary",
              arguments: { plan: "enterprise" },
            },
          },
        ],
        { MCP_SECURE_DB_TOKEN: "" }
      );

      expect(exitCode).toBe(0);
      expect(stderr).toContain("stdio transport ready");
      expect(responses).toHaveLength(2);
      const toolNames = responses[0].result.tools.map((t: any) => t.name);
      expect(toolNames).toContain("get_customer_usage_summary");
      expect(toolNames).toContain("execute_analytical_sql");

      const execBody = JSON.parse(responses[1].result.content[0].text);
      expect(execBody.rowCount).toBe(2);
      expect(execBody.untrustedData).toBe(true);
    });

    it("authenticates over stdio via MCP_SECURE_DB_TOKEN matched against MCP_SECURE_DB_API_KEYS", async () => {
      const apiKey = "stdio_prod_token_abcdef123456";
      const hash = crypto
        .createHash("sha256")
        .update(apiKey, "utf8")
        .digest("hex");

      const { responses, exitCode } = await runStdioSession(
        ["--config", DEMO_SAAS_POLICY, "--transport", "stdio"],
        [{ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "whoami", arguments: {} } }],
        {
          NODE_ENV: "production",
          MCP_SECURE_DB_TOKEN: apiKey,
          MCP_SECURE_DB_API_KEYS: JSON.stringify([
            {
              tokenSha256: hash,
              principal: "ide-agent@corp.internal",
              role: "analyst",
            },
          ]),
        }
      );

      expect(exitCode).toBe(0);
      expect(responses).toHaveLength(1);
      const whoamiBody = JSON.parse(responses[0].result.content[0].text);
      expect(whoamiBody.authenticated).toBe(true);
      expect(whoamiBody.role).toBe("analyst");
      expect(whoamiBody.principal).toBe("ide-agent@corp.internal");
    });
  });
});
