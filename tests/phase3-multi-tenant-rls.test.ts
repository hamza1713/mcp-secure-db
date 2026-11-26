import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { describe, it, expect, afterEach } from "vitest";
import { RBACManager } from "../src/security/rbac.js";
import { resolvePolicyObject } from "../src/policy/loader.js";
import { createSecureMcpServer } from "../src/index.js";
import { PostgresQueryEngine } from "../src/database/postgres-adapter.js";
import { DEFAULT_TABLE_METADATA } from "../src/database/seed.js";
import { TenantContextRequiredError } from "../src/security/template-engine.js";

const CLI_PATH = path.resolve(process.cwd(), "dist", "cli.js");
const MULTI_TENANT_POLICY = path.resolve(
  process.cwd(),
  "examples",
  "policies",
  "multi-tenant-saas.policy.yaml"
);

async function postMcp(
  server: { fetch: (req: Request) => Promise<Response> },
  method: string,
  params: Record<string, unknown>,
  token?: string
): Promise<any> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;

  const res = await server.fetch(
    new Request("http://localhost/mcp", {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    })
  );
  const text = await res.text();
  if (text.trim().startsWith("{")) return JSON.parse(text);
  const dataLines = text
    .split(/\r?\n/)
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim())
    .filter(Boolean);
  return JSON.parse(dataLines[dataLines.length - 1]);
}

describe("Phase 3: Multi-Tenant Isolation (RBAC, :ctx.* Templates & PostgreSQL RLS)", () => {
  const cleanupDirs: string[] = [];

  afterEach(() => {
    while (cleanupDirs.length > 0) {
      fs.rmSync(cleanupDirs.pop()!, { recursive: true, force: true });
    }
  });

  it("extracts verified tenantId from OAuth claims, MCP_SECURE_DB_API_KEYS, and stdio-role while rejecting unsafe characters", () => {
    const rbac = new RBACManager();

    const oauthCtx = rbac.resolveContext(undefined, {
      oauth: {
        scopes: ["db:execute:analytics"],
        payload: { sub: "user-42", tenant_id: "tenant_acme" },
      },
    });
    expect(oauthCtx.role).toBe("analyst");
    expect(oauthCtx.tenantId).toBe("tenant_acme");

    // Unsafe SQL-injection tenant_id claim is rejected / stripped
    const badOauthCtx = rbac.resolveContext(undefined, {
      oauth: {
        scopes: ["db:execute:analytics"],
        payload: { sub: "user-43", tenant_id: "tenant'; DROP TABLE x;--" },
      },
    });
    expect(badOauthCtx.tenantId).toBeUndefined();

    // API keys with tenantId
    const prevKeys = process.env.MCP_SECURE_DB_API_KEYS;
    process.env.MCP_SECURE_DB_API_KEYS = JSON.stringify([
      {
        token: "tenant-api-key-1",
        principal: "svc@globex.io",
        role: "analyst",
        tenantId: "tenant_globex",
      },
    ]);
    try {
      const apiCtx = rbac.resolveContext("Bearer tenant-api-key-1");
      expect(apiCtx.role).toBe("analyst");
      expect(apiCtx.tenantId).toBe("tenant_globex");
    } finally {
      if (prevKeys === undefined) delete process.env.MCP_SECURE_DB_API_KEYS;
      else process.env.MCP_SECURE_DB_API_KEYS = prevKeys;
    }

    const stdioCtx = rbac.resolveStdioRole("analyst", "tenant_local_1");
    expect(stdioCtx.tenantId).toBe("tenant_local_1");
  });

  it("enforces unspoofable :ctx.tenant_id template bindings, omits ctx params from LLM tool schema, and enforces require_tenant_id", async () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-rls-sqlite-"));
    cleanupDirs.push(tmpDir);
    const dbPath = path.join(tmpDir, "tenants.db");

    const db = new DatabaseSync(dbPath);
    db.exec(`
      CREATE TABLE tenant_orders (
        id INTEGER PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        sku TEXT NOT NULL,
        amount_usd REAL NOT NULL
      );
      INSERT INTO tenant_orders VALUES
        (1, 'tenant_acme', 'SKU-A', 120.0),
        (2, 'tenant_acme', 'SKU-B', 340.0),
        (3, 'tenant_globex', 'SKU-A', 999.0);
    `);
    db.close();

    const policy = resolvePolicyObject(
      {
        version: 1,
        engine: {
          type: "sqlite",
          sqlite_path: dbPath,
        },
        tenant_isolation: {
          enabled: true,
          require_tenant_id: true,
        },
        roles: {
          public_viewer: { tables: ["tenant_orders"] },
          analyst: { tables: ["tenant_orders"] },
          admin: { tables: ["tenant_orders"], allow_pii: true },
        },
        templates: [
          {
            name: "my_tenant_orders",
            description: "List orders strictly scoped to the verified caller tenant",
            allowed_roles: ["analyst", "admin"],
            sql: "SELECT id, tenant_id, sku, amount_usd FROM tenant_orders WHERE tenant_id = :ctx.tenant_id AND sku = :sku ORDER BY id LIMIT 25",
            parameters: {
              sku: { type: "string", required: true },
            },
          },
        ],
      },
      tmpDir
    );

    const prevKeys = process.env.MCP_SECURE_DB_API_KEYS;
    process.env.MCP_SECURE_DB_API_KEYS = JSON.stringify([
      {
        token: "k-acme",
        principal: "alice@acme.io",
        role: "analyst",
        tenantId: "tenant_acme",
      },
      {
        token: "k-globex",
        principal: "bob@globex.io",
        role: "analyst",
        tenantId: "tenant_globex",
      },
      {
        token: "k-notenant",
        principal: "unscoped@ops.io",
        role: "analyst",
      },
      {
        token: "k-admin",
        principal: "root@ops.io",
        role: "admin",
      },
    ]);

    const instance = createSecureMcpServer({ policy });
    try {
      await instance.validateTemplates();

      // 1. Tool schema exposed to LLM must NOT contain ctx.tenant_id
      const listRes = await postMcp(instance.server, "tools/list", {}, "k-acme");
      const tmplTool = listRes.result.tools.find(
        (t: any) => t.name === "my_tenant_orders"
      );
      expect(tmplTool).toBeDefined();
      expect(tmplTool.inputSchema.properties).toHaveProperty("sku");
      expect(tmplTool.inputSchema.properties).not.toHaveProperty("ctx.tenant_id");
      expect(tmplTool.inputSchema.properties).not.toHaveProperty("tenant_id");

      // 2. Acme analyst calling with spoofed tenant_globex args still only gets tenant_acme rows
      const acmeRes = await postMcp(
        instance.server,
        "tools/call",
        {
          name: "my_tenant_orders",
          arguments: {
            sku: "SKU-A",
            tenant_id: "tenant_globex",
            "ctx.tenant_id": "tenant_globex",
          },
        },
        "k-acme"
      );
      const acmeData = JSON.parse(acmeRes.result.content[0].text);
      expect(acmeData.rowCount).toBe(1);
      expect(acmeData.rows[0].tenant_id).toBe("tenant_acme");
      expect(acmeData.rows[0].amount_usd).toBe(120);

      // 3. Globex analyst sees only tenant_globex row
      const globexRes = await postMcp(
        instance.server,
        "tools/call",
        {
          name: "my_tenant_orders",
          arguments: { sku: "SKU-A" },
        },
        "k-globex"
      );
      const globexData = JSON.parse(globexRes.result.content[0].text);
      expect(globexData.rowCount).toBe(1);
      expect(globexData.rows[0].tenant_id).toBe("tenant_globex");
      expect(globexData.rows[0].amount_usd).toBe(999);

      // 4. Unscoped analyst fails closed on both template (:ctx.tenant_id) and ad-hoc SQL (require_tenant_id)
      const noTenantTmpl = await postMcp(
        instance.server,
        "tools/call",
        { name: "my_tenant_orders", arguments: { sku: "SKU-A" } },
        "k-notenant"
      );
      expect(noTenantTmpl.result.isError).toBe(true);
      expect(noTenantTmpl.result.content[0].text).toContain(
        "TenantContextRequired"
      );

      const noTenantAdhoc = await postMcp(
        instance.server,
        "tools/call",
        {
          name: "execute_analytical_sql",
          arguments: { query: "SELECT id FROM tenant_orders LIMIT 5" },
        },
        "k-notenant"
      );
      expect(noTenantAdhoc.result.isError).toBe(true);
      expect(noTenantAdhoc.result.content[0].text).toContain(
        "TenantContextRequired"
      );

      // 5. Admin without tenantId is allowed ad-hoc SQL, but still cannot bypass a `:ctx.tenant_id` template without a tenantId
      const adminAdhoc = await postMcp(
        instance.server,
        "tools/call",
        {
          name: "execute_analytical_sql",
          arguments: { query: "SELECT COUNT(*) AS cnt FROM tenant_orders" },
        },
        "k-admin"
      );
      expect(adminAdhoc.result.isError).toBeUndefined();
      expect(JSON.parse(adminAdhoc.result.content[0].text).rows[0].cnt).toBe(3);
    } finally {
      await instance.engine.close();
      if (prevKeys === undefined) delete process.env.MCP_SECURE_DB_API_KEYS;
      else process.env.MCP_SECURE_DB_API_KEYS = prevKeys;
    }
  });

  it("injects parameterized transaction-local set_config('app.tenant_id', $1, true) in PostgresQueryEngine before SET LOCAL ROLE", async () => {
    const policy = resolvePolicyObject(
      {
        version: 1,
        engine: {
          type: "postgres",
          connection_string_env: "DATABASE_URL",
        },
        tenant_isolation: {
          enabled: true,
          require_tenant_id: true,
          pg_tenant_setting: "app.tenant_id",
          pg_principal_setting: "app.principal",
        },
        roles: {
          public_viewer: { tables: ["customers"] },
          analyst: { tables: ["customers"] },
          admin: { tables: ["customers"], allow_pii: true },
        },
      },
      process.cwd()
    );
    policy.seedTableMetadata = { customers: DEFAULT_TABLE_METADATA.customers };

    const pgEngine = new PostgresQueryEngine({
      connectionString: "postgres://mcp_gateway:pw@127.0.0.1:55432/mcp_analytics",
      policy,
    });

    // Fail closed for non-admin without tenantId before even touching pg.Pool
    await expect(
      pgEngine.executeQuery("SELECT id FROM customers", "analyst", "alice@acme.io")
    ).rejects.toThrow(TenantContextRequiredError);

    // Mock the pg.Pool connect() client to verify exact SQL + parameter ordering inside transaction
    const recordedCalls: Array<{ sql: string; values?: unknown[] }> = [];
    let released = false;
    (pgEngine as any).pool = {
      connect: async () => ({
        query: async (q: any, vals?: unknown[]) => {
          if (typeof q === "string") {
            recordedCalls.push({ sql: q, values: vals });
            return { rows: [], fields: [] };
          }
          recordedCalls.push({ sql: q.text, values: q.values });
          return {
            rows: [[1, "Acme Corp"]],
            fields: [{ name: "id" }, { name: "name" }],
          };
        },
        release: () => {
          released = true;
        },
      }),
      end: async () => {},
    };

    try {
      const res = await pgEngine.executeQuery(
        "SELECT id, name FROM customers",
        "analyst",
        "alice@acme.io",
        { requestId: "req_pg_1", tenantId: "tenant_acme" }
      );
      expect(res.rowCount).toBe(1);
      expect(released).toBe(true);

      // Verify exact transaction sequence: BEGIN READ ONLY -> parameterized set_config -> SET LOCAL ROLE -> SELECT -> ROLLBACK
      expect(recordedCalls[0].sql).toContain("BEGIN READ ONLY");
      expect(recordedCalls[1]).toEqual({
        sql: "SELECT set_config($1, $2, true)",
        values: ["app.tenant_id", "tenant_acme"],
      });
      expect(recordedCalls[2]).toEqual({
        sql: "SELECT set_config($1, $2, true)",
        values: ["app.principal", "alice@acme.io"],
      });
      expect(recordedCalls[3].sql).toBe("SET LOCAL ROLE mcp_analyst");
      expect(recordedCalls[recordedCalls.length - 1].sql).toBe("ROLLBACK");
    } finally {
      await pgEngine.close();
    }
  });

  it("propagates --stdio-tenant over real child-process stdio transport cleanly", async () => {
    const frames = [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "whoami", arguments: {} },
      },
      {
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: {
          name: "tenant_usage_summary",
          arguments: { min_requests: 0 },
        },
      },
    ];

    const responses = await new Promise<any[]>((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [
          CLI_PATH,
          "--transport",
          "stdio",
          "--config",
          MULTI_TENANT_POLICY,
          "--stdio-role",
          "analyst",
          "--stdio-tenant",
          "enterprise",
        ],
        {
          stdio: ["pipe", "pipe", "pipe"],
          env: {
            ...process.env,
            MCP_SECURE_DB_TOKEN: "",
            MCP_SECURE_DB_LOG_FORMAT: "json",
          },
        }
      );

      let stdoutBuf = "";
      let stderrBuf = "";
      const timer = setTimeout(() => {
        child.kill();
        reject(new Error(`stdio timeout; stderr=${stderrBuf}`));
      }, 15000);

      child.stdout.on("data", (d) => {
        stdoutBuf += d.toString("utf8");
      });
      child.stderr.on("data", (d) => {
        stderrBuf += d.toString("utf8");
      });
      child.on("close", () => {
        clearTimeout(timer);
        try {
          const lines = stdoutBuf
            .split(/\r?\n/)
            .map((l) => l.trim())
            .filter(Boolean);
          resolve(lines.map((l) => JSON.parse(l)));
        } catch (err: any) {
          reject(
            new Error(`Non-JSON leaked to stdout: ${stdoutBuf}\nstderr: ${stderrBuf}\nerr: ${err.message}`)
          );
        }
      });

      for (const f of frames) {
        child.stdin.write(JSON.stringify(f) + "\n");
      }
      child.stdin.end();
    });

    expect(responses).toHaveLength(2);
    const whoamiBody = JSON.parse(responses[0].result.content[0].text);
    expect(whoamiBody.role).toBe("analyst");
    expect(whoamiBody.tenantId).toBe("enterprise");

    const usageBody = JSON.parse(responses[1].result.content[0].text);
    expect(usageBody.rowCount).toBe(2);
    expect(usageBody.rows.every((r: any) => r.plan === "enterprise")).toBe(true);
  }, 20000);
});
