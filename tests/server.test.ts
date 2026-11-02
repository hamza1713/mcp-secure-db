import { describe, it, expect, afterAll } from "vitest";
import server, {
  handleWhoami,
  handleListTables,
  handleDescribeTable,
  handleVerifyQuerySafety,
  handleExecuteAnalyticalSql,
  handleGetSecurityAuditLog,
  handleReadCatalogResource,
} from "../src/index.js";
import { dbEngine } from "../src/database/engine.js";
import { auditLogger } from "../src/database/audit.js";

async function sendMcpJsonRpc(
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
  // Streamable HTTP may return JSON directly or SSE `data: {...}`
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

describe("MCP Server End-to-End Suite", () => {
  afterAll(async () => {
    await dbEngine.close();
  });

  it("should initialize MCPServer instance", () => {
    expect(server).toBeDefined();
  });

  describe("MCP Wire Protocol Middleware (tools/list, tools/call, resources/read)", () => {
    it("dynamically hides all data tools from unauthenticated callers on tools/list", async () => {
      const rpc = await sendMcpJsonRpc({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/list",
        params: {},
      });
      const toolNames = rpc.result.tools.map((t: any) => t.name);
      expect(toolNames).toEqual(["whoami"]);
    });

    it("exposes viewer, analyst, and admin tools according to Authorization header on tools/list", async () => {
      const viewerRpc = await sendMcpJsonRpc(
        { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
        { authorization: "Bearer token-viewer-demo" }
      );
      expect(viewerRpc.result.tools.map((t: any) => t.name)).toEqual([
        "whoami",
        "list_tables",
        "describe_table",
        "verify_query_safety",
      ]);

      const analystRpc = await sendMcpJsonRpc(
        { jsonrpc: "2.0", id: 3, method: "tools/list", params: {} },
        { authorization: "Bearer token-analyst-demo" }
      );
      expect(analystRpc.result.tools.map((t: any) => t.name)).toContain(
        "execute_analytical_sql"
      );
      expect(analystRpc.result.tools.map((t: any) => t.name)).not.toContain(
        "get_security_audit_log"
      );

      const adminRpc = await sendMcpJsonRpc(
        { jsonrpc: "2.0", id: 4, method: "tools/list", params: {} },
        { authorization: "Bearer token-admin-demo" }
      );
      expect(adminRpc.result.tools.length).toBe(6);
    });

    it("blocks unauthenticated tools/call on data tools via middleware and logs BLOCKED_AUTH", async () => {
      auditLogger.clear();
      const rpc = await sendMcpJsonRpc({
        jsonrpc: "2.0",
        id: 5,
        method: "tools/call",
        params: { name: "list_tables", arguments: {} },
      });
      expect(rpc.result.isError).toBe(true);
      expect(rpc.result.content[0].text).toContain("AuthenticationRequired");
      expect(auditLogger.getEntries(5)[0]?.status).toBe("BLOCKED_AUTH");
    });

    it("enforces default-deny and role filtering on schema://catalog resource", async () => {
      auditLogger.clear();
      await expect(
        handleReadCatalogResource(new URL("schema://catalog"), {})
      ).rejects.toThrow("AuthenticationRequired");
      expect(auditLogger.getEntries(5)[0]?.status).toBe("BLOCKED_AUTH");

      const analystCatalogRes = await handleReadCatalogResource(
        new URL("schema://catalog"),
        {
          request: {
            header: (h: string) =>
              h.toLowerCase() === "authorization"
                ? "Bearer token-analyst-demo"
                : undefined,
          },
        }
      );
      const analystCatalog = JSON.parse(analystCatalogRes.contents[0].text);
      expect(Object.keys(analystCatalog)).toEqual(["customers", "api_usage"]);
      const customerCols = analystCatalog.customers.columns.map(
        (c: any) => c.name
      );
      expect(customerCols).not.toContain("billing_email");
      expect(customerCols).not.toContain("stripe_customer_id");

      const adminCatalogRes = await handleReadCatalogResource(
        new URL("schema://catalog"),
        {
          request: {
            header: (h: string) =>
              h.toLowerCase() === "authorization"
                ? "Bearer token-admin-demo"
                : undefined,
          },
        }
      );
      const adminCatalog = JSON.parse(adminCatalogRes.contents[0].text);
      expect(Object.keys(adminCatalog).length).toBe(4);
      expect(
        adminCatalog.customers.columns.map((c: any) => c.name)
      ).toContain("billing_email");
    });
  });

  describe("Tool: whoami", () => {
    it("should return unauthenticated role when no token is provided", async () => {
      const res: any = await handleWhoami({ token: undefined }, {} as any);
      const body = JSON.parse(res.content[0].text);
      expect(body.role).toBe("unauthenticated");
      expect(body.authenticated).toBe(false);
      expect(body.allowedTools).toEqual(["whoami"]);
    });

    it("should return analyst role when analyst token is provided", async () => {
      const res: any = await handleWhoami(
        { token: "token-analyst-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.role).toBe("analyst");
      expect(body.allowedTools).toContain("execute_analytical_sql");
      expect(body.allowedTools).not.toContain("get_security_audit_log");
    });

    it("should return admin role when admin token is provided", async () => {
      const res: any = await handleWhoami(
        { token: "token-admin-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.role).toBe("admin");
      expect(body.allowedTools).toContain("get_security_audit_log");
    });
  });

  describe("Tool: list_tables", () => {
    it("should deny unauthenticated callers and log BLOCKED_AUTH", async () => {
      auditLogger.clear();
      const res: any = await handleListTables({}, {} as any);
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("AuthenticationRequired");
      expect(auditLogger.getEntries(5)[0]?.status).toBe("BLOCKED_AUTH");
    });

    it("should hide admin-only tables for authenticated public_viewer", async () => {
      const res: any = await handleListTables(
        { token: "token-viewer-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.tables.length).toBe(2);
      const names = body.tables.map((t: any) => t.name);
      expect(names).toContain("customers");
      expect(names).toContain("api_usage");
      expect(names).not.toContain("security_incidents");
    });

    it("should display all 4 tables for admin", async () => {
      const res: any = await handleListTables(
        { token: "token-admin-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.tables.length).toBe(4);
      const names = body.tables.map((t: any) => t.name);
      expect(names).toContain("security_incidents");
      expect(names).toContain("api_keys");
    });
  });

  describe("Tool: describe_table", () => {
    it("should return column descriptions and mark PII hidden for viewer", async () => {
      const res: any = await handleDescribeTable(
        { table_name: "customers", token: "token-viewer-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.name).toBe("customers");
      const billingCol = body.columns.find(
        (c: any) => c.name === "billing_email"
      );
      expect(billingCol.isPII).toBe(true);
      expect(billingCol.hidden).toBe(true);
    });

    it("should reveal PII columns for admin", async () => {
      const res: any = await handleDescribeTable(
        { table_name: "customers", token: "token-admin-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      const billingCol = body.columns.find(
        (c: any) => c.name === "billing_email"
      );
      expect(billingCol.isPII).toBe(true);
      expect(billingCol.hidden).toBe(false);
    });

    it("should return error when viewer requests admin-only table", async () => {
      const res: any = await handleDescribeTable(
        { table_name: "api_keys", token: "token-viewer-demo" },
        {} as any
      );
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("access is denied");
    });
  });

  describe("Tool: verify_query_safety", () => {
    it("should dry-run validate safe queries for authenticated viewer with 0 LLM tokens", async () => {
      const res: any = await handleVerifyQuerySafety(
        { query: "SELECT id, name FROM customers", token: "token-viewer-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.valid).toBe(true);
      expect(body.cost).toContain("0 Tokens");
      expect(body.sanitizedQuery).toContain("LIMIT");
    });

    it("should report violation reasons for dangerous queries", async () => {
      const res: any = await handleVerifyQuerySafety(
        { query: "DROP TABLE customers", token: "token-viewer-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.valid).toBe(false);
      expect(body.violationReason).toContain(
        "Only SELECT statements are permitted"
      );
    });
  });

  describe("Tool: execute_analytical_sql", () => {
    it("should reject execution when called without credentials or by public_viewer", async () => {
      const unauthRes: any = await handleExecuteAnalyticalSql(
        { query: "SELECT id, name FROM customers" },
        {} as any
      );
      expect(unauthRes.isError).toBe(true);
      expect(unauthRes.content[0].text).toContain("AuthenticationRequired");

      const viewerRes: any = await handleExecuteAnalyticalSql(
        {
          query: "SELECT id, name FROM customers",
          token: "token-viewer-demo",
        },
        {} as any
      );
      expect(viewerRes.isError).toBe(true);
      expect(viewerRes.content[0].text).toContain("RBACPermissionDenied");
    });

    it("should execute valid query when called by analyst role", async () => {
      const res: any = await handleExecuteAnalyticalSql(
        {
          query: "SELECT id, name, plan FROM customers",
          token: "token-analyst-demo",
        },
        {} as any
      );
      expect(res.isError).toBeUndefined();
      const body = JSON.parse(res.content[0].text);
      expect(body.rowCount).toBe(5);
      expect(body.sandbox.role).toBe("analyst");
      expect(body.sandbox.workerThread).toBe(true);
    });

    it("should block mutating queries even when called by admin", async () => {
      const res: any = await handleExecuteAnalyticalSql(
        {
          query: "DELETE FROM customers WHERE id = 1",
          token: "token-admin-demo",
        },
        {} as any
      );
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain(
        "Only SELECT statements are permitted"
      );
    });
  });

  describe("Tool: get_security_audit_log", () => {
    it("should deny access to non-admin roles", async () => {
      const res: any = await handleGetSecurityAuditLog(
        { token: "token-analyst-demo" },
        {} as any
      );
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("RBACPermissionDenied");
    });

    it("should return telemetry ring buffer with durability notice to admin", async () => {
      const res: any = await handleGetSecurityAuditLog(
        { token: "token-admin-demo" },
        {} as any
      );
      expect(res.isError).toBeUndefined();
      const body = JSON.parse(res.content[0].text);
      expect(body.durabilityNotice).toContain("not durable");
      expect(body.stats).toBeDefined();
      expect(body.entries).toBeDefined();
    });
  });
});
