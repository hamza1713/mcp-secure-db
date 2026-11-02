import { describe, it, expect } from "vitest";
import server, {
  handleWhoami,
  handleListTables,
  handleDescribeTable,
  handleVerifyQuerySafety,
  handleExecuteAnalyticalSql,
  handleGetSecurityAuditLog,
} from "../src/index.js";

describe("MCP Server End-to-End Suite", () => {
  it("should initialize MCPServer instance", () => {
    expect(server).toBeDefined();
  });

  describe("Tool: whoami", () => {
    it("should return anonymous public_viewer role when no token provided", async () => {
      const res: any = await handleWhoami({ token: undefined }, {} as any);
      expect(res.content).toBeDefined();
      const body = JSON.parse(res.content[0].text);
      expect(body.role).toBe("public_viewer");
      expect(body.allowedTools).toContain("whoami");
      expect(body.allowedTools).not.toContain("execute_analytical_sql");
    });

    it("should return analyst role when analyst token provided", async () => {
      const res: any = await handleWhoami({ token: "token-analyst-demo" }, {} as any);
      const body = JSON.parse(res.content[0].text);
      expect(body.role).toBe("analyst");
      expect(body.allowedTools).toContain("execute_analytical_sql");
      expect(body.allowedTools).not.toContain("get_security_audit_log");
    });

    it("should return admin role when admin token provided", async () => {
      const res: any = await handleWhoami({ token: "token-admin-demo" }, {} as any);
      const body = JSON.parse(res.content[0].text);
      expect(body.role).toBe("admin");
      expect(body.allowedTools).toContain("get_security_audit_log");
    });
  });

  describe("Tool: list_tables", () => {
    it("should hide admin-only tables for public_viewer", async () => {
      const res: any = await handleListTables({}, {} as any);
      const body = JSON.parse(res.content[0].text);
      expect(body.tables.length).toBe(2);
      const names = body.tables.map((t: any) => t.name);
      expect(names).toContain("customers");
      expect(names).toContain("api_usage");
      expect(names).not.toContain("security_incidents");
    });

    it("should display all tables including security_incidents for admin", async () => {
      const res: any = await handleListTables({ token: "token-admin-demo" }, {} as any);
      const body = JSON.parse(res.content[0].text);
      expect(body.tables.length).toBe(4);
      const names = body.tables.map((t: any) => t.name);
      expect(names).toContain("security_incidents");
      expect(names).toContain("api_keys");
    });
  });

  describe("Tool: describe_table", () => {
    it("should return column descriptions and hide PII for viewer", async () => {
      const res: any = await handleDescribeTable({ table_name: "customers" }, {} as any);
      const body = JSON.parse(res.content[0].text);
      expect(body.name).toBe("customers");
      const billingCol = body.columns.find((c: any) => c.name === "billing_email");
      expect(billingCol.isPII).toBe(true);
      expect(billingCol.hidden).toBe(true);
    });

    it("should reveal PII columns for admin", async () => {
      const res: any = await handleDescribeTable(
        { table_name: "customers", token: "token-admin-demo" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      const billingCol = body.columns.find((c: any) => c.name === "billing_email");
      expect(billingCol.isPII).toBe(true);
      expect(billingCol.hidden).toBe(false);
    });

    it("should return error when non-admin requests admin-only table", async () => {
      const res: any = await handleDescribeTable({ table_name: "api_keys" }, {} as any);
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("access is denied");
    });
  });

  describe("Tool: verify_query_safety", () => {
    it("should dry-run validate safe queries with 0 token cost", async () => {
      const res: any = await handleVerifyQuerySafety(
        { query: "SELECT id, name FROM customers" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.valid).toBe(true);
      expect(body.cost).toContain("0 Tokens");
      expect(body.sanitizedQuery).toContain("LIMIT");
    });

    it("should report violation reasons for dangerous queries", async () => {
      const res: any = await handleVerifyQuerySafety(
        { query: "DROP TABLE customers" },
        {} as any
      );
      const body = JSON.parse(res.content[0].text);
      expect(body.valid).toBe(false);
      expect(body.violationReason).toContain("Only SELECT statements are permitted");
    });
  });

  describe("Tool: execute_analytical_sql", () => {
    it("should reject execution when called by public_viewer role", async () => {
      const res: any = await handleExecuteAnalyticalSql(
        { query: "SELECT id, name FROM customers" },
        {} as any
      );
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("RBACPermissionDenied");
    });

    it("should execute valid query when called by analyst role", async () => {
      const res: any = await handleExecuteAnalyticalSql(
        { query: "SELECT id, name, plan FROM customers", token: "token-analyst-demo" },
        {} as any
      );
      expect(res.isError).toBeUndefined();
      const body = JSON.parse(res.content[0].text);
      expect(body.rowCount).toBe(5);
      expect(body.sandbox.role).toBe("analyst");
    });

    it("should block mutating queries even when called by admin", async () => {
      const res: any = await handleExecuteAnalyticalSql(
        { query: "DELETE FROM customers WHERE id = 1", token: "token-admin-demo" },
        {} as any
      );
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("Only SELECT statements are permitted");
    });
  });

  describe("Tool: get_security_audit_log", () => {
    it("should deny access to non-admin roles", async () => {
      const res: any = await handleGetSecurityAuditLog({ token: "token-analyst-demo" }, {} as any);
      expect(res.isError).toBe(true);
      expect(res.content[0].text).toContain("RBACPermissionDenied");
    });

    it("should return telemetry ring buffer to admin", async () => {
      const res: any = await handleGetSecurityAuditLog({ token: "token-admin-demo" }, {} as any);
      expect(res.isError).toBeUndefined();
      const body = JSON.parse(res.content[0].text);
      expect(body.stats).toBeDefined();
      expect(body.entries).toBeDefined();
    });
  });
});
