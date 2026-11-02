import { describe, it, expect } from "vitest";
import { rbacManager } from "../src/security/rbac.js";

describe("RBACManager", () => {
  it("should default to public_viewer when no token is provided", () => {
    const ctx = rbacManager.resolveContext(null);
    expect(ctx.role).toBe("public_viewer");
    expect(ctx.allowedTools).toContain("whoami");
    expect(ctx.allowedTools).toContain("list_tables");
    expect(ctx.allowedTools).not.toContain("execute_analytical_sql");
  });

  it("should resolve analyst token correctly", () => {
    const ctx = rbacManager.resolveContext("token-analyst-demo");
    expect(ctx.role).toBe("analyst");
    expect(ctx.allowedTools).toContain("execute_analytical_sql");
    expect(ctx.allowedTools).not.toContain("get_security_audit_log");
  });

  it("should resolve admin token correctly", () => {
    const ctx = rbacManager.resolveContext("token-admin-demo");
    expect(ctx.role).toBe("admin");
    expect(ctx.allowedTools).toContain("execute_analytical_sql");
    expect(ctx.allowedTools).toContain("get_security_audit_log");
  });

  it("should strip Bearer prefix from authorization headers", () => {
    const ctx = rbacManager.resolveContext("Bearer token-admin-demo");
    expect(ctx.role).toBe("admin");
  });

  it("should filter tool lists based on role privileges", () => {
    const allTools = [
      { name: "whoami" },
      { name: "list_tables" },
      { name: "execute_analytical_sql" },
      { name: "get_security_audit_log" },
    ];

    const viewerTools = rbacManager.filterTools("public_viewer", allTools);
    expect(viewerTools.map((t) => t.name)).toEqual(["whoami", "list_tables"]);

    const analystTools = rbacManager.filterTools("analyst", allTools);
    expect(analystTools.map((t) => t.name)).toEqual([
      "whoami",
      "list_tables",
      "execute_analytical_sql",
    ]);

    const adminTools = rbacManager.filterTools("admin", allTools);
    expect(adminTools.length).toBe(4);
  });
});
