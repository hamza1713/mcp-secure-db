import { describe, it, expect } from "vitest";
import { rbacManager } from "../src/security/rbac.js";

describe("RBACManager Default-Deny and OAuth Resolution (P0-4)", () => {
  it("fails closed to unauthenticated when credentials are missing by default", () => {
    const ctx = rbacManager.resolveContext(null);
    expect(ctx.role).toBe("unauthenticated");
    expect(ctx.authenticated).toBe(false);
    expect(ctx.allowedTools).toEqual(["whoami"]);
    expect(ctx.allowedTools).not.toContain("list_tables");
    expect(ctx.allowedTools).not.toContain("execute_analytical_sql");
  });

  it("fails closed to unauthenticated on invalid tokens even when insecure demo mode is enabled", () => {
    const ctx = rbacManager.resolveContext("Bearer invalid-forged-token", {
      allowInsecureDemo: true,
    });
    expect(ctx.role).toBe("unauthenticated");
    expect(ctx.authenticated).toBe(false);
    expect(ctx.allowedTools).toEqual(["whoami"]);
  });

  it("grants insecure demo public_viewer ONLY when credentials are omitted and allowInsecureDemo is explicitly true", () => {
    const ctx = rbacManager.resolveContext(null, { allowInsecureDemo: true });
    expect(ctx.role).toBe("public_viewer");
    expect(ctx.authenticated).toBe(false);
    expect(ctx.authSource).toBe("insecure_demo");
    expect(ctx.allowedTools).toContain("list_tables");
    expect(ctx.allowedTools).not.toContain("execute_analytical_sql");
  });

  it("resolves viewer, analyst, and admin demo tokens accurately", () => {
    const viewer = rbacManager.resolveContext("token-viewer-demo");
    expect(viewer.role).toBe("public_viewer");
    expect(viewer.authenticated).toBe(true);

    const analyst = rbacManager.resolveContext("token-analyst-demo");
    expect(analyst.role).toBe("analyst");
    expect(analyst.allowedTools).toContain("execute_analytical_sql");
    expect(analyst.allowedTools).not.toContain("get_security_audit_log");

    const admin = rbacManager.resolveContext("Bearer token-admin-demo");
    expect(admin.role).toBe("admin");
    expect(admin.allowedTools).toContain("execute_analytical_sql");
    expect(admin.allowedTools).toContain("get_security_audit_log");
  });

  it("resolves verified mcp-use OAuth scopes before static tokens", () => {
    const oauthAnalyst = rbacManager.resolveContext(null, {
      oauth: {
        clientId: "oauth-client-1",
        scopes: ["db:read:metadata", "db:execute:analytics"],
        user: { email: "oauth-analyst@example.org" },
      },
    });
    expect(oauthAnalyst.role).toBe("analyst");
    expect(oauthAnalyst.authenticated).toBe(true);
    expect(oauthAnalyst.authSource).toBe("oauth");
    expect(oauthAnalyst.principal).toBe("oauth-analyst@example.org");

    const oauthUnscoped = rbacManager.resolveContext(null, {
      oauth: {
        clientId: "oauth-client-2",
        scopes: ["unrelated:scope"],
      },
    });
    expect(oauthUnscoped.role).toBe("unauthenticated");
    expect(oauthUnscoped.authenticated).toBe(false);
  });

  it("filters tool lists dynamically by role including unauthenticated", () => {
    const allTools = [
      { name: "whoami" },
      { name: "list_tables" },
      { name: "execute_analytical_sql" },
      { name: "get_security_audit_log" },
    ];

    expect(
      rbacManager.filterTools("unauthenticated", allTools).map((t) => t.name)
    ).toEqual(["whoami"]);

    expect(
      rbacManager.filterTools("public_viewer", allTools).map((t) => t.name)
    ).toEqual(["whoami", "list_tables"]);

    expect(
      rbacManager.filterTools("analyst", allTools).map((t) => t.name)
    ).toEqual(["whoami", "list_tables", "execute_analytical_sql"]);

    expect(rbacManager.filterTools("admin", allTools).length).toBe(4);
  });
});
