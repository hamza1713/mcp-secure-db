import { SecurityContext, UserRole } from "../types.js";

export const ROLE_TOOLS: Record<UserRole, string[]> = {
  public_viewer: [
    "whoami",
    "list_tables",
    "describe_table",
    "verify_query_safety",
  ],
  analyst: [
    "whoami",
    "list_tables",
    "describe_table",
    "verify_query_safety",
    "execute_analytical_sql",
  ],
  admin: [
    "whoami",
    "list_tables",
    "describe_table",
    "verify_query_safety",
    "execute_analytical_sql",
    "get_security_audit_log",
  ],
};

export const TOKEN_REGISTRY: Record<
  string,
  { principal: string; role: UserRole; scopes: string[] }
> = {
  "token-viewer-demo": {
    principal: "viewer@demo.internal",
    role: "public_viewer",
    scopes: ["db:read:metadata"],
  },
  "token-analyst-demo": {
    principal: "analyst@demo.internal",
    role: "analyst",
    scopes: ["db:read:metadata", "db:execute:analytics"],
  },
  "token-admin-demo": {
    principal: "secops-admin@demo.internal",
    role: "admin",
    scopes: ["db:read:metadata", "db:execute:analytics", "db:audit:read", "db:pii:access"],
  },
};

export class RBACManager {
  public resolveContext(tokenOrHeader?: string | null): SecurityContext {
    if (!tokenOrHeader) {
      // Default fallback for local testing / stdio without headers
      return {
        principal: "anonymous_viewer",
        role: "public_viewer",
        scopes: ["db:read:metadata"],
        allowedTools: ROLE_TOOLS.public_viewer,
      };
    }

    // Extract Bearer token if present
    let cleanToken = tokenOrHeader.trim();
    if (cleanToken.toLowerCase().startsWith("bearer ")) {
      cleanToken = cleanToken.slice(7).trim();
    }

    const reg = TOKEN_REGISTRY[cleanToken];
    if (reg) {
      return {
        principal: reg.principal,
        role: reg.role,
        scopes: reg.scopes,
        allowedTools: ROLE_TOOLS[reg.role],
      };
    }

    // If invalid token provided, fall back to public_viewer
    return {
      principal: "unrecognized_token",
      role: "public_viewer",
      scopes: ["db:read:metadata"],
      allowedTools: ROLE_TOOLS.public_viewer,
    };
  }

  public canAccessTool(role: UserRole, toolName: string): boolean {
    const allowed = ROLE_TOOLS[role] || [];
    return allowed.includes(toolName);
  }

  public filterTools<T extends { name: string }>(role: UserRole, tools: T[]): T[] {
    const allowed = new Set(ROLE_TOOLS[role] || []);
    return tools.filter((t) => allowed.has(t.name));
  }
}

export const rbacManager = new RBACManager();
