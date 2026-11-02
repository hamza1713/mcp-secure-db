import { SecurityContext, UserRole } from "../types.js";

export const ROLE_TOOLS: Record<UserRole, string[]> = {
  unauthenticated: ["whoami"],
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
  { principal: string; role: Exclude<UserRole, "unauthenticated">; scopes: string[] }
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
    scopes: [
      "db:read:metadata",
      "db:execute:analytics",
      "db:audit:read",
      "db:pii:access",
    ],
  },
};

export interface OAuthLikeContext {
  clientId?: string;
  scopes?: string[];
  permissions?: string[];
  user?: { id?: string; email?: string; sub?: string } | Record<string, unknown>;
  payload?: Record<string, unknown>;
  extra?: Record<string, unknown>;
}

export interface ResolveContextOptions {
  allowInsecureDemo?: boolean;
  oauth?: OAuthLikeContext | null;
}

export function isInsecureDemoModeEnabled(override?: boolean): boolean {
  if (typeof override === "boolean") return override;
  return process.env.MCP_SECURE_DB_INSECURE_DEMO === "true";
}

export class RBACManager {
  /**
   * Resolves caller identity using default-deny semantics:
   * 1. Verified OAuth context (`ctx.auth` from `mcp-use` OAuth middleware), when present.
   * 2. Explicit static demo Bearer/API token from `TOKEN_REGISTRY`.
   * 3. INSECURE demo fallback (`public_viewer`) ONLY when credentials are omitted AND
   *    `MCP_SECURE_DB_INSECURE_DEMO=true` is explicitly set.
   * 4. Otherwise fails closed to `unauthenticated` (no data or schema tools).
   */
  public resolveContext(
    tokenOrHeader?: string | null,
    options: ResolveContextOptions = {}
  ): SecurityContext {
    if (options.oauth) {
      const oauthCtx = this.resolveFromOAuth(options.oauth);
      if (oauthCtx) return oauthCtx;
    }

    const raw = typeof tokenOrHeader === "string" ? tokenOrHeader.trim() : "";

    if (!raw) {
      if (isInsecureDemoModeEnabled(options.allowInsecureDemo)) {
        return {
          principal: "insecure_demo_viewer",
          role: "public_viewer",
          authenticated: false,
          authSource: "insecure_demo",
          scopes: ["db:read:metadata"],
          allowedTools: [...ROLE_TOOLS.public_viewer],
        };
      }
      return {
        principal: "unauthenticated",
        role: "unauthenticated",
        authenticated: false,
        authSource: "none",
        scopes: [],
        allowedTools: [...ROLE_TOOLS.unauthenticated],
        denialReason:
          "Missing authentication credentials (default-deny active).",
      };
    }

    let cleanToken = raw;
    if (cleanToken.toLowerCase().startsWith("bearer ")) {
      cleanToken = cleanToken.slice(7).trim();
    }

    if (!cleanToken) {
      return {
        principal: "unauthenticated",
        role: "unauthenticated",
        authenticated: false,
        authSource: "none",
        scopes: [],
        allowedTools: [...ROLE_TOOLS.unauthenticated],
        denialReason: "Empty Bearer token supplied.",
      };
    }

    const reg = TOKEN_REGISTRY[cleanToken];
    if (reg) {
      return {
        principal: reg.principal,
        role: reg.role,
        authenticated: true,
        authSource: "token",
        scopes: [...reg.scopes],
        allowedTools: [...ROLE_TOOLS[reg.role]],
      };
    }

    // Invalid credentials ALWAYS fail closed, even when insecure demo mode is set
    return {
      principal: "unauthenticated",
      role: "unauthenticated",
      authenticated: false,
      authSource: "none",
      scopes: [],
      allowedTools: [...ROLE_TOOLS.unauthenticated],
      denialReason: "Unrecognized or invalid authentication token.",
    };
  }

  public resolveFromOAuth(oauth: OAuthLikeContext): SecurityContext | null {
    const scopeSet = new Set<string>([
      ...(Array.isArray(oauth.scopes) ? oauth.scopes : []),
      ...(Array.isArray(oauth.permissions) ? oauth.permissions : []),
    ]);

    const userObj = (oauth.user ?? {}) as Record<string, unknown>;
    const payloadObj = (oauth.payload ?? {}) as Record<string, unknown>;
    const principal =
      (typeof userObj.email === "string" && userObj.email) ||
      (typeof userObj.sub === "string" && userObj.sub) ||
      (typeof payloadObj.sub === "string" && payloadObj.sub) ||
      oauth.clientId ||
      "oauth_authenticated_principal";

    let role: UserRole = "unauthenticated";
    if (
      scopeSet.has("db:audit:read") ||
      scopeSet.has("db:pii:access") ||
      scopeSet.has("admin")
    ) {
      role = "admin";
    } else if (scopeSet.has("db:execute:analytics") || scopeSet.has("analyst")) {
      role = "analyst";
    } else if (scopeSet.has("db:read:metadata") || scopeSet.has("viewer")) {
      role = "public_viewer";
    }

    if (role === "unauthenticated") {
      return {
        principal: String(principal),
        role: "unauthenticated",
        authenticated: false,
        authSource: "oauth",
        scopes: [...scopeSet],
        allowedTools: [...ROLE_TOOLS.unauthenticated],
        denialReason:
          "Verified OAuth token lacks required mcp-secure-db scopes.",
      };
    }

    return {
      principal: String(principal),
      role,
      authenticated: true,
      authSource: "oauth",
      scopes: [...scopeSet],
      allowedTools: [...ROLE_TOOLS[role]],
    };
  }

  public canAccessTool(role: UserRole, toolName: string): boolean {
    const allowed = ROLE_TOOLS[role] ?? [];
    return allowed.includes(toolName);
  }

  public canReadCatalog(role: UserRole): boolean {
    return role !== "unauthenticated";
  }

  public filterTools<T extends { name: string }>(
    role: UserRole,
    tools: T[]
  ): T[] {
    const allowed = new Set(ROLE_TOOLS[role] ?? []);
    return tools.filter((t) => allowed.has(t.name));
  }
}

export const rbacManager = new RBACManager();
