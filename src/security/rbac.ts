import crypto from "node:crypto";
import { SecurityContext, UserRole } from "../types.js";

export type AuthenticatedRole = Exclude<UserRole, "unauthenticated">;

export const SAFE_TENANT_ID_REGEX = /^[a-zA-Z0-9._:@-]{1,128}$/;

export function validateTenantId(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || !SAFE_TENANT_ID_REGEX.test(trimmed)) return undefined;
  return trimmed;
}

export interface TokenRecord {
  principal: string;
  role: AuthenticatedRole;
  scopes: string[];
  tenantId?: string;
}

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

export const ROLE_RESOURCES: Record<UserRole, string[]> = {
  unauthenticated: [],
  public_viewer: ["schema://catalog", "policy://security-rules"],
  analyst: ["schema://catalog", "policy://security-rules"],
  admin: ["schema://catalog", "policy://security-rules"],
};

export const ROLE_PROMPTS: Record<UserRole, string[]> = {
  unauthenticated: [],
  public_viewer: [],
  analyst: ["executive_analytics"],
  admin: ["executive_analytics", "red_team_security_audit"],
};

const DEFAULT_ROLE_SCOPES: Record<AuthenticatedRole, string[]> = {
  public_viewer: ["db:read:metadata"],
  analyst: ["db:read:metadata", "db:execute:analytics"],
  admin: [
    "db:read:metadata",
    "db:execute:analytics",
    "db:audit:read",
    "db:pii:access",
  ],
};

export const TOKEN_REGISTRY: Record<string, TokenRecord> = {
  "token-viewer-demo": {
    principal: "viewer@demo.internal",
    role: "public_viewer",
    scopes: [...DEFAULT_ROLE_SCOPES.public_viewer],
  },
  "token-analyst-demo": {
    principal: "analyst@demo.internal",
    role: "analyst",
    scopes: [...DEFAULT_ROLE_SCOPES.analyst],
  },
  "token-admin-demo": {
    principal: "secops-admin@demo.internal",
    role: "admin",
    scopes: [...DEFAULT_ROLE_SCOPES.admin],
  },
};

const DEMO_TOKEN_DIGESTS: Array<{ digest: Buffer; record: TokenRecord }> =
  Object.entries(TOKEN_REGISTRY).map(([token, record]) => ({
    digest: sha256Buffer(token),
    record,
  }));

function sha256Buffer(value: string): Buffer {
  return crypto.createHash("sha256").update(value, "utf8").digest();
}

function isValidAuthenticatedRole(role: unknown): role is AuthenticatedRole {
  return role === "public_viewer" || role === "analyst" || role === "admin";
}

interface EnvApiKeyEntry {
  digest: Buffer;
  record: TokenRecord;
}

let cachedEnvApiKeysRaw: string | undefined = undefined;
let cachedEnvApiKeys: EnvApiKeyEntry[] = [];

function getEnvApiKeyEntries(): EnvApiKeyEntry[] {
  const raw = process.env.MCP_SECURE_DB_API_KEYS;
  if (raw === cachedEnvApiKeysRaw) {
    return cachedEnvApiKeys;
  }
  cachedEnvApiKeysRaw = raw;
  if (!raw || raw.trim().length === 0) {
    cachedEnvApiKeys = [];
    return cachedEnvApiKeys;
  }

  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      cachedEnvApiKeys = [];
      return cachedEnvApiKeys;
    }

    const entries: EnvApiKeyEntry[] = [];
    for (const item of parsed) {
      if (!item || typeof item !== "object") continue;
      const role = (item as Record<string, unknown>).role;
      const principal = (item as Record<string, unknown>).principal;
      const token = (item as Record<string, unknown>).token;
      const tokenSha256 = (item as Record<string, unknown>).tokenSha256;
      const scopesRaw = (item as Record<string, unknown>).scopes;

      if (!isValidAuthenticatedRole(role) || typeof principal !== "string" || !principal.trim()) {
        continue;
      }

      let digest: Buffer | null = null;
      if (typeof tokenSha256 === "string" && /^[0-9a-f]{64}$/i.test(tokenSha256.trim())) {
        digest = Buffer.from(tokenSha256.trim(), "hex");
      } else if (typeof token === "string" && token.trim().length > 0) {
        digest = sha256Buffer(token.trim());
      }
      if (!digest) continue;

      const scopes = Array.isArray(scopesRaw)
        ? scopesRaw.filter((s): s is string => typeof s === "string")
        : [...DEFAULT_ROLE_SCOPES[role]];
      const tenantId = validateTenantId(
        (item as Record<string, unknown>).tenantId ??
          (item as Record<string, unknown>).tenant_id
      );

      entries.push({
        digest,
        record: {
          principal: principal.trim(),
          role,
          scopes,
          ...(tenantId ? { tenantId } : {}),
        },
      });
    }
    cachedEnvApiKeys = entries;
  } catch {
    cachedEnvApiKeys = [];
  }
  return cachedEnvApiKeys;
}

function matchDigestRecord(
  candidateDigest: Buffer,
  entries: ReadonlyArray<{ digest: Buffer; record: TokenRecord }>
): TokenRecord | null {
  let matched: TokenRecord | null = null;
  for (const entry of entries) {
    if (
      entry.digest.length === candidateDigest.length &&
      crypto.timingSafeEqual(entry.digest, candidateDigest)
    ) {
      matched = entry.record;
    }
  }
  return matched;
}

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
  allowDemoTokens?: boolean;
  oauth?: OAuthLikeContext | null;
}

export function isInsecureDemoModeEnabled(override?: boolean): boolean {
  if (process.env.NODE_ENV === "production") {
    return false;
  }
  if (typeof override === "boolean") return override;
  return process.env.MCP_SECURE_DB_INSECURE_DEMO === "true";
}

export function isDemoTokensEnabled(override?: boolean): boolean {
  if (process.env.NODE_ENV === "production") {
    return false;
  }
  if (typeof override === "boolean") return override;
  return process.env.MCP_SECURE_DB_ALLOW_DEMO_TOKENS === "true";
}

export function isArgTokenEnabled(): boolean {
  if (process.env.NODE_ENV === "production") {
    return process.env.MCP_SECURE_DB_ALLOW_ARG_TOKEN === "true";
  }
  return process.env.MCP_SECURE_DB_ALLOW_ARG_TOKEN !== "false";
}

export interface RBACManagerOptions {
  roleTools?: Record<UserRole, string[]>;
}

export class RBACManager {
  private readonly roleTools: Record<UserRole, string[]>;

  constructor(options: RBACManagerOptions = {}) {
    this.roleTools = options.roleTools
      ? {
          unauthenticated: [...options.roleTools.unauthenticated],
          public_viewer: [...options.roleTools.public_viewer],
          analyst: [...options.roleTools.analyst],
          admin: [...options.roleTools.admin],
        }
      : {
          unauthenticated: [...ROLE_TOOLS.unauthenticated],
          public_viewer: [...ROLE_TOOLS.public_viewer],
          analyst: [...ROLE_TOOLS.analyst],
          admin: [...ROLE_TOOLS.admin],
        };
  }

  /**
   * Resolves a trusted local stdio session role explicitly requested via CLI `--stdio-role`
   * (and optional `--stdio-tenant`). Never exposed over HTTP headers.
   */
  public resolveStdioRole(
    role: AuthenticatedRole,
    tenantId?: string
  ): SecurityContext {
    const validTenant = validateTenantId(tenantId);
    return {
      principal: `stdio_local_${role}`,
      role,
      authenticated: true,
      authSource: "stdio_local",
      scopes: [...DEFAULT_ROLE_SCOPES[role]],
      allowedTools: [...this.roleTools[role]],
      ...(validTenant ? { tenantId: validTenant } : {}),
    };
  }
  /**
   * Resolves caller identity using default-deny semantics:
   * 1. Verified OAuth context (`ctx.auth` from `mcp-use` OAuth middleware), when present.
   * 2. Environment-configured API keys (`MCP_SECURE_DB_API_KEYS`) matched via constant-time SHA-256 comparison.
   * 3. Static local demo tokens ONLY when `NODE_ENV !== "production"` and `MCP_SECURE_DB_ALLOW_DEMO_TOKENS=true`.
   * 4. INSECURE demo fallback (`public_viewer`) ONLY when credentials are omitted, `NODE_ENV !== "production"`,
   *    and `MCP_SECURE_DB_INSECURE_DEMO=true` is explicitly set.
   * 5. Otherwise fails closed to `unauthenticated` (no data, catalog, or prompt access).
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
          allowedTools: [...this.roleTools.public_viewer],
        };
      }
      return {
        principal: "unauthenticated",
        role: "unauthenticated",
        authenticated: false,
        authSource: "none",
        scopes: [],
        allowedTools: [...this.roleTools.unauthenticated],
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
        allowedTools: [...this.roleTools.unauthenticated],
        denialReason: "Empty Bearer token supplied.",
      };
    }

    const candidateDigest = sha256Buffer(cleanToken);

    // 1. Check production-safe env-configured API keys (constant-time SHA-256 compare)
    const envMatch = matchDigestRecord(candidateDigest, getEnvApiKeyEntries());
    if (envMatch) {
      return {
        principal: envMatch.principal,
        role: envMatch.role,
        authenticated: true,
        authSource: "token",
        scopes: [...envMatch.scopes],
        allowedTools: [...this.roleTools[envMatch.role]],
        ...(envMatch.tenantId ? { tenantId: envMatch.tenantId } : {}),
      };
    }

    // 2. Check static demo tokens ONLY when explicitly enabled outside production
    if (isDemoTokensEnabled(options.allowDemoTokens)) {
      const demoMatch = matchDigestRecord(candidateDigest, DEMO_TOKEN_DIGESTS);
      if (demoMatch) {
        return {
          principal: demoMatch.principal,
          role: demoMatch.role,
          authenticated: true,
          authSource: "token",
          scopes: [...demoMatch.scopes],
          allowedTools: [...this.roleTools[demoMatch.role]],
        };
      }
    }

    // Invalid or disallowed credentials ALWAYS fail closed
    return {
      principal: "unauthenticated",
      role: "unauthenticated",
      authenticated: false,
      authSource: "none",
      scopes: [],
      allowedTools: [...this.roleTools.unauthenticated],
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
    const extraObj = (oauth.extra ?? {}) as Record<string, unknown>;
    const principal =
      (typeof userObj.email === "string" && userObj.email) ||
      (typeof userObj.sub === "string" && userObj.sub) ||
      (typeof payloadObj.sub === "string" && payloadObj.sub) ||
      oauth.clientId ||
      "oauth_authenticated_principal";
    const tenantId = validateTenantId(
      payloadObj.tenant_id ??
        payloadObj.org_id ??
        payloadObj.tid ??
        userObj.tenant_id ??
        userObj.org_id ??
        extraObj.tenant_id
    );

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
        allowedTools: [...this.roleTools.unauthenticated],
        ...(tenantId ? { tenantId } : {}),
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
      allowedTools: [...this.roleTools[role]],
      ...(tenantId ? { tenantId } : {}),
    };
  }

  public canAccessTool(role: UserRole, toolName: string): boolean {
    const allowed = Object.hasOwn(this.roleTools, role)
      ? this.roleTools[role]
      : [];
    return allowed.includes(toolName);
  }

  public canReadCatalog(role: UserRole): boolean {
    return this.canAccessResource(role, "schema://catalog");
  }

  public canAccessResource(role: UserRole, uri: string): boolean {
    const allowed = Object.hasOwn(ROLE_RESOURCES, role)
      ? ROLE_RESOURCES[role]
      : [];
    return allowed.includes(uri);
  }

  public canAccessPrompt(role: UserRole, promptName: string): boolean {
    const allowed = Object.hasOwn(ROLE_PROMPTS, role) ? ROLE_PROMPTS[role] : [];
    return allowed.includes(promptName);
  }

  public filterTools<T extends { name: string }>(
    role: UserRole,
    tools: T[]
  ): T[] {
    const allowed = new Set(
      Object.hasOwn(this.roleTools, role) ? this.roleTools[role] : []
    );
    return tools.filter((t) => allowed.has(t.name));
  }

  public filterResources<T extends { uri: string }>(
    role: UserRole,
    resources: T[]
  ): T[] {
    const allowed = new Set(
      Object.hasOwn(ROLE_RESOURCES, role) ? ROLE_RESOURCES[role] : []
    );
    return resources.filter((r) => allowed.has(r.uri));
  }

  public filterPrompts<T extends { name: string }>(
    role: UserRole,
    prompts: T[]
  ): T[] {
    const allowed = new Set(
      Object.hasOwn(ROLE_PROMPTS, role) ? ROLE_PROMPTS[role] : []
    );
    return prompts.filter((p) => allowed.has(p.name));
  }
}

export const rbacManager = new RBACManager();
