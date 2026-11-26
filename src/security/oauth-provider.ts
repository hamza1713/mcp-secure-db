/**
 * Generic OIDC / JWT OAuth resource-server provider for mcp-secure-db.
 *
 * Works with any identity provider that issues signed JWT access tokens and
 * publishes a JWKS (Okta, Microsoft Entra ID, Auth0, Keycloak, Google, Cognito,
 * WorkOS, ...). Token signature, issuer, audience/resource binding and expiry
 * are verified by `mcp-use`'s `createJwtVerifier`; this module only maps the
 * verified claims onto mcp-secure-db roles and tenants.
 *
 * Enabled by setting `MCP_SECURE_DB_OAUTH_ISSUER`. When enabled, every request
 * to the HTTP MCP endpoint must carry a valid JWT access token: static API keys
 * and demo tokens are no longer accepted on that endpoint (fail closed).
 */
import {
  createJwtVerifier,
  oauthCustomProvider,
  type OAuthAuthInfo,
  type OAuthProvider,
} from "mcp-use/oauth";
import type { AuthenticatedRole } from "./rbac.js";

/** Identity exposed to callbacks as `ctx.auth.user`. */
export interface SecureDbOAuthUser {
  id: string;
  email?: string;
  tenant_id?: string;
  roles: AuthenticatedRole[];
}

export interface SecureDbOAuthConfig {
  issuer: string;
  jwksUrl: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  /** Expected `aud` claim(s), when the IdP's audience differs from the MCP resource URL. */
  audience?: string[];
  /** Canonical public MCP endpoint URL, for example `https://db-gateway.example.com/mcp`. */
  resourceUrl?: string;
  /** Claim holding IdP roles or groups (exact key, or dotted path such as `realm_access.roles`). */
  roleClaim: string;
  /** Maps IdP role/group values onto mcp-secure-db roles. */
  roleMap: Record<string, AuthenticatedRole>;
  /** Claim holding the caller's tenant identifier. */
  tenantClaim: string;
  /** Permitted JWS algorithms (asymmetric only by default). */
  algorithms: string[];
  /**
   * Also honour mcp-secure-db scopes (db:read:metadata, db:execute:analytics,
   * db:audit:read, db:pii:access) granted in the token's scope claim. Off by
   * default because some IdPs let clients request any scope defined on an API.
   */
  trustScopes: boolean;
}

export class OAuthConfigError extends Error {
  constructor(message: string) {
    super(`[mcp-secure-db] OAuth configuration error: ${message}`);
    this.name = "OAuthConfigError";
  }
}

const VALID_ROLES = new Set<AuthenticatedRole>([
  "public_viewer",
  "analyst",
  "admin",
]);

/** Canonical mcp-secure-db scope granted for each role (consumed by RBACManager.resolveFromOAuth). */
const ROLE_SCOPE: Record<AuthenticatedRole, string> = {
  public_viewer: "db:read:metadata",
  analyst: "db:execute:analytics",
  admin: "db:audit:read",
};

const TRUSTABLE_SCOPES = new Set([
  "db:read:metadata",
  "db:execute:analytics",
  "db:audit:read",
  "db:pii:access",
]);

const ROLE_RANK: Record<AuthenticatedRole, number> = {
  public_viewer: 1,
  analyst: 2,
  admin: 3,
};

const DEFAULT_ROLE_MAP: Record<string, AuthenticatedRole> = {
  public_viewer: "public_viewer",
  viewer: "public_viewer",
  analyst: "analyst",
  admin: "admin",
};

const DEFAULT_ALGORITHMS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
];

function parseUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new OAuthConfigError(`${name} must be an absolute URL (got '${value}').`);
  }
  const isLocal =
    url.hostname === "localhost" ||
    url.hostname === "127.0.0.1" ||
    url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocal)) {
    throw new OAuthConfigError(`${name} must use https (http is allowed only for localhost).`);
  }
  return url.toString();
}

function csv(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Reads OAuth settings from the environment.
 *
 * @returns `null` when OAuth is not enabled (`MCP_SECURE_DB_OAUTH_ISSUER` unset).
 * @throws OAuthConfigError when OAuth is enabled but incomplete or invalid, so the
 * server never silently starts without the authentication the operator asked for.
 */
export function readOAuthConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env
): SecureDbOAuthConfig | null {
  const issuerRaw = env.MCP_SECURE_DB_OAUTH_ISSUER?.trim();
  if (!issuerRaw) return null;

  const required = (name: string): string => {
    const value = env[name]?.trim();
    if (!value) {
      throw new OAuthConfigError(
        `${name} is required when MCP_SECURE_DB_OAUTH_ISSUER is set. ` +
          "Copy it from your identity provider's /.well-known/openid-configuration document."
      );
    }
    return value;
  };

  const issuer = issuerRaw.replace(/\/+$/, "");
  parseUrl("MCP_SECURE_DB_OAUTH_ISSUER", issuer);

  let roleMap: Record<string, AuthenticatedRole> = { ...DEFAULT_ROLE_MAP };
  const roleMapRaw = env.MCP_SECURE_DB_OAUTH_ROLE_MAP?.trim();
  if (roleMapRaw) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(roleMapRaw);
    } catch {
      throw new OAuthConfigError("MCP_SECURE_DB_OAUTH_ROLE_MAP must be a JSON object.");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new OAuthConfigError("MCP_SECURE_DB_OAUTH_ROLE_MAP must be a JSON object.");
    }
    roleMap = Object.create(null);
    for (const [idpValue, role] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof role !== "string" || !VALID_ROLES.has(role as AuthenticatedRole)) {
        throw new OAuthConfigError(
          `MCP_SECURE_DB_OAUTH_ROLE_MAP value for '${idpValue}' must be one of public_viewer, analyst, admin.`
        );
      }
      roleMap[idpValue] = role as AuthenticatedRole;
    }
  }

  const algorithms = csv(env.MCP_SECURE_DB_OAUTH_ALGORITHMS);
  for (const alg of algorithms) {
    if (alg.toLowerCase() === "none" || /^HS/i.test(alg)) {
      throw new OAuthConfigError(
        `MCP_SECURE_DB_OAUTH_ALGORITHMS must list asymmetric algorithms only (rejected '${alg}').`
      );
    }
  }

  const audience = csv(env.MCP_SECURE_DB_OAUTH_AUDIENCE);
  const resourceUrlRaw = env.MCP_SECURE_DB_OAUTH_RESOURCE_URL?.trim();

  return {
    issuer,
    jwksUrl: parseUrl("MCP_SECURE_DB_OAUTH_JWKS_URL", required("MCP_SECURE_DB_OAUTH_JWKS_URL")),
    authorizationEndpoint: parseUrl(
      "MCP_SECURE_DB_OAUTH_AUTHORIZATION_ENDPOINT",
      required("MCP_SECURE_DB_OAUTH_AUTHORIZATION_ENDPOINT")
    ),
    tokenEndpoint: parseUrl(
      "MCP_SECURE_DB_OAUTH_TOKEN_ENDPOINT",
      required("MCP_SECURE_DB_OAUTH_TOKEN_ENDPOINT")
    ),
    ...(audience.length > 0 ? { audience } : {}),
    ...(resourceUrlRaw
      ? { resourceUrl: parseUrl("MCP_SECURE_DB_OAUTH_RESOURCE_URL", resourceUrlRaw) }
      : {}),
    roleClaim: env.MCP_SECURE_DB_OAUTH_ROLE_CLAIM?.trim() || "roles",
    roleMap,
    tenantClaim: env.MCP_SECURE_DB_OAUTH_TENANT_CLAIM?.trim() || "tenant_id",
    algorithms: algorithms.length > 0 ? algorithms : [...DEFAULT_ALGORITHMS],
    trustScopes: env.MCP_SECURE_DB_OAUTH_TRUST_SCOPES?.trim() === "true",
  };
}

/**
 * Reads a claim by exact key first (supports namespaced claims such as
 * `https://example.com/roles`), then by dotted path (`realm_access.roles`).
 */
export function readClaim(payload: Record<string, unknown>, claim: string): unknown {
  if (Object.hasOwn(payload, claim)) return payload[claim];
  let current: unknown = payload;
  for (const part of claim.split(".")) {
    if (!current || typeof current !== "object" || Array.isArray(current)) return undefined;
    if (!Object.hasOwn(current as object, part)) return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function claimStrings(value: unknown): string[] {
  if (typeof value === "string") return value.split(/[\s,]+/).filter(Boolean);
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === "string");
  return [];
}

/**
 * Maps verified JWT claims onto an mcp-secure-db identity. Only role values
 * present in the role map are honoured; everything else is ignored, so an
 * unmapped token resolves to `unauthenticated` (default deny).
 */
export function mapClaimsToIdentity(
  payload: Record<string, unknown>,
  config: Pick<SecureDbOAuthConfig, "roleClaim" | "roleMap" | "tenantClaim">
): { user: SecureDbOAuthUser; permissions: string[] } {
  const sub = typeof payload.sub === "string" && payload.sub.trim() ? payload.sub : undefined;
  if (!sub) {
    throw new Error("Verified access token has no subject (sub) claim.");
  }

  const roles = new Set<AuthenticatedRole>();
  for (const value of claimStrings(readClaim(payload, config.roleClaim))) {
    if (Object.hasOwn(config.roleMap, value)) roles.add(config.roleMap[value]);
  }
  const orderedRoles = [...roles].sort((a, b) => ROLE_RANK[b] - ROLE_RANK[a]);

  const tenantRaw = readClaim(payload, config.tenantClaim);
  const email = typeof payload.email === "string" ? payload.email : undefined;

  return {
    user: {
      id: sub,
      ...(email ? { email } : {}),
      ...(typeof tenantRaw === "string" && tenantRaw ? { tenant_id: tenantRaw } : {}),
      roles: orderedRoles,
    },
    // Only the highest mapped role is granted, so RBAC resolution is unambiguous.
    permissions: orderedRoles.length > 0 ? [ROLE_SCOPE[orderedRoles[0]]] : [],
  };
}

/** Builds the `mcp-use` OAuth provider from a validated configuration. */
export function createSecureDbOAuthProvider(
  config: SecureDbOAuthConfig
): OAuthProvider<SecureDbOAuthUser> {
  return oauthCustomProvider<SecureDbOAuthUser>({
    ...(config.resourceUrl ? { resource: config.resourceUrl } : {}),
    scopesSupported: Object.values(ROLE_SCOPE),
    resourceName: "mcp-secure-db",
    createTokenVerifier: (resource) =>
      createJwtVerifier({
        issuer: config.issuer,
        jwksUrl: new URL(config.jwksUrl),
        resource,
        ...(config.audience ? { audience: config.audience } : {}),
        algorithms: config.algorithms,
      }),
    oauthMetadata: {
      issuer: config.issuer,
      authorization_endpoint: config.authorizationEndpoint,
      token_endpoint: config.tokenEndpoint,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
    },
    mapAuthInfo: (authInfo: OAuthAuthInfo) => {
      // createJwtVerifier stores the verified claims at `extra.payload`.
      const payload = (authInfo.extra as Record<string, unknown> | undefined)?.payload;
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw new Error("Verified token payload is missing.");
      }
      const claims = payload as Record<string, unknown>;
      const { user, permissions } = mapClaimsToIdentity(claims, config);
      if (config.trustScopes) {
        for (const scope of authInfo.scopes ?? []) {
          if (TRUSTABLE_SCOPES.has(scope) && !permissions.includes(scope)) permissions.push(scope);
        }
      }
      return { user, payload: claims, permissions };
    },
  });
}

/** Convenience: provider from environment, or `undefined` when OAuth is disabled. */
export function oauthProviderFromEnv(
  env: NodeJS.ProcessEnv = process.env
): OAuthProvider<SecureDbOAuthUser> | undefined {
  const config = readOAuthConfigFromEnv(env);
  return config ? createSecureDbOAuthProvider(config) : undefined;
}
