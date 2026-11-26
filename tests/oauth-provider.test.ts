import { describe, it, expect, beforeAll, afterAll } from "vitest";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  createSecureDbOAuthProvider,
  mapClaimsToIdentity,
  OAuthConfigError,
  readClaim,
  readOAuthConfigFromEnv,
  type SecureDbOAuthConfig,
} from "../src/security/oauth-provider.js";
import { createSecureMcpServer, type SecureMcpServerInstance } from "../src/index.js";

const RESOURCE = "http://localhost/mcp";
const AUDIENCE = "mcp-secure-db-api";

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

function signJwt(
  privateKey: crypto.KeyObject,
  kid: string,
  claims: Record<string, unknown>,
  alg: "RS256" | "none" = "RS256"
): string {
  const header = b64url(JSON.stringify({ alg, typ: "JWT", kid }));
  const body = b64url(JSON.stringify(claims));
  if (alg === "none") return `${header}.${body}.`;
  const sig = crypto.sign("RSA-SHA256", Buffer.from(`${header}.${body}`), privateKey);
  return `${header}.${body}.${b64url(sig)}`;
}

async function rpc(
  instance: SecureMcpServerInstance,
  body: Record<string, unknown>,
  token?: string
): Promise<{ status: number; json: any }> {
  const res = await instance.server.fetch(
    new Request(RESOURCE, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...(token ? { authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    })
  );
  const text = await res.text();
  if (!text.trim()) return { status: res.status, json: null };
  if (text.trim().startsWith("{")) return { status: res.status, json: JSON.parse(text) };
  const data = text
    .split(/\r?\n/)
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim())
    .filter(Boolean);
  return { status: res.status, json: data.length ? JSON.parse(data[data.length - 1]) : null };
}

async function toolNames(instance: SecureMcpServerInstance, token?: string) {
  const { status, json } = await rpc(
    instance,
    { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
    token
  );
  return { status, names: (json?.result?.tools ?? []).map((t: any) => t.name) as string[] };
}

async function whoami(instance: SecureMcpServerInstance, token: string) {
  const { json } = await rpc(
    instance,
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "whoami", arguments: {} } },
    token
  );
  const text = json?.result?.content?.[0]?.text ?? "{}";
  return JSON.parse(text);
}

describe("OAuth / OIDC JWT provider", () => {
  const kid = "test-key-1";
  const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  const attacker = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  let jwksServer: http.Server;
  let issuer: string;
  let config: SecureDbOAuthConfig;
  let instance: SecureMcpServerInstance;

  const now = () => Math.floor(Date.now() / 1000);
  const baseClaims = () => ({
    iss: issuer,
    aud: [AUDIENCE, RESOURCE],
    sub: "user-123",
    email: "analyst@example.com",
    iat: now(),
    exp: now() + 300,
  });

  beforeAll(async () => {
    const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" };
    jwksServer = http.createServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [jwk] }));
    });
    await new Promise<void>((resolve) => jwksServer.listen(0, "127.0.0.1", resolve));
    const { port } = jwksServer.address() as AddressInfo;
    issuer = `http://localhost:${port}`;

    config = readOAuthConfigFromEnv({
      MCP_SECURE_DB_OAUTH_ISSUER: issuer,
      MCP_SECURE_DB_OAUTH_JWKS_URL: `${issuer}/jwks`,
      MCP_SECURE_DB_OAUTH_AUTHORIZATION_ENDPOINT: `${issuer}/authorize`,
      MCP_SECURE_DB_OAUTH_TOKEN_ENDPOINT: `${issuer}/token`,
      MCP_SECURE_DB_OAUTH_AUDIENCE: AUDIENCE,
      MCP_SECURE_DB_OAUTH_RESOURCE_URL: RESOURCE,
      MCP_SECURE_DB_OAUTH_ROLE_CLAIM: "groups",
      MCP_SECURE_DB_OAUTH_ROLE_MAP: JSON.stringify({
        "db-viewers": "public_viewer",
        "db-analysts": "analyst",
        "db-admins": "admin",
      }),
      MCP_SECURE_DB_OAUTH_TENANT_CLAIM: "org",
    })!;
    instance = createSecureMcpServer({ oauth: createSecureDbOAuthProvider(config) });
  });

  afterAll(async () => {
    await instance?.engine.close();
    await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
  });

  describe("configuration", () => {
    it("is disabled when no issuer is set", () => {
      expect(readOAuthConfigFromEnv({})).toBeNull();
    });

    it("fails closed when OAuth is enabled but incomplete", () => {
      expect(() =>
        readOAuthConfigFromEnv({ MCP_SECURE_DB_OAUTH_ISSUER: "https://idp.example.com" })
      ).toThrow(OAuthConfigError);
    });

    it("rejects non-https endpoints, symmetric/none algorithms and invalid role maps", () => {
      const base = {
        MCP_SECURE_DB_OAUTH_ISSUER: "https://idp.example.com",
        MCP_SECURE_DB_OAUTH_JWKS_URL: "https://idp.example.com/keys",
        MCP_SECURE_DB_OAUTH_AUTHORIZATION_ENDPOINT: "https://idp.example.com/authorize",
        MCP_SECURE_DB_OAUTH_TOKEN_ENDPOINT: "https://idp.example.com/token",
      };
      expect(readOAuthConfigFromEnv(base)).not.toBeNull();
      expect(() =>
        readOAuthConfigFromEnv({ ...base, MCP_SECURE_DB_OAUTH_JWKS_URL: "http://idp.example.com/keys" })
      ).toThrow(/https/);
      expect(() => readOAuthConfigFromEnv({ ...base, MCP_SECURE_DB_OAUTH_ALGORITHMS: "HS256" })).toThrow(
        /asymmetric/
      );
      expect(() => readOAuthConfigFromEnv({ ...base, MCP_SECURE_DB_OAUTH_ALGORITHMS: "none" })).toThrow(
        /asymmetric/
      );
      expect(() =>
        readOAuthConfigFromEnv({ ...base, MCP_SECURE_DB_OAUTH_ROLE_MAP: '{"x":"superuser"}' })
      ).toThrow(/must be one of/);
    });
  });

  describe("claim mapping", () => {
    it("reads namespaced and dotted claims", () => {
      expect(readClaim({ "https://acme.io/roles": ["a"] }, "https://acme.io/roles")).toEqual(["a"]);
      expect(readClaim({ realm_access: { roles: ["b"] } }, "realm_access.roles")).toEqual(["b"]);
      expect(readClaim({ a: 1 }, "constructor.prototype")).toBeUndefined();
    });

    it("grants only the highest mapped role and ignores unmapped values", () => {
      const m = mapClaimsToIdentity(
        { sub: "u", groups: ["everyone", "db-analysts", "db-viewers"] },
        config
      );
      expect(m.user.roles).toEqual(["analyst", "public_viewer"]);
      expect(m.permissions).toEqual(["db:execute:analytics"]);
      expect(mapClaimsToIdentity({ sub: "u", groups: ["admin"] }, config).permissions).toEqual([]);
    });

    it("honours only recognised db:* scopes when MCP_SECURE_DB_OAUTH_TRUST_SCOPES=true", () => {
      const trusting = createSecureDbOAuthProvider({ ...config, trustScopes: true });
      const mapped = trusting.mapAuthInfo({
        token: "t",
        clientId: "c",
        scopes: ["db:execute:analytics", "admin", "openid"],
        extra: { payload: { sub: "svc" } },
      } as any);
      expect(mapped.permissions).toEqual(["db:execute:analytics"]);
      const strict = createSecureDbOAuthProvider(config).mapAuthInfo({
        token: "t",
        clientId: "c",
        scopes: ["db:execute:analytics"],
        extra: { payload: { sub: "svc" } },
      } as any);
      expect(strict.permissions).toEqual([]);
    });

    it("requires a subject", () => {
      expect(() => mapClaimsToIdentity({ groups: ["db-admins"] }, config)).toThrow(/sub/);
    });
  });

  describe("end-to-end over the MCP HTTP endpoint", () => {
    it("rejects requests without a token, with a static API key, or with a demo token", async () => {
      expect((await toolNames(instance)).status).toBe(401);
      expect((await toolNames(instance, "token-admin-demo")).status).toBe(401);
      expect((await toolNames(instance, "some-static-api-key")).status).toBe(401);
    });

    it("rejects forged, unsigned, expired, wrong-issuer and wrong-audience tokens", async () => {
      const claims = { ...baseClaims(), groups: ["db-admins"] };
      const cases = [
        signJwt(attacker.privateKey, kid, claims),
        signJwt(privateKey, kid, claims, "none"),
        signJwt(privateKey, kid, { ...claims, exp: now() - 60 }),
        signJwt(privateKey, kid, { ...claims, iss: "https://evil.example.com" }),
        signJwt(privateKey, kid, { ...claims, aud: "some-other-api" }),
      ];
      for (const token of cases) {
        expect((await toolNames(instance, token)).status).toBe(401);
      }
    });

    it("maps a verified analyst token to the analyst role, principal and tenant", async () => {
      const token = signJwt(privateKey, kid, { ...baseClaims(), groups: ["db-analysts"], org: "tenant_acme" });
      const { status, names } = await toolNames(instance, token);
      expect(status).toBe(200);
      expect(names).toContain("execute_analytical_sql");
      expect(names).not.toContain("get_security_audit_log");

      const me = await whoami(instance, token);
      expect(me.role).toBe("analyst");
      expect(me.principal).toBe("analyst@example.com");
      expect(me.tenantId ?? me.tenant_id).toBe("tenant_acme");
    });

    it("maps admin and viewer groups, and gives an unmapped token no data tools", async () => {
      const admin = signJwt(privateKey, kid, { ...baseClaims(), groups: ["db-admins"] });
      expect((await toolNames(instance, admin)).names).toContain("get_security_audit_log");

      const viewer = signJwt(privateKey, kid, { ...baseClaims(), groups: ["db-viewers"] });
      const viewerTools = (await toolNames(instance, viewer)).names;
      expect(viewerTools).toContain("list_tables");
      expect(viewerTools).not.toContain("execute_analytical_sql");

      const nobody = signJwt(privateKey, kid, { ...baseClaims(), groups: ["marketing"] });
      expect((await toolNames(instance, nobody)).names).toEqual(["whoami"]);
    });

    it("does not grant roles from self-requested token scopes unless explicitly trusted", async () => {
      const token = signJwt(privateKey, kid, {
        ...baseClaims(),
        scope: "db:audit:read db:pii:access",
        groups: [],
      });
      expect((await toolNames(instance, token)).names).toEqual(["whoami"]);
    });

    it("keeps operational probes reachable without a token", async () => {
      const res = await instance.server.fetch(new Request("http://localhost/healthz"));
      expect(res.status).toBe(200);
    });
  });
});
