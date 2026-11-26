#!/usr/bin/env node
import dotenv from "dotenv";
dotenv.config({ quiet: true });
import path from "node:path";
import readline from "node:readline";
import { parseArgs } from "node:util";
import { AuthenticatedRole, validateTenantId } from "./security/rbac.js";
import { loadPolicyFromFile } from "./policy/loader.js";
import { verifyAuditLogFile } from "./database/audit.js";
import { createSecureMcpServer } from "./index.js";

const VALID_STDIO_ROLES = new Set<AuthenticatedRole>([
  "public_viewer",
  "analyst",
  "admin",
]);

function printHelp(): void {
  process.stderr.write(`mcp-secure-db v1.0.0 — Zero-Trust SQL MCP Gateway

Usage:
  mcp-secure-db [options]

Options:
  --config <path>            Path to declarative policy.yaml or policy.json
  --transport <http|stdio>   Transport protocol (default: http)
  --port <number>            HTTP listen port (default: $PORT or 8000)
  --host <address>           HTTP bind host (default: $HOST or 127.0.0.1)
  --stdio-role <role>        Explicit local role for stdio mode (public_viewer | analyst | admin)
                             When omitted, stdio uses $MCP_SECURE_DB_TOKEN or default-deny.
  --stdio-tenant <id>        Optional local tenantId paired with --stdio-role in stdio mode
  --validate-policy          Validate policy file, live schema introspection, and all templates, then exit
  --offline                  With --validate-policy, validate policy schema and templates without connecting to PostgreSQL
  --verify-audit [path]      Cryptographically verify SHA-256 / HMAC-SHA256 hash chain of an audit JSONL file, then exit
  --audit-path <path>        Explicit audit JSONL path for --verify-audit (defaults to $MCP_SECURE_DB_AUDIT_PATH or ./data/audit.jsonl)
  --version                  Show version
  --help                     Show this help message
`);
}

function extractJsonRpcPayload(rawText: string): string | null {
  const trimmed = rawText.trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("{")) {
    return trimmed;
  }
  const dataLines = trimmed
    .split(/\r?\n/)
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim())
    .filter(Boolean);
  if (dataLines.length === 0) return null;
  return dataLines[dataLines.length - 1];
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    options: {
      config: { type: "string", short: "c" },
      transport: { type: "string", short: "t", default: "http" },
      port: { type: "string", short: "p" },
      host: { type: "string" },
      "stdio-role": { type: "string" },
      "stdio-tenant": { type: "string" },
      "validate-policy": { type: "boolean", default: false },
      "verify-audit": { type: "boolean", default: false },
      "audit-path": { type: "string" },
      offline: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
    strict: true,
    allowPositionals: true,
  });

  if (values.help) {
    printHelp();
    process.exit(0);
  }

  if (values.version) {
    process.stdout.write("mcp-secure-db 1.0.0\n");
    process.exit(0);
  }

  if (values["verify-audit"]) {
    const targetAuditPath =
      values["audit-path"] ??
      positionals[0] ??
      process.env.MCP_SECURE_DB_AUDIT_PATH?.trim() ??
      path.resolve(process.cwd(), "data", "audit.jsonl");

    const report = verifyAuditLogFile(targetAuditPath);
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    process.exit(report.valid ? 0 : 1);
  }

  if (positionals.length > 0) {
    process.stderr.write(
      `[mcp-secure-db] Unexpected positional argument(s): ${positionals.join(" ")}\n`
    );
    process.exit(1);
  }

  const transport = (values.transport || "http").toLowerCase();
  if (transport !== "http" && transport !== "stdio") {
    process.stderr.write(
      `[mcp-secure-db] Invalid --transport '${values.transport}'. Expected 'http' or 'stdio'.\n`
    );
    process.exit(1);
  }

  let stdioRole: AuthenticatedRole | undefined;
  if (values["stdio-role"]) {
    if (transport !== "stdio") {
      process.stderr.write(
        "[mcp-secure-db] SecurityError: --stdio-role is only permitted with --transport stdio.\n"
      );
      process.exit(1);
    }
    const candidate = values["stdio-role"].toLowerCase() as AuthenticatedRole;
    if (!VALID_STDIO_ROLES.has(candidate)) {
      process.stderr.write(
        `[mcp-secure-db] Invalid --stdio-role '${values["stdio-role"]}'. Expected public_viewer, analyst, or admin.\n`
      );
      process.exit(1);
    }
    stdioRole = candidate;
  }

  let stdioTenantId: string | undefined;
  if (values["stdio-tenant"]) {
    if (transport !== "stdio" || !stdioRole) {
      process.stderr.write(
        "[mcp-secure-db] SecurityError: --stdio-tenant requires --transport stdio and --stdio-role.\n"
      );
      process.exit(1);
    }
    const validated = validateTenantId(values["stdio-tenant"]);
    if (!validated) {
      process.stderr.write(
        `[mcp-secure-db] Invalid --stdio-tenant '${values["stdio-tenant"]}'. Must match /^[a-zA-Z0-9._:@-]{1,128}$/.\n`
      );
      process.exit(1);
    }
    stdioTenantId = validated;
  }

  const configPath =
    values.config ?? process.env.MCP_SECURE_DB_POLICY_PATH?.trim();

  const policy = configPath ? loadPolicyFromFile(configPath) : undefined;

  if (values["validate-policy"]) {
    if (!policy) {
      process.stderr.write(
        "[mcp-secure-db] --validate-policy requires --config <path> or MCP_SECURE_DB_POLICY_PATH.\n"
      );
      process.exit(1);
    }

    if (values.offline && policy.engine.type === "postgres") {
      const { PostgresAstValidator } = await import(
        "./security/pg-ast-validator.js"
      );
      const { compileAndValidateTemplate } = await import(
        "./security/template-engine.js"
      );
      // Build synthetic table metadata for all declared tables so offline AST checks succeed
      const declaredTableMeta: Record<string, any> = {};
      const allTables = new Set([
        ...policy.roleAllowedTables.public_viewer,
        ...policy.roleAllowedTables.analyst,
        ...policy.roleAllowedTables.admin,
      ]);
      for (const tbl of allTables) {
        const piiCols = [...(policy.pii.explicitColumnsByTable[tbl] ?? [])];
        declaredTableMeta[tbl] = {
          name: tbl,
          description: "Declared policy table",
          adminOnly:
            !policy.roleAllowedTables.analyst.includes(tbl) &&
            !policy.roleAllowedTables.public_viewer.includes(tbl),
          rowCount: 0,
          columns: piiCols.map((c) => ({
            name: c,
            type: "TEXT",
            isPII: true,
            description: "Declared PII column",
          })),
        };
      }
      const allPii = new Set<string>();
      for (const s of Object.values(policy.pii.explicitColumnsByTable)) {
        for (const c of s) allPii.add(c);
      }
      const pgValidator = new PostgresAstValidator({
        maxRows: policy.adhocSql.maxRows,
        defaultLimit: policy.adhocSql.defaultLimit,
        maxOffset: policy.adhocSql.maxOffset,
        allowedSchemas: policy.engine.allowedSchemas,
        extraAllowedViews: policy.extraAllowedViews,
        roleAllowedTables: policy.roleAllowedTables,
        tableMetadata: declaredTableMeta,
        piiColumns: allPii,
        piiColumnsByTable: policy.pii.explicitColumnsByTable,
      });

      try {
        const compiled = policy.templates.map((t) =>
          compileAndValidateTemplate(t, "postgresql", (sql, role) =>
            pgValidator.validate(sql, role)
          )
        );
        process.stdout.write(
          JSON.stringify(
            {
              valid: true,
              mode: "offline",
              policyPath: policy.sourcePath,
              engine: policy.engine.type,
              adhocSqlEnabled: policy.adhocSql.enabled,
              declaredTables: [...allTables],
              validatedTemplates: compiled.map((t) => ({
                name: t.definition.name,
                allowedRoles: t.definition.allowed_roles,
                paramCount: t.paramOrder.length,
                contextParams: t.contextParamsUsed,
                limitApplied: t.limitApplied,
              })),
            },
            null,
            2
          ) + "\n"
        );
        process.exit(0);
      } catch (err: any) {
        process.stderr.write(
          `[mcp-secure-db] Offline policy validation FAILED: ${err.message}\n`
        );
        process.exit(1);
      }
    }

    const instance = createSecureMcpServer({ policy });
    try {
      const compiled = await instance.validateTemplates();
      const adminTables = instance.engine.getTables("admin");
      process.stdout.write(
        JSON.stringify(
          {
            valid: true,
            policyPath: policy.sourcePath,
            engine: policy.engine.type,
            adhocSqlEnabled: policy.adhocSql.enabled,
            introspectedTables: adminTables.map((t) => ({
              name: t.name,
              rowCount: t.rowCount,
              columnCount: t.columns.length,
            })),
            validatedTemplates: compiled.map((t) => ({
              name: t.definition.name,
              allowedRoles: t.definition.allowed_roles,
              paramCount: t.paramOrder.length,
              contextParams: t.contextParamsUsed,
              limitApplied: t.limitApplied,
            })),
          },
          null,
          2
        ) + "\n"
      );
      await instance.engine.close();
      process.exit(0);
    } catch (err: any) {
      process.stderr.write(
        `[mcp-secure-db] Policy validation FAILED: ${err.message}\n`
      );
      await instance.engine.close().catch(() => {});
      process.exit(1);
    }
  }

  // In stdio mode, preserve a private handle to raw stdout exclusively for JSON-RPC
  // frames and redirect all incidental console/stdout writes (e.g. mcp-use request
  // access logs) to stderr so IDE MCP clients never receive corrupted frames.
  const rawStdoutWrite = process.stdout.write.bind(process.stdout);
  if (transport === "stdio" && !values["validate-policy"]) {
    const redirectToStderr = (...args: unknown[]) => console.error(...args);
    console.log = redirectToStderr;
    console.info = redirectToStderr;
    console.debug = redirectToStderr;
    console.warn = redirectToStderr;
    process.stdout.write = ((
      chunk: string | Uint8Array,
      encoding?: BufferEncoding | ((err?: Error | null) => void),
      cb?: (err?: Error | null) => void
    ): boolean => {
      if (typeof encoding === "function") {
        return process.stderr.write(chunk, encoding);
      }
      return process.stderr.write(chunk, encoding, cb);
    }) as typeof process.stdout.write;
  }

  // OAuth guards the network-facing HTTP endpoint. The stdio transport is a
  // local process whose trust comes from the launching user (--stdio-role or
  // MCP_SECURE_DB_TOKEN), so the OAuth gate is not applied there.
  const oauthEnvSet = Boolean(process.env.MCP_SECURE_DB_OAUTH_ISSUER?.trim());
  if (transport === "stdio" && oauthEnvSet) {
    process.stderr.write(
      "[mcp-secure-db] MCP_SECURE_DB_OAUTH_ISSUER is ignored for the stdio transport (local trust).\n"
    );
  }
  const instance = createSecureMcpServer({
    policy,
    stdioRole,
    stdioTenantId,
    ...(transport === "stdio" ? { oauth: null } : {}),
  });

  // Eagerly initialize engine introspection and validate all declared templates at boot
  await instance.validateTemplates();

  const shutdown = () => {
    void instance.engine.close().finally(() => process.exit(0));
  };
  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);

  if (transport === "stdio") {
    const envToken = process.env.MCP_SECURE_DB_TOKEN?.trim();
    const authLabel = envToken
      ? "env:MCP_SECURE_DB_TOKEN"
      : stdioRole
        ? `stdio-role:${stdioRole}`
        : "unauthenticated (default-deny)";

    // CRITICAL: stdout is exclusively reserved for JSON-RPC frames in stdio mode
    process.stderr.write(
      `[mcp-secure-db] stdio transport ready (engine=${instance.policy.engine.type}, policy=${instance.policy.mode}, auth=${authLabel}, templates=${instance.policy.templates.length})\n`
    );

    const rl = readline.createInterface({
      input: process.stdin,
      crlfDelay: Infinity,
      terminal: false,
    });

    for await (const rawLine of rl) {
      const line = rawLine.trim();
      if (!line) continue;

      let parsedMsg: any;
      try {
        parsedMsg = JSON.parse(line);
      } catch (err: any) {
        rawStdoutWrite(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: `Parse error: ${err.message}`,
            },
          }) + "\n"
        );
        continue;
      }

      const headers: Record<string, string> = {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      };
      if (envToken) {
        headers.authorization = envToken.toLowerCase().startsWith("bearer ")
          ? envToken
          : `Bearer ${envToken}`;
      }

      try {
        const req = new Request("http://localhost/mcp", {
          method: "POST",
          headers,
          body: line,
        });
        const res = await instance.server.fetch(req);
        const bodyText = await res.text();

        // MCP notifications (no `id`) do not expect a JSON-RPC response frame
        const isNotification =
          parsedMsg &&
          typeof parsedMsg === "object" &&
          !Object.hasOwn(parsedMsg, "id");
        if (isNotification) {
          continue;
        }

        const payload = extractJsonRpcPayload(bodyText);
        if (payload) {
          rawStdoutWrite(payload + "\n");
        }
      } catch (err: any) {
        if (parsedMsg && Object.hasOwn(parsedMsg, "id")) {
          rawStdoutWrite(
            JSON.stringify({
              jsonrpc: "2.0",
              id: parsedMsg.id,
              error: {
                code: -32603,
                message: `Internal stdio bridge error: ${err.message}`,
              },
            }) + "\n"
          );
        }
      }
    }

    await instance.engine.close();
    process.exit(0);
  }

  // HTTP transport mode
  const port = Number(values.port ?? process.env.PORT ?? 8000);
  const host = values.host ?? process.env.HOST ?? "127.0.0.1";
  process.stderr.write(
    `[mcp-secure-db] starting HTTP server on http://${host}:${port}/mcp (engine=${instance.policy.engine.type}, policy=${instance.policy.mode}, templates=${instance.policy.templates.length}, auth=${oauthEnvSet ? "oauth-jwt" : "api-keys"})\n`
  );
  await instance.server.listen(port, { host });
}

main().catch((err) => {
  process.stderr.write(`[mcp-secure-db] Fatal error: ${err.message}\n`);
  process.exit(1);
});
