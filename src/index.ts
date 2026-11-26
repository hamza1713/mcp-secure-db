import "dotenv/config";
import crypto from "node:crypto";
import { MCPServer } from "mcp-use";
import { z } from "zod";
import {
  AuthenticatedRole,
  isArgTokenEnabled,
  RBACManager,
  ROLE_TOOLS,
} from "./security/rbac.js";
import { createQueryEngine, QueryEngine } from "./database/query-engine.js";
import { AuditLogger, auditLogger } from "./database/audit.js";
import {
  defaultRateLimiter,
  RateLimiter,
  validationRateLimiter,
} from "./security/rate-limiter.js";
import { ResolvedPolicy } from "./policy/loader.js";
import {
  bindTemplateParameters,
  buildTemplateZodSchema,
  compileAndValidateTemplate,
  CompiledTemplate,
  compileTemplateSql,
  TenantContextRequiredError,
} from "./security/template-engine.js";
import { metricsRegistry, MetricsRegistry } from "./observability/metrics.js";
import {
  generateRequestId,
  structuredLogger,
  StructuredLogger,
} from "./observability/logger.js";
import { SecurityContext, UserRole } from "./types.js";

export interface CreateSecureMcpServerOptions {
  policy?: ResolvedPolicy;
  policyPath?: string;
  engine?: QueryEngine;
  /**
   * Trusted local stdio role bound ONLY by `src/cli.ts --transport stdio --stdio-role <role>`.
   * Never read from HTTP headers or request arguments.
   */
  stdioRole?: AuthenticatedRole;
  /**
   * Trusted local stdio tenant bound ONLY by `src/cli.ts --transport stdio --stdio-tenant <id>`.
   */
  stdioTenantId?: string;
  rateLimiter?: RateLimiter;
  validationLimiter?: RateLimiter;
  metrics?: MetricsRegistry;
  logger?: StructuredLogger;
  audit?: AuditLogger;
}

export interface SecureMcpServerInstance {
  server: MCPServer;
  engine: QueryEngine;
  policy: ResolvedPolicy;
  rbac: RBACManager;
  metrics: MetricsRegistry;
  audit: AuditLogger;
  validateTemplates: () => Promise<CompiledTemplate[]>;
  resolveAuthContext: (explicitToken?: string | null, ctx?: any) => SecurityContext;
  handleWhoami: (args: { token?: string }, ctx?: any) => Promise<any>;
  handleListTables: (args: { token?: string }, ctx?: any) => Promise<any>;
  handleDescribeTable: (
    args: { table_name: string; token?: string },
    ctx?: any
  ) => Promise<any>;
  handleVerifyQuerySafety: (
    args: { query: string; token?: string },
    ctx?: any
  ) => Promise<any>;
  handleExecuteAnalyticalSql: (
    args: { query: string; token?: string },
    ctx?: any
  ) => Promise<any>;
  handleGetSecurityAuditLog: (
    args: { limit?: number; token?: string },
    ctx?: any
  ) => Promise<any>;
  handleReadCatalogResource: (uri: URL, ctx?: any) => Promise<any>;
  handleReadSecurityRulesResource: (uri: URL, ctx?: any) => Promise<any>;
}

function buildRoleToolsForPolicy(policy: ResolvedPolicy): Record<UserRole, string[]> {
  const map: Record<UserRole, string[]> = {
    unauthenticated: ["whoami"],
    public_viewer: ["whoami", "list_tables", "describe_table"],
    analyst: ["whoami", "list_tables", "describe_table"],
    admin: ["whoami", "list_tables", "describe_table", "get_security_audit_log"],
  };

  if (policy.adhocSql.enabled) {
    map.public_viewer.push("verify_query_safety");
    map.analyst.push("verify_query_safety");
    map.admin.push("verify_query_safety");

    for (const r of policy.adhocSql.allowedRoles) {
      if (!map[r].includes("execute_analytical_sql")) {
        map[r].push("execute_analytical_sql");
      }
    }
  }

  for (const tmpl of policy.templates) {
    for (const role of tmpl.allowed_roles) {
      if (!map[role].includes(tmpl.name)) {
        map[role].push(tmpl.name);
      }
    }
  }

  return map;
}

export function createSecureMcpServer(
  options: CreateSecureMcpServerOptions = {}
): SecureMcpServerInstance {
  const activeMetrics = options.metrics ?? metricsRegistry;
  const activeLogger = options.logger ?? structuredLogger;
  const activeAudit = options.audit ?? auditLogger;

  const engine: QueryEngine =
    options.engine ??
    createQueryEngine({
      policy: options.policy,
      policyPath: options.policyPath,
      metrics: activeMetrics,
      audit: activeAudit,
    });
  const policy = engine.getActivePolicy();
  const roleTools =
    policy.mode === "default_demo" && policy.templates.length === 0
      ? ROLE_TOOLS
      : buildRoleToolsForPolicy(policy);
  const rbac = new RBACManager({ roleTools });

  const queryRateLimiter =
    options.rateLimiter ??
    (policy.mode === "file"
      ? new RateLimiter(policy.rateLimits)
      : defaultRateLimiter);
  const dryRunRateLimiter = options.validationLimiter ?? validationRateLimiter;

  const server = new MCPServer({
    name: "mcp-secure-db",
    version: "1.0.0",
    description:
      "Zero-trust SQL MCP gateway with declarative policy, live introspection, layered AST validation, parameterized templates, and isolated database execution",
  });

  // Pre-compile template SQL placeholders & Zod schemas synchronously so undeclared
  // placeholders fail immediately; full AST validation runs once introspection is ready.
  const templateDialect =
    policy.engine.type === "postgres" ? "postgresql" : "sqlite";
  const precompiledTemplates = new Map<
    string,
    {
      definition: (typeof policy.templates)[number];
      parameterizedSql: string;
      paramOrder: string[];
      inputSchema: z.ZodObject<Record<string, z.ZodTypeAny>>;
    }
  >();

  for (const tmpl of policy.templates) {
    const { parameterizedSql, paramOrder } = compileTemplateSql(
      tmpl.sql,
      templateDialect,
      tmpl.parameters
    );
    const inputSchema = buildTemplateZodSchema(tmpl.parameters);
    precompiledTemplates.set(tmpl.name, {
      definition: tmpl,
      parameterizedSql,
      paramOrder,
      inputSchema,
    });
  }

  let validatedTemplatesMap: Map<string, CompiledTemplate> | null = null;
  let templateValidationPromise: Promise<Map<string, CompiledTemplate>> | null =
    null;

  async function ensureTemplatesValidated(): Promise<
    Map<string, CompiledTemplate>
  > {
    if (validatedTemplatesMap) return validatedTemplatesMap;
    if (templateValidationPromise) return templateValidationPromise;

    templateValidationPromise = (async () => {
      await engine.init();
      const compiled = new Map<string, CompiledTemplate>();
      for (const tmpl of policy.templates) {
        const result = compileAndValidateTemplate(
          tmpl,
          templateDialect,
          (sql, role) => engine.validate(sql, role)
        );
        compiled.set(tmpl.name, result);
      }
      validatedTemplatesMap = compiled;
      return compiled;
    })();

    try {
      return await templateValidationPromise;
    } catch (err) {
      templateValidationPromise = null;
      throw err;
    }
  }

  async function validateTemplates(): Promise<CompiledTemplate[]> {
    const map = await ensureTemplatesValidated();
    return [...map.values()];
  }

  function resolveAuthContext(
    explicitToken?: string | null,
    ctx?: any
  ): SecurityContext {
    let token = isArgTokenEnabled() ? explicitToken : undefined;
    const req = ctx?.request ?? ctx?.req;
    if (!token && req) {
      const authHeader =
        req.header?.("authorization") ||
        req.header?.("x-api-key") ||
        req.raw?.headers?.get?.("authorization") ||
        req.raw?.headers?.get?.("x-api-key") ||
        req.headers?.get?.("authorization") ||
        req.headers?.get?.("x-api-key");
      if (authHeader) token = authHeader;
    }

    const oauth = ctx?.auth
      ? {
          clientId: ctx.auth.clientId,
          scopes: ctx.auth.scopes,
          permissions: ctx.auth.permissions,
          user: ctx.auth.user,
          payload: ctx.auth.payload ?? ctx.auth.extra,
        }
      : null;

    if (!oauth && (!token || !token.trim()) && options.stdioRole) {
      return rbac.resolveStdioRole(options.stdioRole, options.stdioTenantId);
    }

    return rbac.resolveContext(token, { oauth });
  }

  function denyToolCall(
    secCtx: SecurityContext,
    toolName: string,
    requiredRoleLabel: string,
    recordedInput: string,
    requestId?: string
  ) {
    const isUnauth = secCtx.role === "unauthenticated";
    const status = isUnauth ? "BLOCKED_AUTH" : "BLOCKED_RBAC";
    const reason = isUnauth
      ? secCtx.denialReason ||
        `Unauthenticated access to '${toolName}' denied by default-deny policy.`
      : `Role '${secCtx.role}' lacks permission for '${toolName}'.`;
    activeAudit.log({
      requestId,
      principal: secCtx.principal,
      role: secCtx.role,
      tenantId: secCtx.tenantId,
      tool: toolName,
      query: recordedInput,
      status,
      reason,
    });
    activeMetrics.incRequest("tools/call", toolName, secCtx.role, status);
    activeMetrics.incBlock("rbac", secCtx.role, status);
    activeLogger.warn({
      event: "tool_denied",
      requestId,
      role: secCtx.role,
      tenantId: secCtx.tenantId,
      tool: toolName,
      status,
      detail: reason,
    });

    const prefix = isUnauth ? "AuthenticationRequired" : "RBACPermissionDenied";
    return {
      isError: true,
      content: [
        {
          type: "text" as const,
          text: `${prefix}: Role '${secCtx.role}' is not authorized to invoke '${toolName}'. Minimum role required: '${requiredRoleLabel}'.`,
        },
      ],
    };
  }

  // ==========================================
  // OPERATIONAL HTTP PROBES (/healthz, /readyz, /metrics)
  // ==========================================
  server.get("/healthz", (c) =>
    c.json(
      {
        status: "ok",
        service: "mcp-secure-db",
        version: "1.0.0",
        engine: policy.engine.type,
        policyMode: policy.mode,
        adhocSqlEnabled: policy.adhocSql.enabled,
        templateCount: policy.templates.length,
        tenantIsolationEnabled: policy.tenantIsolation.enabled,
      },
      200
    )
  );

  server.get("/readyz", async (c) => {
    const ready = await engine.healthCheck();
    const poolStats = engine.getPoolStats?.();
    return c.json(
      {
        status: ready ? "ready" : "not_ready",
        service: "mcp-secure-db",
        engine: policy.engine.type,
        ...(poolStats ? { pool: poolStats } : {}),
      },
      ready ? 200 : 503
    );
  });

  server.get("/metrics", (c) => {
    const metricsPublic =
      process.env.MCP_SECURE_DB_METRICS_PUBLIC?.trim() === "true";

    if (!metricsPublic) {
      const authHeader =
        c.req.header("authorization") || c.req.header("x-api-key") || "";
      const cleanToken = authHeader.toLowerCase().startsWith("bearer ")
        ? authHeader.slice(7).trim()
        : authHeader.trim();

      const configuredMetricsToken =
        process.env.MCP_SECURE_DB_METRICS_TOKEN?.trim();
      let authorizedByMetricsToken = false;
      if (configuredMetricsToken && cleanToken) {
        const expectedBuf = crypto
          .createHash("sha256")
          .update(configuredMetricsToken, "utf8")
          .digest();
        const candidateBuf = crypto
          .createHash("sha256")
          .update(cleanToken, "utf8")
          .digest();
        authorizedByMetricsToken = crypto.timingSafeEqual(
          expectedBuf,
          candidateBuf
        );
      }

      if (!authorizedByMetricsToken) {
        const secCtx = resolveAuthContext(authHeader || undefined, {
          request: c.req,
        });
        if (secCtx.role === "unauthenticated") {
          return c.json(
            {
              error:
                "AuthenticationRequired: /metrics requires admin credentials or MCP_SECURE_DB_METRICS_TOKEN.",
            },
            401
          );
        }
        if (secCtx.role !== "admin") {
          return c.json(
            {
              error:
                "RBACPermissionDenied: /metrics requires 'admin' role or MCP_SECURE_DB_METRICS_TOKEN.",
            },
            403
          );
        }
      }
    }

    activeMetrics.setAuditChainSeq(activeAudit.getChainState().seq);
    activeMetrics.setSqlitePoolStats(engine.getPoolStats?.() ?? null);
    return c.text(activeMetrics.renderPrometheus(), 200, {
      "content-type": "text/plain; version=0.0.4; charset=utf-8",
      "cache-control": "no-store",
    });
  });

  // ==========================================
  // MCP PROTOCOL MIDDLEWARE (Layer 1 — All 6 Methods)
  // ==========================================
  server.use("mcp:tools/list", async (ctx, next) => {
    const secCtx = resolveAuthContext(undefined, ctx);
    const allTools = await next();
    return rbac.filterTools(secCtx.role, allTools);
  });

  server.use("mcp:tools/call", async (ctx, next) => {
    const toolName = ctx.params.name;
    const argToken =
      typeof ctx.params.arguments?.token === "string"
        ? ctx.params.arguments.token
        : undefined;
    const secCtx = resolveAuthContext(argToken, ctx);

    if (!rbac.canAccessTool(secCtx.role, toolName)) {
      const tmpl = precompiledTemplates.get(toolName);
      const minRole = tmpl
        ? tmpl.definition.allowed_roles.join("|")
        : toolName === "get_security_audit_log"
          ? "admin"
          : toolName === "execute_analytical_sql"
            ? policy.adhocSql.enabled
              ? policy.adhocSql.allowedRoles.join("|")
              : "disabled_by_policy"
            : "public_viewer";
      return denyToolCall(secCtx, toolName, minRole, `CALL ${toolName}`);
    }

    return next();
  });

  server.use("mcp:resources/list", async (ctx, next) => {
    const secCtx = resolveAuthContext(undefined, ctx);
    const allResources = await next();
    return rbac.filterResources(secCtx.role, allResources);
  });

  server.use("mcp:resources/read", async (ctx, next) => {
    const secCtx = resolveAuthContext(undefined, ctx);
    const uri = ctx.params.uri;
    if (!rbac.canAccessResource(secCtx.role, uri)) {
      const isUnauth = secCtx.role === "unauthenticated";
      auditLogger.log({
        principal: secCtx.principal,
        role: secCtx.role,
        tool: `resource:${uri}`,
        query: `READ ${uri}`,
        status: isUnauth ? "BLOCKED_AUTH" : "BLOCKED_RBAC",
        reason: isUnauth
          ? secCtx.denialReason ||
            `Unauthenticated read of '${uri}' denied by default-deny policy.`
          : `Role '${secCtx.role}' lacks permission to read '${uri}'.`,
      });
      const prefix = isUnauth ? "AuthenticationRequired" : "RBACPermissionDenied";
      throw new Error(
        `${prefix}: Role '${secCtx.role}' is not authorized to read resource '${uri}'.`
      );
    }
    return next();
  });

  server.use("mcp:prompts/list", async (ctx, next) => {
    const secCtx = resolveAuthContext(undefined, ctx);
    const allPrompts = await next();
    return rbac.filterPrompts(secCtx.role, allPrompts);
  });

  server.use("mcp:prompts/get", async (ctx, next) => {
    const secCtx = resolveAuthContext(undefined, ctx);
    const promptName = ctx.params.name;
    if (!rbac.canAccessPrompt(secCtx.role, promptName)) {
      const isUnauth = secCtx.role === "unauthenticated";
      auditLogger.log({
        principal: secCtx.principal,
        role: secCtx.role,
        tool: `prompt:${promptName}`,
        query: `GET_PROMPT ${promptName}`,
        status: isUnauth ? "BLOCKED_AUTH" : "BLOCKED_RBAC",
        reason: isUnauth
          ? secCtx.denialReason ||
            `Unauthenticated access to prompt '${promptName}' denied by default-deny policy.`
          : `Role '${secCtx.role}' lacks permission for prompt '${promptName}'.`,
      });
      const prefix = isUnauth ? "AuthenticationRequired" : "RBACPermissionDenied";
      throw new Error(
        `${prefix}: Role '${secCtx.role}' is not authorized to access prompt '${promptName}'.`
      );
    }
    return next();
  });

  // ==========================================
  // BUILT-IN TOOL HANDLERS
  // ==========================================
  async function handleWhoami({ token }: { token?: string }, ctx?: any) {
    const requestId = generateRequestId();
    const secCtx = resolveAuthContext(token, ctx);
    activeMetrics.incRequest("tools/call", "whoami", secCtx.role, "SUCCESS");
    activeLogger.info({
      event: "tool_completed",
      requestId,
      role: secCtx.role,
      tenantId: secCtx.tenantId,
      tool: "whoami",
      status: "SUCCESS",
    });
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              requestId,
              principal: secCtx.principal,
              role: secCtx.role,
              tenantId: secCtx.tenantId ?? null,
              authenticated: secCtx.authenticated,
              authSource: secCtx.authSource,
              scopes: secCtx.scopes,
              allowedTools: secCtx.allowedTools,
              policyMode: policy.mode,
              adhocSqlEnabled: policy.adhocSql.enabled,
              tenantIsolationEnabled: policy.tenantIsolation.enabled,
              notice:
                secCtx.role === "unauthenticated"
                  ? "Default-deny active: supply valid OAuth or Bearer credentials to access database metadata or query tools."
                  : "Role determines dynamic tool visibility, table allowlists, and PII enforcement.",
            },
            null,
            2
          ),
        },
      ],
    };
  }

  async function handleListTables({ token }: { token?: string }, ctx?: any) {
    const secCtx = resolveAuthContext(token, ctx);
    if (!rbac.canAccessTool(secCtx.role, "list_tables")) {
      return denyToolCall(
        secCtx,
        "list_tables",
        "public_viewer",
        "CALL list_tables"
      );
    }

    if (policy.mode === "file") {
      await engine.init();
    }

    const tables = engine.getTables(secCtx.role);
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              role: secCtx.role,
              tableCount: tables.length,
              tables,
            },
            null,
            2
          ),
        },
      ],
    };
  }

  async function handleDescribeTable(
    { table_name, token }: { table_name: string; token?: string },
    ctx?: any
  ) {
    const secCtx = resolveAuthContext(token, ctx);
    if (!rbac.canAccessTool(secCtx.role, "describe_table")) {
      return denyToolCall(
        secCtx,
        "describe_table",
        "public_viewer",
        `CALL describe_table(${table_name})`
      );
    }

    if (policy.mode === "file") {
      await engine.init();
    }

    const schema = engine.getTableSchema(table_name, secCtx.role);
    if (!schema) {
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text: `Table '${table_name}' was not found or access is denied for role '${secCtx.role}'.`,
          },
        ],
      };
    }
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(schema, null, 2),
        },
      ],
    };
  }

  async function handleVerifyQuerySafety(
    { query, token }: { query: string; token?: string },
    ctx?: any
  ) {
    const requestId = generateRequestId();
    const secCtx = resolveAuthContext(token, ctx);
    if (!rbac.canAccessTool(secCtx.role, "verify_query_safety")) {
      return denyToolCall(
        secCtx,
        "verify_query_safety",
        policy.adhocSql.enabled ? "public_viewer" : "disabled_by_policy",
        query,
        requestId
      );
    }

    const rateCheck = dryRunRateLimiter.consumeQuerySlot(
      secCtx.principal,
      secCtx.role
    );
    if (!rateCheck.allowed) {
      activeAudit.log({
        requestId,
        principal: secCtx.principal,
        role: secCtx.role,
        tenantId: secCtx.tenantId,
        tool: "verify_query_safety",
        query,
        status: "BLOCKED_RATE_LIMIT",
        reason: rateCheck.reason,
      });
      activeMetrics.incRequest(
        "tools/call",
        "verify_query_safety",
        secCtx.role,
        "BLOCKED_RATE_LIMIT"
      );
      activeMetrics.incBlock("rate_limit", secCtx.role, "BLOCKED_RATE_LIMIT");
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text: `RateLimitExceeded: ${rateCheck.reason}`,
          },
        ],
      };
    }

    if (policy.mode === "file") {
      await engine.init();
    }

    const valStart = performance.now();
    const validation = engine.validate(query, secCtx.role);
    activeMetrics.observeValidationDurationMs(performance.now() - valStart);
    activeMetrics.incRequest(
      "tools/call",
      "verify_query_safety",
      secCtx.role,
      validation.valid ? "SUCCESS" : "BLOCKED_AST"
    );
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              requestId,
              role: secCtx.role,
              valid: validation.valid,
              sanitizedQuery: validation.sanitizedQuery,
              tablesAccessed: validation.tablesAccessed,
              columnsAccessed: validation.columnsAccessed,
              functionsUsed: validation.functionsUsed ?? [],
              limitApplied: validation.limitInjected,
              violationReason: validation.violationReason ?? null,
              cost:
                policy.engine.type === "postgres"
                  ? "0 Tokens (Local PostgreSQL WASM AST Validation)"
                  : "0 Tokens (Local JavaScript AST Validation)",
            },
            null,
            2
          ),
        },
      ],
    };
  }

  async function handleExecuteAnalyticalSql(
    { query, token }: { query: string; token?: string },
    ctx?: any
  ) {
    const requestId = generateRequestId();
    const callStart = performance.now();
    const secCtx = resolveAuthContext(token, ctx);

    if (!rbac.canAccessTool(secCtx.role, "execute_analytical_sql")) {
      return denyToolCall(
        secCtx,
        "execute_analytical_sql",
        policy.adhocSql.enabled ? "analyst" : "disabled_by_policy",
        query,
        requestId
      );
    }

    const rateCheck = queryRateLimiter.consumeQuerySlot(
      secCtx.principal,
      secCtx.role
    );
    if (!rateCheck.allowed) {
      activeAudit.log({
        requestId,
        principal: secCtx.principal,
        role: secCtx.role,
        tenantId: secCtx.tenantId,
        tool: "execute_analytical_sql",
        query,
        status: "BLOCKED_RATE_LIMIT",
        reason: rateCheck.reason,
      });
      activeMetrics.incRequest(
        "tools/call",
        "execute_analytical_sql",
        secCtx.role,
        "BLOCKED_RATE_LIMIT"
      );
      activeMetrics.incBlock("rate_limit", secCtx.role, "BLOCKED_RATE_LIMIT");
      activeLogger.warn({
        event: "rate_limit_blocked",
        requestId,
        role: secCtx.role,
        tenantId: secCtx.tenantId,
        tool: "execute_analytical_sql",
        status: "BLOCKED_RATE_LIMIT",
        detail: rateCheck.reason,
      });
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text: `RateLimitExceeded: ${rateCheck.reason}`,
          },
        ],
      };
    }

    try {
      const result = await engine.executeQuery(
        query,
        secCtx.role,
        secCtx.principal,
        { requestId, tenantId: secCtx.tenantId }
      );

      queryRateLimiter.recordRows(secCtx.principal, result.rowCount);
      activeMetrics.incRequest(
        "tools/call",
        "execute_analytical_sql",
        secCtx.role,
        "SUCCESS"
      );
      activeLogger.info({
        event: "query_executed",
        requestId,
        role: secCtx.role,
        tenantId: secCtx.tenantId,
        tool: "execute_analytical_sql",
        status: "SUCCESS",
        durationMs: Math.round((performance.now() - callStart) * 100) / 100,
        rowCount: result.rowCount,
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ requestId, ...result }, null, 2),
          },
        ],
      };
    } catch (err: any) {
      activeMetrics.incRequest(
        "tools/call",
        "execute_analytical_sql",
        secCtx.role,
        "ERROR"
      );
      activeLogger.warn({
        event: "query_failed",
        requestId,
        role: secCtx.role,
        tenantId: secCtx.tenantId,
        tool: "execute_analytical_sql",
        status: "ERROR",
        durationMs: Math.round((performance.now() - callStart) * 100) / 100,
        detail: err.message,
      });
      return {
        isError: true,
        content: [
          {
            type: "text" as const,
            text: `QueryExecutionFailed: ${err.message}`,
          },
        ],
      };
    }
  }

  async function handleGetSecurityAuditLog(
    { limit = 20, token }: { limit?: number; token?: string },
    ctx?: any
  ) {
    const requestId = generateRequestId();
    const secCtx = resolveAuthContext(token, ctx);

    if (!rbac.canAccessTool(secCtx.role, "get_security_audit_log")) {
      return denyToolCall(
        secCtx,
        "get_security_audit_log",
        "admin",
        "CALL get_security_audit_log",
        requestId
      );
    }

    const entries = activeAudit.getEntries(limit);
    const persistentEntries = activeAudit.getPersistentEntries(limit);
    const stats = activeAudit.getStats();
    const chainState = activeAudit.getChainState();
    activeMetrics.incRequest(
      "tools/call",
      "get_security_audit_log",
      secCtx.role,
      "SUCCESS"
    );

    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              requestId,
              durabilityNotice:
                "In-memory ring buffer (non-durable cache across restarts). Persistent tamper-evident hash-chained log written to data/audit.jsonl with sensitive literals redacted.",
              persistentLogPath: activeAudit.getLogFilePath(),
              chainState,
              stats,
              returnedEntries: entries.length,
              entries,
              persistentEntries,
            },
            null,
            2
          ),
        },
      ],
    };
  }

  async function handleReadCatalogResource(uri: URL, ctx?: any) {
    const secCtx = resolveAuthContext(undefined, ctx);
    if (!rbac.canReadCatalog(secCtx.role)) {
      auditLogger.log({
        principal: secCtx.principal,
        role: secCtx.role,
        tool: "resource:schema://catalog",
        query: "READ schema://catalog",
        status: "BLOCKED_AUTH",
        reason:
          secCtx.denialReason ||
          "Unauthenticated read of schema://catalog denied by default-deny policy.",
      });
      throw new Error(
        "AuthenticationRequired: valid credentials are required to read schema://catalog."
      );
    }

    if (policy.mode === "file") {
      await engine.init();
    }

    const filteredCatalog = engine.getFilteredCatalog(secCtx.role);
    return {
      contents: [
        {
          uri: uri.href,
          mimeType: "application/json",
          text: JSON.stringify(filteredCatalog, null, 2),
        },
      ],
    };
  }

  async function handleReadSecurityRulesResource(uri: URL, ctx?: any) {
    const secCtx = resolveAuthContext(undefined, ctx);
    if (!rbac.canAccessResource(secCtx.role, "policy://security-rules")) {
      auditLogger.log({
        principal: secCtx.principal,
        role: secCtx.role,
        tool: "resource:policy://security-rules",
        query: "READ policy://security-rules",
        status: "BLOCKED_AUTH",
        reason:
          secCtx.denialReason ||
          "Unauthenticated read of policy://security-rules denied by default-deny policy.",
      });
      throw new Error(
        "AuthenticationRequired: valid credentials are required to read policy://security-rules."
      );
    }

    return {
      contents: [
        {
          uri: uri.href,
          mimeType: "text/markdown",
          text: `# mcp-secure-db Security Policy Specification

1. **Layer 1: Default-Deny RBAC Middleware** - Rejects unauthenticated data, catalog, resource, and prompt access by default, filters tool/resource/prompt visibility, and enforces role authorization across all MCP methods.
2. **Layer 2: Dialect AST Validator** - PostgreSQL runs official PostgreSQL C parser/lexer via \`libpg-query\` WASM; SQLite runs local AST validation with explicit function/table/schema allowlists, cross-relation join checks, and row/offset caps without calling an LLM.
3. **Layer 3: Isolated Database Sandbox** - SQLite runs read-only inside \`node:worker_threads\` with V8 heap limits, hard timeout termination, defensive mode, disabled extension loading, \`query_only\` pragma, and compile-time \`setAuthorizer\`; PostgreSQL runs per-role \`BEGIN READ ONLY\` transactions with \`SET LOCAL ROLE\`, \`statement_timeout\`, and hardened \`search_path\`.
4. **Layer 4: Fail-Closed Result Policy, Rate Limits & Audit Log** - Scans returned columns and values for restricted PII/secret patterns before returning rows, atomically enforces per-principal query and row budgets, and writes redacted events to an append-only rotating JSONL log.`,
        },
      ],
    };
  }

  // ==========================================
  // BUILT-IN TOOL REGISTRATIONS
  // ==========================================
  server.tool(
    {
      name: "whoami",
      description:
        "Inspect active authentication principal, assigned role, granted scopes, and accessible tools.",
      inputSchema: z.object({
        token: z
          .string()
          .optional()
          .describe(
            "Optional Bearer or API token for local testing (disabled in NODE_ENV=production; prefer HTTP Authorization header or OAuth)"
          ),
      }),
    },
    handleWhoami
  );

  server.tool(
    {
      name: "list_tables",
      description:
        "List accessible analytical database tables with row counts and visible column names. (Requires authenticated role).",
      inputSchema: z.object({
        token: z
          .string()
          .optional()
          .describe(
            "Optional authentication token for local testing (disabled in NODE_ENV=production)"
          ),
      }),
    },
    handleListTables
  );

  server.tool(
    {
      name: "describe_table",
      description:
        "Inspect schema details, column types, and descriptions for an authorized table; PII columns are omitted for non-admins. (Requires authenticated role).",
      inputSchema: z.object({
        table_name: z.string().describe("Target table name to inspect"),
        token: z
          .string()
          .optional()
          .describe(
            "Optional authentication token for local testing (disabled in NODE_ENV=production)"
          ),
      }),
    },
    handleDescribeTable
  );

  server.tool(
    {
      name: "verify_query_safety",
      description:
        "Dry-run local AST validation of an analytical SQL query using the active engine dialect without executing it. (Requires authenticated role; hidden when adhoc_sql is disabled).",
      inputSchema: z.object({
        query: z
          .string()
          .describe("SQL query to validate against allowlist and role policy"),
        token: z
          .string()
          .optional()
          .describe(
            "Optional authentication token for local testing (disabled in NODE_ENV=production)"
          ),
      }),
    },
    handleVerifyQuerySafety
  );

  server.tool(
    {
      name: "execute_analytical_sql",
      description:
        "Execute bounded, non-mutating analytical SQL queries in the isolated database sandbox. (Requires 'analyst' or 'admin' role; hidden when adhoc_sql is disabled).",
      inputSchema: z.object({
        query: z.string().describe("Analytical SELECT query to execute"),
        token: z
          .string()
          .optional()
          .describe(
            "Optional authentication token for local testing (disabled in NODE_ENV=production)"
          ),
      }),
    },
    handleExecuteAnalyticalSql
  );

  server.tool(
    {
      name: "get_security_audit_log",
      description:
        "Inspect recent audit telemetry, persistent redacted JSONL entries, and policy block statistics. (Requires 'admin' role).",
      inputSchema: z.object({
        limit: z
          .number()
          .int()
          .positive()
          .default(20)
          .optional()
          .describe("Maximum audit log entries to return"),
        token: z
          .string()
          .optional()
          .describe(
            "Optional authentication token for local testing (disabled in NODE_ENV=production)"
          ),
      }),
    },
    handleGetSecurityAuditLog
  );

  // ==========================================
  // DYNAMIC PARAMETERIZED SAFE TEMPLATE TOOLS
  // ==========================================
  for (const [tmplName, pre] of precompiledTemplates.entries()) {
    server.tool(
      {
        name: tmplName,
        description: `${pre.definition.description} [Parameterized Safe Template; allowed roles: ${pre.definition.allowed_roles.join(", ")}]`,
        inputSchema: pre.inputSchema,
      },
      async (rawArgs: Record<string, unknown>, ctx?: any) => {
        const requestId = generateRequestId();
        const callStart = performance.now();
        const argToken =
          typeof rawArgs.token === "string" ? rawArgs.token : undefined;
        const secCtx = resolveAuthContext(argToken, ctx);

        if (!rbac.canAccessTool(secCtx.role, tmplName)) {
          return denyToolCall(
            secCtx,
            tmplName,
            pre.definition.allowed_roles.join("|"),
            `CALL ${tmplName}`,
            requestId
          );
        }

        const rateCheck = queryRateLimiter.consumeQuerySlot(
          secCtx.principal,
          secCtx.role
        );
        if (!rateCheck.allowed) {
          activeAudit.log({
            requestId,
            principal: secCtx.principal,
            role: secCtx.role,
            tenantId: secCtx.tenantId,
            tool: tmplName,
            query: pre.parameterizedSql,
            status: "BLOCKED_RATE_LIMIT",
            reason: rateCheck.reason,
          });
          activeMetrics.incRequest(
            "tools/call",
            tmplName,
            secCtx.role,
            "BLOCKED_RATE_LIMIT"
          );
          activeMetrics.incBlock("rate_limit", secCtx.role, "BLOCKED_RATE_LIMIT");
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: `RateLimitExceeded: ${rateCheck.reason}`,
              },
            ],
          };
        }

        try {
          const validatedMap = await ensureTemplatesValidated();
          const compiled = validatedMap.get(tmplName);
          if (!compiled) {
            throw new Error(`Template '${tmplName}' failed startup validation.`);
          }
          const boundValues = bindTemplateParameters(rawArgs, compiled, secCtx);
          const result = await engine.executeParameterizedQuery(
            compiled.parameterizedSql,
            boundValues,
            secCtx.role,
            secCtx.principal,
            tmplName,
            compiled.limitApplied,
            { requestId, tenantId: secCtx.tenantId }
          );

          queryRateLimiter.recordRows(secCtx.principal, result.rowCount);
          activeMetrics.incRequest("tools/call", tmplName, secCtx.role, "SUCCESS");
          activeLogger.info({
            event: "template_executed",
            requestId,
            role: secCtx.role,
            tenantId: secCtx.tenantId,
            tool: tmplName,
            status: "SUCCESS",
            durationMs: Math.round((performance.now() - callStart) * 100) / 100,
            rowCount: result.rowCount,
          });

          return {
            content: [
              {
                type: "text" as const,
                text: JSON.stringify({ requestId, ...result }, null, 2),
              },
            ],
          };
        } catch (err: any) {
          if (err instanceof TenantContextRequiredError) {
            activeAudit.log({
              requestId,
              principal: secCtx.principal,
              role: secCtx.role,
              tool: tmplName,
              query: pre.parameterizedSql,
              status: "BLOCKED_AUTH",
              reason: err.message,
            });
            activeMetrics.incBlock(
              "tenant_isolation",
              secCtx.role,
              "BLOCKED_AUTH"
            );
          }
          activeMetrics.incRequest("tools/call", tmplName, secCtx.role, "ERROR");
          activeLogger.warn({
            event: "template_failed",
            requestId,
            role: secCtx.role,
            tenantId: secCtx.tenantId,
            tool: tmplName,
            status: "ERROR",
            durationMs: Math.round((performance.now() - callStart) * 100) / 100,
            detail: err.message,
          });
          return {
            isError: true,
            content: [
              {
                type: "text" as const,
                text: `TemplateExecutionFailed: ${err.message}`,
              },
            ],
          };
        }
      }
    );
  }

  // ==========================================
  // RESOURCES
  // ==========================================
  server.resource(
    {
      name: "catalog",
      uri: "schema://catalog",
      description:
        "Role-filtered JSON catalog of authorized warehouse tables and non-PII columns",
    },
    handleReadCatalogResource
  );

  server.resource(
    {
      name: "security-rules",
      uri: "policy://security-rules",
      description: "Layered SQL Validation and Isolated Execution Policy",
    },
    handleReadSecurityRulesResource
  );

  // ==========================================
  // PROMPTS
  // ==========================================
  server.prompt(
    {
      name: "executive_analytics",
      description:
        "Executive briefing template for SaaS revenue and API compute metrics",
      schema: z.object({
        focus: z.enum(["compute", "growth", "security"]).default("compute"),
      }),
    },
    async ({ focus }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `You are a Data Analyst with authenticated access to mcp-secure-db.
Analyze current platform metrics with focus on '${focus}'.
1. Inspect available tables using list_tables.
2. Prefer declared parameterized template tools when available, or use verify_query_safety before running analytical aggregations.
3. Formulate bounded analytical queries joining authorized tables on explicit foreign keys.
4. Summarize key metrics and compute consumption trends.`,
          },
        },
      ],
    })
  );

  server.prompt(
    {
      name: "red_team_security_audit",
      description:
        "Adversarial testing prompt to verify layered query guardrails",
      schema: z.object({
        target_attack: z
          .enum([
            "comment_smuggling",
            "cartesian_join",
            "mutation_injection",
            "pii_exfiltration",
          ])
          .default("mutation_injection"),
      }),
    },
    async ({ target_attack }) => ({
      messages: [
        {
          role: "user",
          content: {
            type: "text",
            text: `You are a Security Researcher testing mcp-secure-db guardrails against: ${target_attack}.
Verify how the layered controls respond to the test vector:
- If mutation_injection: test DROP TABLE or UPDATE.
- If comment_smuggling: test payloads with '--' or '/*'.
- If cartesian_join: test unconstrained CROSS JOIN, implicit comma join, or 'ON 1=1'.
- If pii_exfiltration: test aliases, CTEs, subqueries, expressions, or SELECT * on sensitive tables under analyst role.
Verify that blocked attempts are recorded in the audit log.`,
          },
        },
      ],
    })
  );

  return {
    server,
    engine,
    policy,
    rbac,
    metrics: activeMetrics,
    audit: activeAudit,
    validateTemplates,
    resolveAuthContext,
    handleWhoami,
    handleListTables,
    handleDescribeTable,
    handleVerifyQuerySafety,
    handleExecuteAnalyticalSql,
    handleGetSecurityAuditLog,
    handleReadCatalogResource,
    handleReadSecurityRulesResource,
  };
}

// ==========================================
// DEFAULT MODULE SINGLETON (backward-compatible)
// ==========================================
const defaultInstance = createSecureMcpServer();

export const activeEngine: QueryEngine = defaultInstance.engine;
export const resolveAuthContext = defaultInstance.resolveAuthContext;
export const handleWhoami = defaultInstance.handleWhoami;
export const handleListTables = defaultInstance.handleListTables;
export const handleDescribeTable = defaultInstance.handleDescribeTable;
export const handleVerifyQuerySafety = defaultInstance.handleVerifyQuerySafety;
export const handleExecuteAnalyticalSql =
  defaultInstance.handleExecuteAnalyticalSql;
export const handleGetSecurityAuditLog =
  defaultInstance.handleGetSecurityAuditLog;
export const handleReadCatalogResource =
  defaultInstance.handleReadCatalogResource;
export const handleReadSecurityRulesResource =
  defaultInstance.handleReadSecurityRulesResource;

// ==========================================
// GRACEFUL SHUTDOWN
// ==========================================
let shutdownHookInstalled = false;
if (!shutdownHookInstalled && process.env.VITEST !== "true") {
  shutdownHookInstalled = true;
  const gracefulShutdown = () => {
    void activeEngine.close().finally(() => {
      process.exit(0);
    });
  };
  process.once("SIGINT", gracefulShutdown);
  process.once("SIGTERM", gracefulShutdown);
}

const defaultServer: MCPServer = defaultInstance.server;
export default defaultServer;
