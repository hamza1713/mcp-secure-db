import { MCPServer } from "mcp-use";
import { z } from "zod";
import { rbacManager } from "./security/rbac.js";
import { dbEngine } from "./database/engine.js";
import { sqlValidator } from "./security/validator.js";
import { auditLogger } from "./database/audit.js";
import { TABLE_METADATA } from "./database/seed.js";
import { SecurityContext, UserRole } from "./types.js";

const server = new MCPServer({
  name: "mcp-secure-db",
  version: "1.0.0",
  description:
    "Reference MCP server demonstrating layered SQL validation and worker-isolated SQLite execution",
});

/**
 * Resolves caller security context from:
 * 1. Verified `mcp-use` OAuth context (`ctx.auth`), when configured
 * 2. Explicit tool `token` argument or HTTP `Authorization` / `x-api-key` headers
 * 3. Default-deny (`unauthenticated`) unless `MCP_SECURE_DB_INSECURE_DEMO=true`
 */
export function resolveAuthContext(
  explicitToken?: string | null,
  ctx?: any
): SecurityContext {
  let token = explicitToken;
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

  // Also map @modelcontextprotocol/server AuthInfo on middleware ctx.auth if present
  const oauth = ctx?.auth
    ? {
        clientId: ctx.auth.clientId,
        scopes: ctx.auth.scopes,
        permissions: ctx.auth.permissions,
        user: ctx.auth.user,
        payload: ctx.auth.payload ?? ctx.auth.extra,
      }
    : null;

  return rbacManager.resolveContext(token, { oauth });
}

function buildFilteredCatalog(role: UserRole) {
  return Object.fromEntries(
    Object.entries(TABLE_METADATA)
      .filter(([, meta]) => role === "admin" || !meta.adminOnly)
      .map(([name, meta]) => [
        name,
        {
          name: meta.name,
          description: meta.description,
          rowCount: meta.rowCount,
          columns: meta.columns
            .filter((col) => role === "admin" || !col.isPII)
            .map((col) => ({
              name: col.name,
              type: col.type,
              isPII: col.isPII,
              description: col.description,
            })),
          redactedPiiColumnCount:
            role === "admin"
              ? 0
              : meta.columns.filter((col) => col.isPII).length,
        },
      ])
  );
}

function denyToolCall(
  secCtx: SecurityContext,
  toolName: string,
  requiredRoleLabel: string,
  recordedInput: string
) {
  const isUnauth = secCtx.role === "unauthenticated";
  auditLogger.log({
    principal: secCtx.principal,
    role: secCtx.role,
    tool: toolName,
    query: recordedInput,
    status: isUnauth ? "BLOCKED_AUTH" : "BLOCKED_RBAC",
    reason: isUnauth
      ? secCtx.denialReason ||
        `Unauthenticated access to '${toolName}' denied by default-deny policy.`
      : `Role '${secCtx.role}' lacks permission for '${toolName}'.`,
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
// MCP PROTOCOL MIDDLEWARE (Layer 1)
// ==========================================

server.use("mcp:tools/list", async (ctx, next) => {
  const secCtx = resolveAuthContext(undefined, ctx);
  const allTools = await next();
  return rbacManager.filterTools(secCtx.role, allTools);
});

server.use("mcp:tools/call", async (ctx, next) => {
  const toolName = ctx.params.name;
  const argToken =
    typeof ctx.params.arguments?.token === "string"
      ? ctx.params.arguments.token
      : undefined;
  const secCtx = resolveAuthContext(argToken, ctx);

  if (!rbacManager.canAccessTool(secCtx.role, toolName)) {
    const minRole =
      toolName === "get_security_audit_log"
        ? "admin"
        : toolName === "execute_analytical_sql"
          ? "analyst"
          : "public_viewer";
    return denyToolCall(secCtx, toolName, minRole, `CALL ${toolName}`);
  }

  return next();
});

// ==========================================
// TOOL HANDLERS
// ==========================================

export async function handleWhoami(
  { token }: { token?: string },
  ctx?: any
) {
  const secCtx = resolveAuthContext(token, ctx);
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            principal: secCtx.principal,
            role: secCtx.role,
            authenticated: secCtx.authenticated,
            authSource: secCtx.authSource,
            scopes: secCtx.scopes,
            allowedTools: secCtx.allowedTools,
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

export async function handleListTables(
  { token }: { token?: string },
  ctx?: any
) {
  const secCtx = resolveAuthContext(token, ctx);
  if (!rbacManager.canAccessTool(secCtx.role, "list_tables")) {
    return denyToolCall(secCtx, "list_tables", "public_viewer", "CALL list_tables");
  }

  const tables = dbEngine.getTables(secCtx.role);
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

export async function handleDescribeTable(
  { table_name, token }: { table_name: string; token?: string },
  ctx?: any
) {
  const secCtx = resolveAuthContext(token, ctx);
  if (!rbacManager.canAccessTool(secCtx.role, "describe_table")) {
    return denyToolCall(
      secCtx,
      "describe_table",
      "public_viewer",
      `CALL describe_table(${table_name})`
    );
  }

  const schema = dbEngine.getTableSchema(table_name, secCtx.role);
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

export async function handleVerifyQuerySafety(
  { query, token }: { query: string; token?: string },
  ctx?: any
) {
  const secCtx = resolveAuthContext(token, ctx);
  if (!rbacManager.canAccessTool(secCtx.role, "verify_query_safety")) {
    return denyToolCall(
      secCtx,
      "verify_query_safety",
      "public_viewer",
      query
    );
  }

  const validation = sqlValidator.validate(query, secCtx.role);
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            role: secCtx.role,
            valid: validation.valid,
            sanitizedQuery: validation.sanitizedQuery,
            tablesAccessed: validation.tablesAccessed,
            columnsAccessed: validation.columnsAccessed,
            functionsUsed: validation.functionsUsed ?? [],
            limitApplied: validation.limitInjected,
            violationReason: validation.violationReason ?? null,
            cost: "0 Tokens (Local JavaScript AST Validation)",
          },
          null,
          2
        ),
      },
    ],
  };
}

export async function handleExecuteAnalyticalSql(
  { query, token }: { query: string; token?: string },
  ctx?: any
) {
  const secCtx = resolveAuthContext(token, ctx);

  if (!rbacManager.canAccessTool(secCtx.role, "execute_analytical_sql")) {
    return denyToolCall(secCtx, "execute_analytical_sql", "analyst", query);
  }

  try {
    const result = await dbEngine.executeQuery(
      query,
      secCtx.role,
      secCtx.principal
    );
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (err: any) {
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

export async function handleGetSecurityAuditLog(
  { limit = 20, token }: { limit?: number; token?: string },
  ctx?: any
) {
  const secCtx = resolveAuthContext(token, ctx);

  if (!rbacManager.canAccessTool(secCtx.role, "get_security_audit_log")) {
    return denyToolCall(
      secCtx,
      "get_security_audit_log",
      "admin",
      "CALL get_security_audit_log"
    );
  }

  const entries = auditLogger.getEntries(limit);
  const stats = auditLogger.getStats();

  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            durabilityNotice:
              "In-memory recent-events buffer (not durable across restarts).",
            stats,
            returnedEntries: entries.length,
            entries,
          },
          null,
          2
        ),
      },
    ],
  };
}

export async function handleReadCatalogResource(uri: URL, ctx?: any) {
  const secCtx = resolveAuthContext(undefined, ctx);
  if (!rbacManager.canReadCatalog(secCtx.role)) {
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

  const filteredCatalog = buildFilteredCatalog(secCtx.role);
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

// ==========================================
// TOOL REGISTRATIONS
// ==========================================

export const whoami = server.tool(
  {
    name: "whoami",
    description:
      "Inspect active authentication principal, assigned role, granted scopes, and accessible tools.",
    inputSchema: z.object({
      token: z
        .string()
        .optional()
        .describe("Optional Bearer or API token for role resolution"),
    }),
  },
  handleWhoami
);

export const listTables = server.tool(
  {
    name: "list_tables",
    description:
      "List accessible analytical database tables with row counts and visible column names. (Requires authenticated role).",
    inputSchema: z.object({
      token: z
        .string()
        .optional()
        .describe("Optional authentication token for role checking"),
    }),
  },
  handleListTables
);

export const describeTable = server.tool(
  {
    name: "describe_table",
    description:
      "Inspect schema details, column types, descriptions, and PII protection flags for an authorized table. (Requires authenticated role).",
    inputSchema: z.object({
      table_name: z.string().describe("Target table name to inspect"),
      token: z.string().optional().describe("Optional authentication token"),
    }),
  },
  handleDescribeTable
);

export const verifyQuerySafety = server.tool(
  {
    name: "verify_query_safety",
    description:
      "Dry-run local JavaScript AST validation of an analytical SQL query without executing it. (Requires authenticated role).",
    inputSchema: z.object({
      query: z
        .string()
        .describe("SQL query to validate against allowlist and role policy"),
      token: z
        .string()
        .optional()
        .describe("Optional authentication token to evaluate role rules"),
    }),
  },
  handleVerifyQuerySafety
);

export const executeAnalyticalSql = server.tool(
  {
    name: "execute_analytical_sql",
    description:
      "Execute bounded, non-mutating analytical SQL queries in the worker-isolated SQLite sandbox. (Requires 'analyst' or 'admin' role).",
    inputSchema: z.object({
      query: z.string().describe("Analytical SELECT query to execute"),
      token: z.string().optional().describe("Optional authentication token"),
    }),
  },
  handleExecuteAnalyticalSql
);

export const getSecurityAuditLog = server.tool(
  {
    name: "get_security_audit_log",
    description:
      "Inspect in-memory recent-events audit telemetry and policy block statistics. (Requires 'admin' role).",
    inputSchema: z.object({
      limit: z
        .number()
        .int()
        .positive()
        .default(20)
        .optional()
        .describe("Maximum audit log entries to return"),
      token: z.string().optional().describe("Optional authentication token"),
    }),
  },
  handleGetSecurityAuditLog
);

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
    description: "Layered SQL Validation and Worker-Isolated SQLite Policy",
  },
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        mimeType: "text/markdown",
        text: `# mcp-secure-db Security Policy Specification

1. **Layer 1: Default-Deny RBAC Middleware** - Rejects unauthenticated data access by default, filters tool visibility on \`tools/list\`, and enforces role authorization on \`tools/call\` and \`schema://catalog\`.
2. **Layer 2: Local JavaScript AST Validator** - Enforces SELECT-only queries, explicit function and table allowlists, recursive CTE/subquery/compound traversal, join constraints, and row caps without calling an LLM.
3. **Layer 3: Worker-Isolated SQLite Sandbox (\`node:sqlite\`)** - Runs inside a dedicated \`node:worker_threads\` worker with V8 heap limits, hard timeout termination, defensive mode, disabled extension loading, \`query_only\` pragma, and a compile-time \`setAuthorizer\` callback.
4. **Layer 4: Fail-Closed Result Policy and Audit Buffer** - Scans returned columns and values for restricted PII patterns before returning rows, and logs decisions to an in-memory recent-events buffer.`,
      },
    ],
  })
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
2. Use verify_query_safety before running analytical aggregations.
3. Formulate bounded analytical queries joining customers and api_usage on explicit foreign keys.
4. Summarize account tiers and compute consumption trends.`,
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

export default server;
