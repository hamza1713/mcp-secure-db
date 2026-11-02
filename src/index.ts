import { MCPServer } from "mcp-use";
import { z } from "zod";
import { rbacManager } from "./security/rbac.js";
import { dbEngine } from "./database/engine.js";
import { sqlValidator } from "./security/validator.js";
import { auditLogger } from "./database/audit.js";
import { TABLE_METADATA } from "./database/seed.js";

const server = new MCPServer({
  name: "mcp-secure-db",
  version: "1.0.0",
  description:
    "Reference MCP server demonstrating layered SQL validation and in-process SQLite execution",
});

/**
 * Helper to resolve security context from request context or explicit token parameter
 */
export function resolveAuthContext(explicitToken?: string | null, ctx?: any) {
  let token = explicitToken;
  if (!token && ctx?.request) {
    const authHeader =
      ctx.request.header?.("authorization") ||
      ctx.request.header?.("x-api-key") ||
      ctx.request.headers?.get?.("authorization");
    if (authHeader) token = authHeader;
  }
  return rbacManager.resolveContext(token);
}

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
            scopes: secCtx.scopes,
            allowedTools: secCtx.allowedTools,
            notice:
              "Role determines dynamic tool visibility and column-level PII masking.",
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

  // Hard RBAC enforcement
  if (!rbacManager.canAccessTool(secCtx.role, "execute_analytical_sql")) {
    auditLogger.log({
      principal: secCtx.principal,
      role: secCtx.role,
      query,
      status: "BLOCKED_RBAC",
      reason: `Role '${secCtx.role}' lacks permission for 'execute_analytical_sql'.`,
    });
    return {
      isError: true,
      content: [
        {
          type: "text" as const,
          text: `RBACPermissionDenied: Role '${secCtx.role}' is not authorized to execute analytical queries. Minimum role required: 'analyst'.`,
        },
      ],
    };
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
    auditLogger.log({
      principal: secCtx.principal,
      role: secCtx.role,
      query: "CALL get_security_audit_log",
      status: "BLOCKED_RBAC",
      reason: `Role '${secCtx.role}' is not authorized to inspect security audit logs.`,
    });
    return {
      isError: true,
      content: [
        {
          type: "text" as const,
          text: `RBACPermissionDenied: Role '${secCtx.role}' is not authorized to view security audit telemetry. Minimum role required: 'admin'.`,
        },
      ],
    };
  }

  const entries = auditLogger.getEntries(limit);
  const stats = auditLogger.getStats();

  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
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
      "List accessible analytical database tables with row counts and visible column names.",
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
      "Inspect schema details, column types, descriptions, and PII protection flags for a specific table.",
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
      "Dry-run deterministic AST validation of an analytical SQL query without executing it.",
    inputSchema: z.object({
      query: z
        .string()
        .describe("SQL query to validate against the 4-layer security policy"),
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
      "Execute bounded, non-mutating analytical SQL queries in the in-process SQLite sandbox. (Requires 'analyst' or 'admin' role).",
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
      "Inspect execution telemetry, security blocks, AST violations, and sandbox statistics. (Requires 'admin' role).",
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
      "JSON catalog of all warehouse tables and column security definitions",
  },
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        mimeType: "application/json",
        text: JSON.stringify(TABLE_METADATA, null, 2),
      },
    ],
  })
);

server.resource(
  {
    name: "security-rules",
    uri: "policy://security-rules",
    description:
      "Deterministic 4-Layer Defense-in-Depth Security Specification",
  },
  async (uri) => ({
    contents: [
      {
        uri: uri.href,
        mimeType: "text/markdown",
        text: `# mcp-secure-db Security Policy Specification

1. **Layer 1: Role-Based Authorization** - Token resolution and tool-level access checks.
2. **Layer 2: Local JavaScript AST Validator** - Rejects SQL comments, chained statements, non-SELECT statements, basic Cartesian joins, and direct references to sensitive columns without calling an LLM.
3. **Layer 3: In-Process WebAssembly SQLite Sandbox** - Seeded in-memory SQLite instance with no external network or filesystem handles.
4. **Layer 4: In-Memory Recent-Events Buffer** - Non-durable ring buffer recording recent query executions and blocks.`,
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
          text: `You are a Principal Data Analyst with access to mcp-secure-db.
Analyze current platform metrics with focus on '${focus}'.
1. Inspect available tables using list_tables.
2. Use verify_query_safety before running analytical aggregations.
3. Formulate bounded analytical queries joining customers and api_usage.
4. Summarize top enterprise accounts and compute consumption trends.`,
        },
      },
    ],
  })
);

server.prompt(
  {
    name: "red_team_security_audit",
    description:
      "Adversarial penetration testing harness to verify defense-in-depth boundaries",
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
          text: `You are a Red Team Security Researcher testing mcp-secure-db defenses against: ${target_attack}.
Attempt to verify that the 4-layer defense deterministically blocks the attack vector:
- If mutation_injection: test DROP TABLE or UPDATE.
- If comment_smuggling: test payloads with '--' or '/*'.
- If cartesian_join: test unconstrained CROSS JOIN or 'ON 1=1'.
- If pii_exfiltration: test SELECT billing_email or SELECT * under public_viewer role.
Verify that 0 tokens are spent on LLM guards and that violations are recorded in the security audit log.`,
        },
      },
    ],
  })
);

export default server;
