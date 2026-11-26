import { z } from "zod";

export const BUILTIN_TOOL_NAMES = new Set([
  "whoami",
  "list_tables",
  "describe_table",
  "verify_query_safety",
  "execute_analytical_sql",
  "get_security_audit_log",
]);

export const DEFAULT_PII_AUTO_TAG_PATTERNS: readonly string[] = [
  "(?:^|_)(?:email|e_mail|ssn|social_security|password|passwd|pwd|secret|token|api_key|private_key|salary|compensation|dob|date_of_birth|credit_card|card_number|iban|client_ip|ip_address|stripe_customer_id)(?:$|_)",
];

const SAFE_IDENTIFIER_REGEX = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const SAFE_TOOL_NAME_REGEX = /^[a-z][a-z0-9_]{1,63}$/;
const NESTED_QUANTIFIER_REGEX = /\([^)]*[+*][^)]*\)[+*?]/;

const AuthenticatedRoleSchema = z.enum(["public_viewer", "analyst", "admin"]);

export const RateLimitPolicySchema = z
  .object({
    max_queries_per_minute: z.number().int().min(0).max(10000),
    max_rows_per_hour: z.number().int().min(0).max(10_000_000),
  })
  .strict();

export const RolePolicySchema = z
  .object({
    tables: z
      .array(z.string().regex(SAFE_IDENTIFIER_REGEX, "Invalid table identifier"))
      .default([]),
    views: z
      .array(z.string().regex(SAFE_IDENTIFIER_REGEX, "Invalid view identifier"))
      .default([]),
    pg_role: z
      .string()
      .regex(SAFE_IDENTIFIER_REGEX, "Invalid PostgreSQL role identifier")
      .optional(),
    allow_pii: z.boolean().optional(),
    rate_limit: RateLimitPolicySchema.optional(),
  })
  .strict();

export const TemplateParameterSchema = z
  .object({
    type: z.enum(["string", "integer", "number", "boolean"]),
    description: z.string().max(300).optional(),
    required: z.boolean().default(true),
    default: z.union([z.string(), z.number(), z.boolean()]).optional(),
    enum: z.array(z.string()).min(1).max(100).optional(),
    min: z.number().optional(),
    max: z.number().optional(),
    max_length: z.number().int().positive().max(4096).optional(),
  })
  .strict();

export const TemplateDefinitionSchema = z
  .object({
    name: z
      .string()
      .regex(
        SAFE_TOOL_NAME_REGEX,
        "Template tool name must be lowercase snake_case (2-64 chars)"
      )
      .refine(
        (name) => !BUILTIN_TOOL_NAMES.has(name),
        "Template name collides with a built-in MCP tool"
      ),
    description: z.string().min(4).max(500),
    allowed_roles: z.array(AuthenticatedRoleSchema).min(1),
    sql: z.string().min(6).max(4096),
    parameters: z
      .record(
        z
          .string()
          .regex(SAFE_IDENTIFIER_REGEX, "Invalid parameter name")
          .refine(
            (name) => name.toLowerCase() !== "ctx" && !name.toLowerCase().startsWith("ctx_"),
            "Parameter name cannot shadow reserved server context prefix 'ctx'"
          ),
        TemplateParameterSchema
      )
      .default({}),
  })
  .strict();

const SafeRegexStringSchema = z
  .string()
  .min(1)
  .max(256, "PII auto-tag regex pattern must be at most 256 characters")
  .refine(
    (pat) => !NESTED_QUANTIFIER_REGEX.test(pat),
    "PII auto-tag regex pattern cannot contain nested quantifiers"
  )
  .refine((pat) => {
    try {
      new RegExp(pat, "i");
      return true;
    } catch {
      return false;
    }
  }, "Invalid regular expression syntax in pii.auto_tag_patterns");

export const EnginePolicySchema = z
  .object({
    type: z.enum(["sqlite", "postgres"]).default("sqlite"),
    sqlite_path: z.string().min(1).optional(),
    connection_string_env: z
      .string()
      .regex(/^[A-Z_][A-Z0-9_]*$/, "Must be an uppercase environment variable name")
      .default("DATABASE_URL"),
    allowed_schemas: z
      .array(
        z
          .string()
          .regex(SAFE_IDENTIFIER_REGEX, "Invalid PostgreSQL schema identifier")
      )
      .min(1)
      .default(["public"]),
    statement_timeout_ms: z.number().int().min(100).max(60000).default(5000),
    max_connections: z.number().int().min(1).max(100).default(10),
    worker_pool_size: z.number().int().min(1).max(8).default(1),
    ssl: z
      .union([
        z.boolean(),
        z.object({ rejectUnauthorized: z.boolean().optional() }).strict(),
      ])
      .optional(),
  })
  .strict();

export const TenantIsolationPolicySchema = z
  .object({
    enabled: z.boolean().default(false),
    require_tenant_id: z.boolean().default(false),
    pg_tenant_setting: z
      .string()
      .regex(
        /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/,
        "Must be a PostgreSQL custom GUC name (e.g. app.tenant_id)"
      )
      .default("app.tenant_id"),
    pg_principal_setting: z
      .string()
      .regex(
        /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/,
        "Must be a PostgreSQL custom GUC name (e.g. app.principal)"
      )
      .default("app.principal"),
  })
  .strict();

export const AdhocSqlPolicySchema = z
  .object({
    enabled: z.boolean().default(true),
    allowed_roles: z
      .array(AuthenticatedRoleSchema)
      .default(["analyst", "admin"]),
    default_limit: z.number().int().min(1).max(1000).default(100),
    max_rows: z.number().int().min(1).max(5000).default(1000),
    max_offset: z.number().int().min(0).max(100000).default(10000),
  })
  .strict();

export const PiiPolicySchema = z
  .object({
    columns: z
      .record(
        z.string().regex(SAFE_IDENTIFIER_REGEX, "Invalid table name in pii.columns"),
        z.array(
          z.string().regex(SAFE_IDENTIFIER_REGEX, "Invalid column name in pii.columns")
        )
      )
      .default({}),
    auto_tag_patterns: z
      .array(SafeRegexStringSchema)
      .max(20)
      .default([...DEFAULT_PII_AUTO_TAG_PATTERNS]),
    extra_sensitive_substrings: z.array(z.string().min(6).max(128)).max(100).default([]),
  })
  .strict();

export const PolicyFileSchema = z
  .object({
    version: z.literal(1),
    engine: EnginePolicySchema.default({
      type: "sqlite",
      connection_string_env: "DATABASE_URL",
      allowed_schemas: ["public"],
      statement_timeout_ms: 5000,
      max_connections: 10,
      worker_pool_size: 1,
    }),
    tenant_isolation: TenantIsolationPolicySchema.default({
      enabled: false,
      require_tenant_id: false,
      pg_tenant_setting: "app.tenant_id",
      pg_principal_setting: "app.principal",
    }),
    adhoc_sql: AdhocSqlPolicySchema.default({
      enabled: true,
      allowed_roles: ["analyst", "admin"],
      default_limit: 100,
      max_rows: 1000,
      max_offset: 10000,
    }),
    roles: z
      .object({
        public_viewer: RolePolicySchema.default({ tables: [], views: [] }),
        analyst: RolePolicySchema.default({ tables: [], views: [] }),
        admin: RolePolicySchema.default({ tables: [], views: [], allow_pii: true }),
      })
      .strict(),
    pii: PiiPolicySchema.default({
      columns: {},
      auto_tag_patterns: [...DEFAULT_PII_AUTO_TAG_PATTERNS],
      extra_sensitive_substrings: [],
    }),
    templates: z.array(TemplateDefinitionSchema).max(100).default([]),
  })
  .strict()
  .superRefine((doc, ctx) => {
    const names = new Set<string>();
    for (let i = 0; i < doc.templates.length; i++) {
      const t = doc.templates[i];
      if (names.has(t.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["templates", i, "name"],
          message: `Duplicate template name '${t.name}'`,
        });
      }
      names.add(t.name);
    }
    if (doc.adhoc_sql.default_limit > doc.adhoc_sql.max_rows) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adhoc_sql", "default_limit"],
        message: "adhoc_sql.default_limit cannot exceed adhoc_sql.max_rows",
      });
    }
  });

export type PolicyFile = z.infer<typeof PolicyFileSchema>;
export type TemplateParameterPolicy = z.infer<typeof TemplateParameterSchema>;
export type TemplatePolicy = z.infer<typeof TemplateDefinitionSchema>;
