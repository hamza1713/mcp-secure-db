import { z } from "zod";
import { SecurityContext, UserRole, ValidationResult } from "../types.js";
import { TemplateParameterPolicy, TemplatePolicy } from "../policy/schema.js";

export class TenantContextRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantContextRequiredError";
  }
}

export const TRUSTED_CONTEXT_PARAMS = new Set([
  "ctx.tenant_id",
  "ctx.principal",
  "ctx.role",
]);

export interface CompiledTemplate {
  definition: TemplatePolicy;
  dialect: "sqlite" | "postgresql";
  parameterizedSql: string;
  paramOrder: string[];
  contextParamsUsed: string[];
  inputSchema: z.ZodObject<Record<string, z.ZodTypeAny>>;
  limitApplied: number;
}

interface PlaceholderSpan {
  start: number;
  end: number;
  name: string;
}

/**
 * Lexically scans SQL outside string literals ('...'), quoted identifiers ("...", `...`),
 * and PostgreSQL dollar-quoted literals ($$...$$) for `:param_name` named placeholders.
 * Ignores PostgreSQL `::type` cast operators.
 */
function findNamedPlaceholders(sql: string): PlaceholderSpan[] {
  const spans: PlaceholderSpan[] = [];
  let inSingle = false;
  let inDouble = false;
  let inBacktick = false;
  let dollarTag: string | null = null;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = i + 1 < sql.length ? sql[i + 1] : "";

    if (dollarTag !== null) {
      if (sql.startsWith(dollarTag, i)) {
        i += dollarTag.length - 1;
        dollarTag = null;
      }
      continue;
    }

    if (ch === "'" && !inDouble && !inBacktick) {
      if (inSingle && next === "'") {
        i++;
        continue;
      }
      inSingle = !inSingle;
      continue;
    }
    if (ch === '"' && !inSingle && !inBacktick) {
      if (inDouble && next === '"') {
        i++;
        continue;
      }
      inDouble = !inDouble;
      continue;
    }
    if (ch === "`" && !inSingle && !inDouble) {
      if (inBacktick && next === "`") {
        i++;
        continue;
      }
      inBacktick = !inBacktick;
      continue;
    }

    if (!inSingle && !inDouble && !inBacktick) {
      if (ch === "$") {
        const tagMatch = sql.slice(i).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/);
        if (tagMatch) {
          dollarTag = tagMatch[0];
          i += dollarTag.length - 1;
          continue;
        }
      }

      if (ch === ":") {
        const prev = i > 0 ? sql[i - 1] : "";
        // Skip PostgreSQL :: type cast syntax
        if (prev === ":" || next === ":") {
          continue;
        }
        const match = sql
          .slice(i + 1)
          .match(/^(ctx\.[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*)/);
        if (match) {
          spans.push({
            start: i,
            end: i + 1 + match[1].length,
            name: match[1],
          });
          i += match[1].length;
        }
      }
    }
  }

  return spans;
}

export function buildDummyLiteral(param: TemplateParameterPolicy): string {
  if (param.type === "string") {
    const sample =
      param.enum && param.enum.length > 0
        ? param.enum[0]
        : typeof param.default === "string"
          ? param.default
          : "sample";
    return `'${sample.replace(/'/g, "''")}'`;
  }
  if (param.type === "integer") {
    const sample =
      typeof param.default === "number"
        ? Math.trunc(param.default)
        : typeof param.min === "number"
          ? Math.ceil(param.min)
          : 1;
    return String(sample);
  }
  if (param.type === "number") {
    const sample =
      typeof param.default === "number"
        ? param.default
        : typeof param.min === "number"
          ? param.min
          : 1.0;
    return String(sample);
  }
  return "true";
}

function buildContextDummyLiteral(ctxParamName: string): string {
  if (ctxParamName === "ctx.tenant_id") return "'tenant_sample'";
  if (ctxParamName === "ctx.principal") return "'principal@example.internal'";
  if (ctxParamName === "ctx.role") return "'analyst'";
  throw new Error(
    `TemplateValidationError: unsupported server context placeholder ':${ctxParamName}'. Supported: ${[...TRUSTED_CONTEXT_PARAMS].join(", ")}.`
  );
}

export function buildDummyValidationSql(
  sql: string,
  declaredParams: Record<string, TemplateParameterPolicy>
): string {
  const spans = findNamedPlaceholders(sql);
  let out = "";
  let cursor = 0;

  for (const span of spans) {
    let literal: string;
    if (span.name.startsWith("ctx.")) {
      if (!TRUSTED_CONTEXT_PARAMS.has(span.name)) {
        throw new Error(
          `TemplateValidationError: unsupported server context placeholder ':${span.name}'.`
        );
      }
      literal = buildContextDummyLiteral(span.name);
    } else {
      const def = declaredParams[span.name];
      if (!def) {
        throw new Error(
          `TemplateValidationError: SQL references undeclared parameter ':${span.name}'.`
        );
      }
      literal = buildDummyLiteral(def);
    }
    out += sql.slice(cursor, span.start) + literal;
    cursor = span.end;
  }
  out += sql.slice(cursor);
  return out;
}

export function compileTemplateSql(
  sql: string,
  dialect: "sqlite" | "postgresql",
  declaredParams: Record<string, TemplateParameterPolicy>
): {
  parameterizedSql: string;
  paramOrder: string[];
  contextParamsUsed: string[];
} {
  const spans = findNamedPlaceholders(sql);
  let out = "";
  let cursor = 0;
  const paramOrder: string[] = [];
  const contextParamsSet = new Set<string>();
  const pgIndexByName = new Map<string, number>();

  for (const span of spans) {
    const isTrustedCtx = span.name.startsWith("ctx.");
    if (isTrustedCtx) {
      if (!TRUSTED_CONTEXT_PARAMS.has(span.name)) {
        throw new Error(
          `TemplateValidationError: unsupported server context placeholder ':${span.name}'.`
        );
      }
      contextParamsSet.add(span.name);
    } else if (!Object.hasOwn(declaredParams, span.name)) {
      throw new Error(
        `TemplateValidationError: SQL references undeclared parameter ':${span.name}'.`
      );
    }

    let replacement: string;
    if (dialect === "postgresql") {
      let idx = pgIndexByName.get(span.name);
      if (idx === undefined) {
        paramOrder.push(span.name);
        idx = paramOrder.length;
        pgIndexByName.set(span.name, idx);
      }
      replacement = `$${idx}`;
    } else {
      paramOrder.push(span.name);
      replacement = "?";
    }

    out += sql.slice(cursor, span.start) + replacement;
    cursor = span.end;
  }
  out += sql.slice(cursor);

  return {
    parameterizedSql: out.replace(/;\s*$/, "").trim(),
    paramOrder,
    contextParamsUsed: [...contextParamsSet],
  };
}

export function buildTemplateZodSchema(
  declaredParams: Record<string, TemplateParameterPolicy>
): z.ZodObject<Record<string, z.ZodTypeAny>> {
  const shape: Record<string, z.ZodTypeAny> = {};

  for (const [name, def] of Object.entries(declaredParams)) {
    let field: z.ZodTypeAny;

    if (def.type === "string") {
      if (def.enum && def.enum.length > 0) {
        field = z.enum(def.enum as [string, ...string[]]);
      } else {
        let s = z.string();
        if (def.max_length !== undefined) s = s.max(def.max_length);
        field = s;
      }
    } else if (def.type === "integer") {
      let n = z.number().int();
      if (def.min !== undefined) n = n.min(def.min);
      if (def.max !== undefined) n = n.max(def.max);
      field = n;
    } else if (def.type === "number") {
      let n = z.number();
      if (def.min !== undefined) n = n.min(def.min);
      if (def.max !== undefined) n = n.max(def.max);
      field = n;
    } else {
      field = z.boolean();
    }

    if (def.description) {
      field = field.describe(def.description);
    }

    if (def.default !== undefined) {
      field = field.default(def.default).optional();
    } else if (!def.required) {
      field = field.optional();
    }

    shape[name] = field;
  }

  // Optional local-testing token parameter (ignored in NODE_ENV=production)
  shape.token = z
    .string()
    .optional()
    .describe(
      "Optional authentication token for local testing (disabled in NODE_ENV=production)"
    );

  return z.object(shape);
}

/**
 * Compiles and validates a declarative template at startup against the active
 * dialect's AST validator for every role listed in `template.allowed_roles`.
 * Fails fast if the template is non-SELECT, touches unauthorized tables/functions,
 * or accesses PII columns while permitting non-admin roles.
 */
export function compileAndValidateTemplate(
  template: TemplatePolicy,
  dialect: "sqlite" | "postgresql",
  validateFn: (sql: string, role: UserRole) => ValidationResult
): CompiledTemplate {
  const dummySql = buildDummyValidationSql(template.sql, template.parameters);

  let effectiveLimit = 100;
  for (const role of template.allowed_roles) {
    const res = validateFn(dummySql, role);
    if (!res.valid) {
      throw new Error(
        `TemplateSecurityViolation [${template.name}] for role '${role}': ${res.violationReason}`
      );
    }
    if (res.limitInjected !== undefined) {
      effectiveLimit = res.limitInjected;
    }
  }

  const { parameterizedSql, paramOrder, contextParamsUsed } = compileTemplateSql(
    template.sql,
    dialect,
    template.parameters
  );

  // Ensure bounded row limit if template SQL omitted LIMIT
  const finalSql = /\bLIMIT\b/i.test(parameterizedSql)
    ? parameterizedSql
    : `${parameterizedSql} LIMIT ${effectiveLimit}`;

  return {
    definition: template,
    dialect,
    parameterizedSql: finalSql,
    paramOrder,
    contextParamsUsed,
    inputSchema: buildTemplateZodSchema(template.parameters),
    limitApplied: effectiveLimit,
  };
}

export function bindTemplateParameters(
  args: Record<string, unknown>,
  compiled: CompiledTemplate,
  securityContext?: Pick<SecurityContext, "principal" | "role" | "tenantId">
): unknown[] {
  const values: unknown[] = [];
  for (const paramName of compiled.paramOrder) {
    if (paramName.startsWith("ctx.")) {
      if (!securityContext) {
        throw new TenantContextRequiredError(
          `TenantContextRequired: template '${compiled.definition.name}' requires verified server security context for ':${paramName}'.`
        );
      }
      if (paramName === "ctx.tenant_id") {
        if (!securityContext.tenantId || !securityContext.tenantId.trim()) {
          throw new TenantContextRequiredError(
            `TenantContextRequired: template '${compiled.definition.name}' requires a verified tenantId on the caller's identity.`
          );
        }
        values.push(securityContext.tenantId);
      } else if (paramName === "ctx.principal") {
        values.push(securityContext.principal);
      } else if (paramName === "ctx.role") {
        values.push(securityContext.role);
      } else {
        throw new Error(
          `TemplateParameterError: unsupported server context parameter ':${paramName}'.`
        );
      }
      continue;
    }

    const def = compiled.definition.parameters[paramName];
    let val = args[paramName];
    if (val === undefined && def?.default !== undefined) {
      val = def.default;
    }
    if (val === undefined) {
      if (def?.required) {
        throw new Error(
          `TemplateParameterError: missing required parameter '${paramName}' for template '${compiled.definition.name}'.`
        );
      }
      val = null;
    }
    if (compiled.dialect === "sqlite" && typeof val === "boolean") {
      val = val ? 1 : 0;
    }
    values.push(val);
  }
  return values;
}
