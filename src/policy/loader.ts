import fs from "node:fs";
import path from "node:path";
import YAML from "yaml";
import { ColumnMetadata, TableMetadata, UserRole } from "../types.js";
import type { AuthenticatedRole } from "../security/rbac.js";
import {
  COMPANY_ROLE_ALLOWED_TABLES,
  DEFAULT_ROLE_ALLOWED_TABLES,
  SQL_LIMITS,
  TABLE_PII_COLUMNS,
} from "../security/policy.js";
import {
  COMPANY_TABLE_METADATA,
  DEFAULT_TABLE_METADATA,
} from "../database/seed.js";
import {
  DEFAULT_RATE_LIMITS,
  RateLimitTierConfig,
} from "../security/rate-limiter.js";
import {
  PolicyFile,
  PolicyFileSchema,
  TemplatePolicy,
} from "./schema.js";

export interface IntrospectedColumn {
  name: string;
  type: string;
}

export interface IntrospectedTable {
  name: string;
  rowCount: number;
  columns: IntrospectedColumn[];
  description?: string;
}

export interface ResolvedRolePolicy {
  tables: readonly string[];
  views: readonly string[];
  pgRole: string;
  allowPii: boolean;
  rateLimit: RateLimitTierConfig;
}

export interface ResolvedPolicy {
  mode: "file" | "default_demo";
  sourcePath?: string;
  engine: {
    type: "sqlite" | "postgres";
    sqlitePath: string | null;
    connectionStringEnv: string;
    allowedSchemas: string[];
    statementTimeoutMs: number;
    maxConnections: number;
    workerPoolSize: number;
    ssl?: boolean | { rejectUnauthorized?: boolean };
  };
  tenantIsolation: {
    enabled: boolean;
    requireTenantId: boolean;
    pgTenantSetting: string;
    pgPrincipalSetting: string;
  };
  adhocSql: {
    enabled: boolean;
    allowedRoles: AuthenticatedRole[];
    defaultLimit: number;
    maxRows: number;
    maxOffset: number;
  };
  roles: Record<AuthenticatedRole, ResolvedRolePolicy>;
  roleAllowedTables: Record<UserRole, readonly string[]>;
  extraAllowedViews: string[];
  rateLimits: Record<UserRole, RateLimitTierConfig>;
  pii: {
    explicitColumnsByTable: Record<string, Set<string>>;
    autoTagPatternSources: string[];
    autoTagPatterns: RegExp[];
    extraSensitiveSubstrings: string[];
  };
  templates: TemplatePolicy[];
  seedTableMetadata: Record<string, TableMetadata>;
}

const DEFAULT_PG_ROLE_MAP: Record<AuthenticatedRole, string> = {
  public_viewer: "mcp_viewer",
  analyst: "mcp_analyst",
  admin: "mcp_admin",
};

function dedupeLower(items: readonly string[]): string[] {
  return [...new Set(items.map((s) => s.trim().toLowerCase()).filter(Boolean))];
}

export function resolvePolicyObject(
  parsedRaw: unknown,
  baseDir: string,
  sourcePath?: string
): ResolvedPolicy {
  const result = PolicyFileSchema.safeParse(parsedRaw);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
      .join("; ");
    throw new Error(`PolicyValidationError: ${issues}`);
  }

  const doc: PolicyFile = result.data;
  const resolvedSqlitePath = doc.engine.sqlite_path
    ? path.resolve(baseDir, doc.engine.sqlite_path)
    : null;

  const roles: Record<AuthenticatedRole, ResolvedRolePolicy> = {
    public_viewer: {
      tables: dedupeLower(doc.roles.public_viewer.tables),
      views: dedupeLower(doc.roles.public_viewer.views),
      pgRole: doc.roles.public_viewer.pg_role ?? DEFAULT_PG_ROLE_MAP.public_viewer,
      allowPii: doc.roles.public_viewer.allow_pii ?? false,
      rateLimit: doc.roles.public_viewer.rate_limit
        ? {
            maxQueriesPerMinute:
              doc.roles.public_viewer.rate_limit.max_queries_per_minute,
            maxRowsPerHour:
              doc.roles.public_viewer.rate_limit.max_rows_per_hour,
          }
        : { ...DEFAULT_RATE_LIMITS.public_viewer },
    },
    analyst: {
      tables: dedupeLower(doc.roles.analyst.tables),
      views: dedupeLower(doc.roles.analyst.views),
      pgRole: doc.roles.analyst.pg_role ?? DEFAULT_PG_ROLE_MAP.analyst,
      allowPii: doc.roles.analyst.allow_pii ?? false,
      rateLimit: doc.roles.analyst.rate_limit
        ? {
            maxQueriesPerMinute:
              doc.roles.analyst.rate_limit.max_queries_per_minute,
            maxRowsPerHour: doc.roles.analyst.rate_limit.max_rows_per_hour,
          }
        : { ...DEFAULT_RATE_LIMITS.analyst },
    },
    admin: {
      tables: dedupeLower(doc.roles.admin.tables),
      views: dedupeLower(doc.roles.admin.views),
      pgRole: doc.roles.admin.pg_role ?? DEFAULT_PG_ROLE_MAP.admin,
      allowPii: doc.roles.admin.allow_pii ?? true,
      rateLimit: doc.roles.admin.rate_limit
        ? {
            maxQueriesPerMinute:
              doc.roles.admin.rate_limit.max_queries_per_minute,
            maxRowsPerHour: doc.roles.admin.rate_limit.max_rows_per_hour,
          }
        : { ...DEFAULT_RATE_LIMITS.admin },
    },
  };

  const roleAllowedTables: Record<UserRole, readonly string[]> = {
    unauthenticated: [],
    public_viewer: dedupeLower([
      ...roles.public_viewer.tables,
      ...roles.public_viewer.views,
    ]),
    analyst: dedupeLower([...roles.analyst.tables, ...roles.analyst.views]),
    admin: dedupeLower([...roles.admin.tables, ...roles.admin.views]),
  };

  const extraAllowedViews = dedupeLower([
    ...roles.public_viewer.views,
    ...roles.analyst.views,
    ...roles.admin.views,
  ]);

  const explicitColumnsByTable: Record<string, Set<string>> = {};
  for (const [tbl, cols] of Object.entries(doc.pii.columns)) {
    explicitColumnsByTable[tbl.toLowerCase()] = new Set(dedupeLower(cols));
  }

  const autoTagPatterns = doc.pii.auto_tag_patterns.map(
    (pat) => new RegExp(pat, "i")
  );

  return {
    mode: "file",
    sourcePath,
    engine: {
      type: doc.engine.type,
      sqlitePath: resolvedSqlitePath,
      connectionStringEnv: doc.engine.connection_string_env,
      allowedSchemas: doc.engine.allowed_schemas.map((s) => s.toLowerCase()),
      statementTimeoutMs: doc.engine.statement_timeout_ms,
      maxConnections: doc.engine.max_connections,
      workerPoolSize: doc.engine.worker_pool_size,
      ssl: doc.engine.ssl,
    },
    tenantIsolation: {
      enabled: doc.tenant_isolation.enabled,
      requireTenantId: doc.tenant_isolation.require_tenant_id,
      pgTenantSetting: doc.tenant_isolation.pg_tenant_setting,
      pgPrincipalSetting: doc.tenant_isolation.pg_principal_setting,
    },
    adhocSql: {
      enabled: doc.adhoc_sql.enabled,
      allowedRoles: [...doc.adhoc_sql.allowed_roles],
      defaultLimit: doc.adhoc_sql.default_limit,
      maxRows: doc.adhoc_sql.max_rows,
      maxOffset: doc.adhoc_sql.max_offset,
    },
    roles,
    roleAllowedTables,
    extraAllowedViews,
    rateLimits: {
      unauthenticated: { ...DEFAULT_RATE_LIMITS.unauthenticated },
      public_viewer: roles.public_viewer.rateLimit,
      analyst: roles.analyst.rateLimit,
      admin: roles.admin.rateLimit,
    },
    pii: {
      explicitColumnsByTable,
      autoTagPatternSources: [...doc.pii.auto_tag_patterns],
      autoTagPatterns,
      extraSensitiveSubstrings: [...doc.pii.extra_sensitive_substrings],
    },
    templates: doc.templates,
    seedTableMetadata: {},
  };
}

export function loadPolicyFromFile(filePath: string): ResolvedPolicy {
  const absPath = path.resolve(filePath);
  if (!fs.existsSync(absPath)) {
    throw new Error(`PolicyLoadError: policy file not found at '${absPath}'.`);
  }

  const rawText = fs.readFileSync(absPath, "utf8");
  const ext = path.extname(absPath).toLowerCase();

  let parsed: unknown;
  try {
    if (ext === ".json") {
      parsed = JSON.parse(rawText);
    } else {
      parsed = YAML.parse(rawText);
    }
  } catch (err: any) {
    throw new Error(
      `PolicyParseError: failed to parse '${absPath}': ${err.message}`
    );
  }

  return resolvePolicyObject(parsed, path.dirname(absPath), absPath);
}

export function buildDefaultDemoPolicy(
  engineType: "sqlite" | "postgres" = "sqlite",
  sqliteDbPath?: string | null
): ResolvedPolicy {
  const effectiveSqlitePath =
    engineType === "sqlite"
      ? sqliteDbPath ?? process.env.MCP_SECURE_DB_SQLITE_PATH?.trim() ?? null
      : null;
  const useCompany = Boolean(
    engineType === "sqlite" &&
      effectiveSqlitePath &&
      effectiveSqlitePath.length > 0
  );

  const roleTableMap = useCompany
    ? COMPANY_ROLE_ALLOWED_TABLES
    : DEFAULT_ROLE_ALLOWED_TABLES;
  const seedMeta = useCompany ? COMPANY_TABLE_METADATA : DEFAULT_TABLE_METADATA;

  const explicitColumnsByTable: Record<string, Set<string>> = {};
  for (const [tbl, cols] of Object.entries(TABLE_PII_COLUMNS)) {
    if (tbl in seedMeta) {
      explicitColumnsByTable[tbl] = new Set(cols);
    }
  }

  return {
    mode: "default_demo",
    engine: {
      type: engineType,
      sqlitePath: effectiveSqlitePath ? path.resolve(effectiveSqlitePath) : null,
      connectionStringEnv: "DATABASE_URL",
      allowedSchemas: ["public"],
      statementTimeoutMs: engineType === "postgres" ? 3000 : 5000,
      maxConnections: 10,
      workerPoolSize: 1,
    },
    tenantIsolation: {
      enabled: false,
      requireTenantId: false,
      pgTenantSetting: "app.tenant_id",
      pgPrincipalSetting: "app.principal",
    },
    adhocSql: {
      enabled: true,
      allowedRoles: ["analyst", "admin"],
      defaultLimit: SQL_LIMITS.defaultLimit,
      maxRows: SQL_LIMITS.maxRows,
      maxOffset: SQL_LIMITS.maxOffset,
    },
    roles: {
      public_viewer: {
        tables: [...roleTableMap.public_viewer],
        views: [],
        pgRole: DEFAULT_PG_ROLE_MAP.public_viewer,
        allowPii: false,
        rateLimit: { ...DEFAULT_RATE_LIMITS.public_viewer },
      },
      analyst: {
        tables: [...roleTableMap.analyst],
        views: [],
        pgRole: DEFAULT_PG_ROLE_MAP.analyst,
        allowPii: false,
        rateLimit: { ...DEFAULT_RATE_LIMITS.analyst },
      },
      admin: {
        tables: [...roleTableMap.admin],
        views: [],
        pgRole: DEFAULT_PG_ROLE_MAP.admin,
        allowPii: true,
        rateLimit: { ...DEFAULT_RATE_LIMITS.admin },
      },
    },
    roleAllowedTables: {
      unauthenticated: [],
      public_viewer: [...roleTableMap.public_viewer],
      analyst: [...roleTableMap.analyst],
      admin: [...roleTableMap.admin],
    },
    extraAllowedViews: [],
    rateLimits: {
      unauthenticated: { ...DEFAULT_RATE_LIMITS.unauthenticated },
      public_viewer: { ...DEFAULT_RATE_LIMITS.public_viewer },
      analyst: { ...DEFAULT_RATE_LIMITS.analyst },
      admin: { ...DEFAULT_RATE_LIMITS.admin },
    },
    pii: {
      explicitColumnsByTable,
      autoTagPatternSources: [],
      autoTagPatterns: [],
      extraSensitiveSubstrings: [],
    },
    templates: [],
    seedTableMetadata: { ...seedMeta },
  };
}

/**
 * Classifies live-introspected database tables using policy default-deny table lists,
 * explicit per-table PII declarations, and compiled PII regex auto-taggers.
 */
export function classifyTableMetadataWithPolicy(
  introspectedTables: readonly IntrospectedTable[],
  policy: ResolvedPolicy
): {
  tableMetadata: Record<string, TableMetadata>;
  piiColumnsByTable: Record<string, Set<string>>;
  allPiiColumns: Set<string>;
} {
  const nonAdminTables = new Set<string>([
    ...policy.roleAllowedTables.public_viewer,
    ...policy.roleAllowedTables.analyst,
  ]);
  const allConfiguredTables = new Set<string>([
    ...nonAdminTables,
    ...policy.roleAllowedTables.admin,
  ]);

  const tableMetadata: Record<string, TableMetadata> = {};
  const piiColumnsByTable: Record<string, Set<string>> = {};
  const allPiiColumns = new Set<string>();

  for (const rawTable of introspectedTables) {
    const lowerTable = rawTable.name.toLowerCase();
    // Strict default-deny: ignore any table not explicitly granted to at least one role
    if (allConfiguredTables.size > 0 && !allConfiguredTables.has(lowerTable)) {
      continue;
    }

    const explicitForTable =
      policy.pii.explicitColumnsByTable[lowerTable] ?? new Set<string>();
    const tablePiiSet = new Set<string>(explicitForTable);
    const seedTable = policy.seedTableMetadata[lowerTable];
    const seedColsByName = new Map(
      (seedTable?.columns ?? []).map((c) => [c.name.toLowerCase(), c])
    );

    const columns: ColumnMetadata[] = rawTable.columns.map((col) => {
      const lowerCol = col.name.toLowerCase();
      const seedCol = seedColsByName.get(lowerCol);
      const matchedAutoPattern = policy.pii.autoTagPatterns.some((re) =>
        re.test(lowerCol)
      );
      const isPII =
        explicitForTable.has(lowerCol) ||
        matchedAutoPattern ||
        Boolean(seedCol?.isPII);

      if (isPII) {
        tablePiiSet.add(lowerCol);
        allPiiColumns.add(lowerCol);
      }

      return {
        name: col.name,
        type: col.type || seedCol?.type || "TEXT",
        isPII,
        description:
          seedCol?.description ??
          (isPII
            ? `Restricted PII column (${col.type || "TEXT"})`
            : `Introspected column (${col.type || "TEXT"})`),
      };
    });

    if (tablePiiSet.size > 0) {
      piiColumnsByTable[lowerTable] = tablePiiSet;
    }

    tableMetadata[lowerTable] = {
      name: lowerTable,
      description:
        rawTable.description ??
        seedTable?.description ??
        `Authorized ${policy.engine.type} relation '${lowerTable}'`,
      adminOnly: !nonAdminTables.has(lowerTable),
      rowCount: rawTable.rowCount,
      columns,
    };
  }

  return {
    tableMetadata,
    piiColumnsByTable,
    allPiiColumns,
  };
}
