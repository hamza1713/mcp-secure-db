import { loadModule, parseSync, scanSync } from "libpg-query";
import { TableMetadata, UserRole, ValidationResult } from "../types.js";
import { DEFAULT_TABLE_METADATA } from "../database/seed.js";
import {
  ALLOWED_FUNCTIONS_POSTGRES,
  DEFAULT_ROLE_ALLOWED_TABLES,
  PII_COLUMNS,
  POSTGRES_FORBIDDEN_FUNCTION_PREFIXES,
  SQL_LIMITS,
  getAllowedTablesFromMap,
} from "./policy.js";

// Initialize official PostgreSQL WASM parser module once at module load
await loadModule();

const DISALLOWED_CONTROL_CHARS_REGEX =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069\uFEFF]/;

const FORBIDDEN_PG_SCHEMAS = new Set([
  "pg_catalog",
  "information_schema",
  "pg_toast",
  "pg_temp",
]);

const FORBIDDEN_PG_TABLES = new Set([
  "pg_shadow",
  "pg_authid",
  "pg_database",
  "pg_user",
  "pg_roles",
  "pg_settings",
  "pg_stat_activity",
  "pg_tablespace",
]);

const DISALLOWED_PG_OPERATORS = new Set([
  "~",
  "~*",
  "!~",
  "!~*",
  "->",
  "->>",
  "#>",
  "#>>",
  "@@",
  "@>",
  "<@",
]);

const ALLOWED_SQL_VALUE_FUNCTIONS = new Set([
  "SVFOP_CURRENT_DATE",
  "SVFOP_CURRENT_TIME",
  "SVFOP_CURRENT_TIME_N",
  "SVFOP_CURRENT_TIMESTAMP",
  "SVFOP_CURRENT_TIMESTAMP_N",
  "SVFOP_LOCALTIME",
  "SVFOP_LOCALTIME_N",
  "SVFOP_LOCALTIMESTAMP",
  "SVFOP_LOCALTIMESTAMP_N",
]);

const ALLOWED_JOIN_COMPARATORS = new Set(["=", "<", "<=", ">", ">="]);

/**
 * Standard SQL syntax forms (EXTRACT, TRIM, SUBSTRING ... FROM ...) that
 * PostgreSQL's official grammar desugars into `pg_catalog.<fn>` calls in the AST.
 */
const PG_CATALOG_GRAMMAR_SUGARED_FUNCTIONS = new Set([
  "extract",
  "date_part",
  "btrim",
  "ltrim",
  "rtrim",
  "substring",
  "trim",
]);

export interface PostgresAstValidatorOptions {
  maxRows?: number;
  defaultLimit?: number;
  maxSqlLength?: number;
  maxAstDepth?: number;
  maxCompoundSelects?: number;
  maxCtes?: number;
  maxJoins?: number;
  maxFunctionArgs?: number;
  maxLikePatternLength?: number;
  maxOffset?: number;
  allowedSchemas?: string[];
  extraAllowedViews?: string[];
  roleAllowedTables?: Record<UserRole, readonly string[]>;
  tableMetadata?: Record<string, TableMetadata>;
  piiColumns?: Set<string>;
  piiColumnsByTable?: Record<string, Set<string>>;
}

interface PgValidationState {
  role: UserRole;
  allowedTables: Set<string>;
  tablesAccessed: Set<string>;
  columnsAccessed: Set<string>;
  functionsUsed: Set<string>;
  cteCount: number;
  compoundCount: number;
  joinCount: number;
}

interface PgColRefInfo {
  table: string | null;
  column: string;
}

/**
 * Official PostgreSQL AST Validator backed by `libpg-query` (PostgreSQL 18 C
 * parser & C lexer compiled to WebAssembly). Reduces dialect drift between
 * JS regex/PEG parsers and live PostgreSQL servers.
 */
export class PostgresAstValidator {
  private readonly maxRows: number;
  private readonly defaultLimit: number;
  private readonly maxSqlLength: number;
  private readonly maxAstDepth: number;
  private readonly maxCompoundSelects: number;
  private readonly maxCtes: number;
  private readonly maxJoins: number;
  private readonly maxFunctionArgs: number;
  private readonly maxLikePatternLength: number;
  private readonly maxOffset: number;
  private readonly allowedSchemas: Set<string>;
  private readonly extraAllowedViews: Set<string>;
  private readonly roleAllowedTables: Record<UserRole, readonly string[]>;
  private readonly tableMetadata: Record<string, TableMetadata>;
  private readonly piiColumns: Set<string>;
  private readonly piiColumnsByTable: Record<string, Set<string>>;

  constructor(options: PostgresAstValidatorOptions = {}) {
    this.maxRows = options.maxRows ?? SQL_LIMITS.maxRows;
    this.defaultLimit = options.defaultLimit ?? SQL_LIMITS.defaultLimit;
    this.maxSqlLength = options.maxSqlLength ?? SQL_LIMITS.maxSqlLength;
    this.maxAstDepth = options.maxAstDepth ?? SQL_LIMITS.maxAstDepth;
    this.maxCompoundSelects =
      options.maxCompoundSelects ?? SQL_LIMITS.maxCompoundSelects;
    this.maxCtes = options.maxCtes ?? SQL_LIMITS.maxCtes;
    this.maxJoins = options.maxJoins ?? SQL_LIMITS.maxJoins;
    this.maxFunctionArgs =
      options.maxFunctionArgs ?? SQL_LIMITS.maxFunctionArgs;
    this.maxLikePatternLength =
      options.maxLikePatternLength ?? SQL_LIMITS.maxLikePatternLength;
    this.maxOffset = options.maxOffset ?? SQL_LIMITS.maxOffset;
    this.allowedSchemas = new Set(
      (options.allowedSchemas ?? ["public"]).map((s) => s.toLowerCase())
    );
    this.extraAllowedViews = new Set(
      (options.extraAllowedViews ?? []).map((v) => v.toLowerCase())
    );
    this.roleAllowedTables =
      options.roleAllowedTables ?? DEFAULT_ROLE_ALLOWED_TABLES;
    this.tableMetadata = options.tableMetadata ?? DEFAULT_TABLE_METADATA;
    this.piiColumns = options.piiColumns ?? PII_COLUMNS;
    this.piiColumnsByTable = options.piiColumnsByTable ?? {};
  }

  public validate(
    query: string,
    role: UserRole = "public_viewer"
  ): ValidationResult {
    if (role === "unauthenticated") {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason:
          "Authentication required: Unauthenticated callers cannot execute queries.",
      };
    }

    const trimmed = query.trim();
    if (!trimmed) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: "Query cannot be empty.",
      };
    }

    if (trimmed.length > this.maxSqlLength) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `Query exceeds maximum SQL length of ${this.maxSqlLength} characters.`,
      };
    }

    if (DISALLOWED_CONTROL_CHARS_REGEX.test(query)) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason:
          "Query contains disallowed control, null-byte, or bidirectional Unicode characters.",
      };
    }

    // 1. Official PostgreSQL C lexer pass: rejects SQL/C comments & chained semicolons
    // while natively honoring $$...$$ dollar-quoting and E'...' backslash escapes.
    let tokens: Array<{ tokenName?: string; text?: string; start?: number; end?: number }>;
    try {
      const scanRes = scanSync(trimmed) as { tokens?: typeof tokens };
      tokens = scanRes.tokens ?? [];
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `PostgreSQL lexical scan error: ${err.message}`,
      };
    }

    let seenSemicolon = false;
    for (const tok of tokens) {
      if (tok.tokenName === "SQL_COMMENT" || tok.tokenName === "C_COMMENT") {
        return {
          valid: false,
          tablesAccessed: [],
          columnsAccessed: [],
          violationReason:
            "SQL comments (-- or /* */) are forbidden to reduce comment-smuggling ambiguity.",
        };
      }
      if (tok.tokenName === "ASCII_59" || tok.text === ";") {
        if (seenSemicolon) {
          return {
            valid: false,
            tablesAccessed: [],
            columnsAccessed: [],
            violationReason:
              "Chained multiple SQL statements are strictly forbidden.",
          };
        }
        seenSemicolon = true;
      } else if (seenSemicolon) {
        return {
          valid: false,
          tablesAccessed: [],
          columnsAccessed: [],
          violationReason:
            "Chained multiple SQL statements are strictly forbidden.",
        };
      }
    }

    // 2. Official PostgreSQL C parser pass
    let parsed: { stmts?: Array<{ stmt?: Record<string, any> }> };
    try {
      parsed = parseSync(trimmed) as typeof parsed;
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `PostgreSQL syntax error: ${err.message}`,
      };
    }

    const stmts = parsed.stmts ?? [];
    if (stmts.length !== 1) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: "Multiple statement AST is strictly forbidden.",
      };
    }

    const rootStmt = stmts[0]?.stmt;
    if (!rootStmt || !rootStmt.SelectStmt) {
      const stmtKind = rootStmt
        ? Object.keys(rootStmt)[0] ?? "UNKNOWN"
        : "UNKNOWN";
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `Only SELECT statements are permitted. PostgreSQL statement type '${stmtKind}' is strictly forbidden.`,
      };
    }

    const selectStmt = rootStmt.SelectStmt;
    const state: PgValidationState = {
      role,
      allowedTables: getAllowedTablesFromMap(
        role,
        this.roleAllowedTables,
        [...this.extraAllowedViews]
      ),
      tablesAccessed: new Set<string>(),
      columnsAccessed: new Set<string>(),
      functionsUsed: new Set<string>(),
      cteCount: 0,
      compoundCount: 0,
      joinCount: 0,
    };

    try {
      this.checkAstDepth(selectStmt, 0);
      this.validateSelectStmt(selectStmt, state, new Set<string>(), 0);
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [...state.tablesAccessed],
        columnsAccessed: [...state.columnsAccessed],
        functionsUsed: [...state.functionsUsed],
        violationReason: err.message,
      };
    }

    // 3. Enforce terminal LIMIT and OFFSET bounds without fragile SQL mutation
    let limitApplied: number;
    let sanitizedQuery: string;
    try {
      const bounded = this.buildBoundedQuery(trimmed, selectStmt);
      limitApplied = bounded.limitApplied;
      sanitizedQuery = bounded.sanitizedQuery;
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [...state.tablesAccessed],
        columnsAccessed: [...state.columnsAccessed],
        functionsUsed: [...state.functionsUsed],
        violationReason: err.message,
      };
    }

    return {
      valid: true,
      sanitizedQuery,
      astType: "select",
      tablesAccessed: [...state.tablesAccessed],
      columnsAccessed: [...state.columnsAccessed],
      functionsUsed: [...state.functionsUsed],
      limitInjected: limitApplied,
    };
  }

  private extractNonNegativeIntConst(node: any, label: string): number {
    const aConst = node?.A_Const;
    if (!aConst || !aConst.ival || typeof aConst.ival !== "object") {
      throw new Error(`${label} value must be a non-negative integer literal.`);
    }
    // Protobuf3 omits integer 0, so `{ ival: {} }` represents 0
    const raw = aConst.ival.ival === undefined ? 0 : Number(aConst.ival.ival);
    if (!Number.isInteger(raw) || raw < 0) {
      throw new Error(`${label} value must be a non-negative integer literal.`);
    }
    return raw;
  }

  private buildBoundedQuery(
    trimmedSql: string,
    selectStmt: any
  ): { sanitizedQuery: string; limitApplied: number } {
    const noTrailingSemi = trimmedSql.replace(/;\s*$/, "").trim();
    const isCompound =
      typeof selectStmt.op === "string" && selectStmt.op !== "SETOP_NONE";

    if (selectStmt.limitOffset) {
      const offsetVal = this.extractNonNegativeIntConst(
        selectStmt.limitOffset,
        "OFFSET"
      );
      if (offsetVal > this.maxOffset) {
        throw new Error(
          `OFFSET value ${offsetVal} exceeds maximum allowed offset of ${this.maxOffset}.`
        );
      }
    }

    if (selectStmt.limitCount) {
      const parsedLimit = this.extractNonNegativeIntConst(
        selectStmt.limitCount,
        "LIMIT"
      );
      if (parsedLimit <= this.maxRows) {
        return {
          sanitizedQuery: noTrailingSemi,
          limitApplied: parsedLimit,
        };
      }
      // Clamp explicit LIMIT / FETCH FIRST exceeding maxRows cleanly via planner-pushed wrapper
      return {
        sanitizedQuery: `SELECT * FROM (${noTrailingSemi}) AS _mcp_bounded LIMIT ${this.maxRows}`,
        limitApplied: this.maxRows,
      };
    }

    // No explicit LIMIT supplied: append directly on simple SELECT or wrap compound query
    if (!isCompound && !selectStmt.limitOffset) {
      return {
        sanitizedQuery: `${noTrailingSemi} LIMIT ${this.defaultLimit}`,
        limitApplied: this.defaultLimit,
      };
    }

    return {
      sanitizedQuery: `SELECT * FROM (${noTrailingSemi}) AS _mcp_bounded LIMIT ${this.defaultLimit}`,
      limitApplied: this.defaultLimit,
    };
  }

  private checkAstDepth(node: unknown, depth: number): void {
    if (depth > this.maxAstDepth * 2) {
      throw new Error(
        `Query exceeds maximum AST nesting depth of ${this.maxAstDepth}.`
      );
    }
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) {
        this.checkAstDepth(item, depth + 1);
      }
      return;
    }
    for (const val of Object.values(node as Record<string, unknown>)) {
      if (val && typeof val === "object") {
        this.checkAstDepth(val, depth + 1);
      }
    }
  }

  private isPiiColumn(colName: string, localBaseTables: readonly string[]): boolean {
    const lower = colName.toLowerCase();
    for (const tbl of localBaseTables) {
      if (this.piiColumnsByTable[tbl]?.has(lower)) {
        return true;
      }
    }
    return this.piiColumns.has(lower);
  }

  private checkColumnPermission(
    colName: string,
    state: PgValidationState,
    localBaseTables: readonly string[]
  ): void {
    const normalized = colName.toLowerCase();
    if (!normalized || normalized === "*") return;
    state.columnsAccessed.add(normalized);
    if (
      state.role !== "admin" &&
      this.isPiiColumn(normalized, localBaseTables)
    ) {
      throw new Error(
        `Access denied: column '${normalized}' contains sensitive PII and requires admin privileges.`
      );
    }
  }

  private validateSelectStmt(
    selectStmt: any,
    state: PgValidationState,
    outerCtes: Set<string>,
    nestingLevel: number
  ): void {
    if (!selectStmt || typeof selectStmt !== "object") {
      throw new Error("Invalid empty SELECT AST node.");
    }

    if (selectStmt.intoClause) {
      throw new Error("SELECT INTO statements are strictly forbidden.");
    }

    if (
      Array.isArray(selectStmt.lockingClause) &&
      selectStmt.lockingClause.length > 0
    ) {
      throw new Error("Locking SELECT clauses (FOR UPDATE/SHARE) are strictly forbidden.");
    }

    const activeCtes = new Set<string>(outerCtes);

    // 1. WITH CTEs
    if (Array.isArray(selectStmt.withClause?.ctes)) {
      for (const cteWrap of selectStmt.withClause.ctes) {
        const cte = cteWrap?.CommonTableExpr;
        if (!cte) throw new Error("Malformed CTE AST node.");

        state.cteCount += 1;
        if (state.cteCount > this.maxCtes) {
          throw new Error(
            `Query exceeds maximum CTE count of ${this.maxCtes}.`
          );
        }

        const cteName = String(cte.ctename || "").toLowerCase();
        if (!cteName) {
          throw new Error("Invalid unnamed CTE definition.");
        }

        if (
          this.tableMetadata[cteName] ||
          FORBIDDEN_PG_TABLES.has(cteName) ||
          cteName.startsWith("pg_") ||
          this.extraAllowedViews.has(cteName)
        ) {
          throw new Error(
            `CTE alias '${cteName}' cannot shadow catalog or PostgreSQL system table names.`
          );
        }

        const cteSelect = cte.ctequery?.SelectStmt;
        if (!cteSelect) {
          const kind = cte.ctequery ? Object.keys(cte.ctequery)[0] : "UNKNOWN";
          throw new Error(
            `CTE '${cteName}' must contain a valid SELECT query (found '${kind}').`
          );
        }

        // Add before recursing so WITH RECURSIVE self-references validate cleanly
        activeCtes.add(cteName);
        this.validateSelectStmt(cteSelect, state, activeCtes, nestingLevel + 1);
      }
    }

    // 2. Compound SELECT branches (UNION / INTERSECT / EXCEPT)
    if (
      typeof selectStmt.op === "string" &&
      selectStmt.op !== "SETOP_NONE"
    ) {
      state.compoundCount += 1;
      if (state.compoundCount >= this.maxCompoundSelects) {
        throw new Error(
          `Query exceeds maximum compound SELECT count of ${this.maxCompoundSelects}.`
        );
      }
      if (selectStmt.larg) {
        this.validateSelectStmt(
          selectStmt.larg,
          state,
          activeCtes,
          nestingLevel + 1
        );
      }
      if (selectStmt.rarg) {
        this.validateSelectStmt(
          selectStmt.rarg,
          state,
          activeCtes,
          nestingLevel + 1
        );
      }
    }

    // 3. FROM clause (RangeVar, JoinExpr, RangeSubselect; reject comma joins & TVFs)
    const localBaseTables: string[] = [];
    if (Array.isArray(selectStmt.fromClause)) {
      if (selectStmt.fromClause.length > 1) {
        throw new Error(
          "Implicit comma-separated Cartesian joins are prohibited; use an explicit JOIN with an ON clause."
        );
      }
      for (const fromItem of selectStmt.fromClause) {
        this.validateFromItem(
          fromItem,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
    }

    // 4. DISTINCT / DISTINCT ON clause
    if (Array.isArray(selectStmt.distinctClause)) {
      for (const distNode of selectStmt.distinctClause) {
        if (distNode && Object.keys(distNode).length > 0) {
          this.validateExpr(
            distNode,
            state,
            activeCtes,
            localBaseTables,
            nestingLevel
          );
        }
      }
    }

    // 5. SELECT targetList & wildcard protection
    let hasWildcard = false;
    if (Array.isArray(selectStmt.targetList)) {
      for (const targetWrap of selectStmt.targetList) {
        const resTarget = targetWrap?.ResTarget;
        if (!resTarget?.val) continue;
        if (this.isDirectStarColumnRef(resTarget.val)) {
          hasWildcard = true;
        } else {
          this.validateExpr(
            resTarget.val,
            state,
            activeCtes,
            localBaseTables,
            nestingLevel
          );
        }
      }
    }

    if (hasWildcard && state.role !== "admin") {
      const candidateTables = new Set<string>([
        ...localBaseTables,
        ...state.tablesAccessed,
      ]);
      for (const table of candidateTables) {
        const meta = this.tableMetadata[table];
        const hasPii =
          Boolean(meta && meta.columns.some((c) => c.isPII)) ||
          Boolean(
            this.piiColumnsByTable[table] &&
              this.piiColumnsByTable[table].size > 0
          );
        if (hasPii) {
          throw new Error(
            `Wildcard SELECT * on table '${table}' containing PII columns is prohibited for role '${state.role}'. Explicitly select non-sensitive columns.`
          );
        }
        if (this.extraAllowedViews.has(table)) {
          throw new Error(
            `Wildcard SELECT * on view '${table}' is prohibited for role '${state.role}'. Explicitly select permitted columns.`
          );
        }
      }
      if (localBaseTables.length === 0) {
        throw new Error(
          `Wildcard SELECT * on derived relations or CTEs is prohibited for role '${state.role}'. Explicitly list columns.`
        );
      }
    }

    // 6. WHERE, GROUP BY, HAVING, WINDOW, ORDER BY, VALUES, nested LIMIT/OFFSET
    if (selectStmt.whereClause) {
      this.validateExpr(
        selectStmt.whereClause,
        state,
        activeCtes,
        localBaseTables,
        nestingLevel
      );
    }

    if (Array.isArray(selectStmt.groupClause)) {
      for (const g of selectStmt.groupClause) {
        this.validateExpr(g, state, activeCtes, localBaseTables, nestingLevel);
      }
    }

    if (selectStmt.havingClause) {
      this.validateExpr(
        selectStmt.havingClause,
        state,
        activeCtes,
        localBaseTables,
        nestingLevel
      );
    }

    if (Array.isArray(selectStmt.windowClause)) {
      for (const win of selectStmt.windowClause) {
        this.validateExpr(win, state, activeCtes, localBaseTables, nestingLevel);
      }
    }

    if (Array.isArray(selectStmt.sortClause)) {
      for (const sort of selectStmt.sortClause) {
        this.validateExpr(
          sort,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
    }

    if (Array.isArray(selectStmt.valuesLists)) {
      for (const row of selectStmt.valuesLists) {
        this.validateExpr(row, state, activeCtes, localBaseTables, nestingLevel);
      }
    }

    if (nestingLevel > 0) {
      if (selectStmt.limitCount) {
        const nestedLimit = this.extractNonNegativeIntConst(
          selectStmt.limitCount,
          "LIMIT"
        );
        if (nestedLimit > this.maxRows) {
          throw new Error(
            `Subquery LIMIT ${nestedLimit} exceeds maximum allowed limit of ${this.maxRows}.`
          );
        }
      }
      if (selectStmt.limitOffset) {
        const nestedOffset = this.extractNonNegativeIntConst(
          selectStmt.limitOffset,
          "OFFSET"
        );
        if (nestedOffset > this.maxOffset) {
          throw new Error(
            `Subquery OFFSET ${nestedOffset} exceeds maximum allowed offset of ${this.maxOffset}.`
          );
        }
      }
    }
  }

  private validateFromItem(
    item: any,
    state: PgValidationState,
    activeCtes: Set<string>,
    localBaseTables: string[],
    nestingLevel: number
  ): Set<string> {
    if (!item || typeof item !== "object") {
      return new Set<string>();
    }

    if (item.RangeVar) {
      const rv = item.RangeVar;
      if (rv.catalogname) {
        throw new Error(
          `Cross-database qualifier '${rv.catalogname}' is forbidden.`
        );
      }
      if (rv.schemaname) {
        const schema = String(rv.schemaname).toLowerCase();
        if (FORBIDDEN_PG_SCHEMAS.has(schema) || schema.startsWith("pg_")) {
          throw new Error(
            `Access to system catalog '${schema}' is forbidden.`
          );
        }
        if (!this.allowedSchemas.has(schema)) {
          throw new Error(
            `Schema qualifier '${rv.schemaname}' is not in the permitted PostgreSQL schema allowlist.`
          );
        }
      }

      const relName = String(rv.relname || "").toLowerCase();
      if (!relName) {
        throw new Error("Invalid empty table reference in FROM clause.");
      }

      if (!activeCtes.has(relName)) {
        if (FORBIDDEN_PG_TABLES.has(relName) || relName.startsWith("pg_")) {
          throw new Error(
            `Access to system table '${relName}' is forbidden.`
          );
        }

        state.tablesAccessed.add(relName);
        localBaseTables.push(relName);

        if (
          !this.tableMetadata[relName] &&
          !this.extraAllowedViews.has(relName)
        ) {
          throw new Error(
            `Access denied: table '${relName}' is not in the authorized catalog.`
          );
        }

        if (!state.allowedTables.has(relName)) {
          throw new Error(
            `Access denied: table '${relName}' requires higher privileges for role '${state.role}'.`
          );
        }
      }

      const alias = String(rv.alias?.aliasname || relName).toLowerCase();
      return new Set<string>([alias]);
    }

    if (item.RangeSubselect) {
      const rs = item.RangeSubselect;
      const subSelect = rs.subquery?.SelectStmt;
      if (!subSelect) {
        throw new Error("Derived table in FROM must be a valid SELECT query.");
      }
      this.validateSelectStmt(subSelect, state, activeCtes, nestingLevel + 1);
      const alias = String(rs.alias?.aliasname || "").toLowerCase();
      return alias ? new Set<string>([alias]) : new Set<string>();
    }

    if (item.JoinExpr) {
      const je = item.JoinExpr;
      state.joinCount += 1;
      if (state.joinCount > this.maxJoins) {
        throw new Error(
          `Query exceeds maximum join count of ${this.maxJoins}.`
        );
      }

      if (je.isNatural) {
        throw new Error(
          "NATURAL JOIN is prohibited; specify explicit join columns in an ON clause."
        );
      }

      const leftRelations = this.validateFromItem(
        je.larg,
        state,
        activeCtes,
        localBaseTables,
        nestingLevel
      );
      const rightRelations = this.validateFromItem(
        je.rarg,
        state,
        activeCtes,
        localBaseTables,
        nestingLevel
      );

      const hasUsing =
        Array.isArray(je.usingClause) && je.usingClause.length > 0;
      if (!je.quals && !hasUsing) {
        throw new Error(
          "Unconstrained Cartesian CROSS JOIN is strictly prohibited; JOIN clauses must specify an explicit ON or USING condition."
        );
      }

      if (je.quals) {
        this.validatePgJoinQuals(je.quals, leftRelations, rightRelations);
        this.validateExpr(
          je.quals,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }

      if (hasUsing) {
        for (const u of je.usingClause) {
          const colName = String(u?.String?.sval ?? "").toLowerCase();
          if (colName) {
            this.checkColumnPermission(colName, state, localBaseTables);
          }
        }
      }

      return new Set<string>([...leftRelations, ...rightRelations]);
    }

    if (item.RangeFunction || item.RangeTableFunc || item.RangeTableSample) {
      throw new Error(
        "Table-valued functions and TABLESAMPLE in FROM clauses are strictly forbidden."
      );
    }

    const unknownKey = Object.keys(item)[0] ?? "unknown";
    throw new Error(
      `Unsupported or disallowed FROM clause node '${unknownKey}'.`
    );
  }

  private collectPgColumnRefs(
    node: any,
    out: PgColRefInfo[] = []
  ): PgColRefInfo[] {
    if (!node || typeof node !== "object") return out;
    if (Array.isArray(node)) {
      for (const item of node) this.collectPgColumnRefs(item, out);
      return out;
    }
    if (node.SubLink || node.SelectStmt) return out;
    if (node.ColumnRef && Array.isArray(node.ColumnRef.fields)) {
      const parts = node.ColumnRef.fields
        .map((f: any) => f?.String?.sval)
        .filter((s: unknown): s is string => typeof s === "string");
      if (parts.length === 1) {
        out.push({ table: null, column: parts[0].toLowerCase() });
      } else if (parts.length >= 2) {
        out.push({
          table: parts[parts.length - 2].toLowerCase(),
          column: parts[parts.length - 1].toLowerCase(),
        });
      }
      return out;
    }
    for (const val of Object.values(node)) {
      if (val && typeof val === "object") {
        this.collectPgColumnRefs(val, out);
      }
    }
    return out;
  }

  private stripPgLocations(node: any): any {
    if (!node || typeof node !== "object") return node;
    if (Array.isArray(node)) return node.map((i) => this.stripPgLocations(i));
    const cleaned: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) {
      if (k === "location") continue;
      cleaned[k] = this.stripPgLocations(v);
    }
    return cleaned;
  }

  private validatePgJoinQuals(
    quals: any,
    leftRelations: Set<string>,
    rightRelations: Set<string>
  ): void {
    const refs = this.collectPgColumnRefs(quals);
    if (refs.length === 0) {
      throw new Error(
        "Degenerate tautological or constant join condition (e.g., ON 1=1 or ON true) is strictly forbidden."
      );
    }

    if (!this.hasPgCrossRelationPredicate(quals, leftRelations, rightRelations)) {
      throw new Error(
        "Degenerate tautological or non-correlating join condition is strictly forbidden; ON clause must compare columns across the joined relations."
      );
    }
  }

  private hasPgCrossRelationPredicate(
    node: any,
    leftRelations: Set<string>,
    rightRelations: Set<string>
  ): boolean {
    if (!node || typeof node !== "object") return false;

    if (node.BoolExpr) {
      const op = node.BoolExpr.boolop;
      const args: any[] = Array.isArray(node.BoolExpr.args)
        ? node.BoolExpr.args
        : [];
      if (op === "AND_EXPR") {
        return args.some((a) =>
          this.hasPgCrossRelationPredicate(a, leftRelations, rightRelations)
        );
      }
      if (op === "OR_EXPR") {
        return (
          args.length > 0 &&
          args.every((a) =>
            this.hasPgCrossRelationPredicate(a, leftRelations, rightRelations)
          )
        );
      }
      return false;
    }

    if (node.A_Expr && node.A_Expr.kind === "AEXPR_OP") {
      const opName = String(node.A_Expr.name?.[0]?.String?.sval ?? "");
      if (!ALLOWED_JOIN_COMPARATORS.has(opName)) {
        return false;
      }

      const lRefs = this.collectPgColumnRefs(node.A_Expr.lexpr);
      const rRefs = this.collectPgColumnRefs(node.A_Expr.rexpr);
      if (lRefs.length === 0 || rRefs.length === 0) {
        return false;
      }

      if (
        JSON.stringify(this.stripPgLocations(node.A_Expr.lexpr)) ===
        JSON.stringify(this.stripPgLocations(node.A_Expr.rexpr))
      ) {
        return false;
      }

      const lTables = new Set(
        lRefs.map((r) => r.table).filter((t): t is string => t !== null)
      );
      const rTables = new Set(
        rRefs.map((r) => r.table).filter((t): t is string => t !== null)
      );

      if (lTables.size > 0 && rTables.size > 0) {
        for (const lt of lTables) {
          for (const rt of rTables) {
            if (lt === rt) continue;
            if (leftRelations.size === 0 || rightRelations.size === 0) {
              return true;
            }
            if (
              (leftRelations.has(lt) && rightRelations.has(rt)) ||
              (rightRelations.has(lt) && leftRelations.has(rt))
            ) {
              return true;
            }
          }
        }
        return false;
      }

      const lCols = new Set(lRefs.map((r) => r.column));
      const rCols = new Set(rRefs.map((r) => r.column));
      for (const lc of lCols) {
        for (const rc of rCols) {
          if (lc !== rc) return true;
        }
      }
      return false;
    }

    return false;
  }

  private isDirectStarColumnRef(node: any): boolean {
    if (!node?.ColumnRef || !Array.isArray(node.ColumnRef.fields)) return false;
    return node.ColumnRef.fields.some((f: any) => Boolean(f?.A_Star));
  }

  private validateExpr(
    node: any,
    state: PgValidationState,
    activeCtes: Set<string>,
    localBaseTables: readonly string[],
    nestingLevel: number
  ): void {
    if (!node || typeof node !== "object") return;

    if (Array.isArray(node)) {
      for (const item of node) {
        this.validateExpr(
          item,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      return;
    }

    // Subqueries inside EXISTS, IN, ANY, ALL, scalar projections
    if (node.SubLink) {
      const sl = node.SubLink;
      if (sl.testexpr) {
        this.validateExpr(
          sl.testexpr,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      if (sl.subselect?.SelectStmt) {
        this.validateSelectStmt(
          sl.subselect.SelectStmt,
          state,
          activeCtes,
          nestingLevel + 1
        );
      } else if (sl.subselect) {
        throw new Error("Only SELECT subqueries are permitted.");
      }
      return;
    }

    if (node.SelectStmt) {
      this.validateSelectStmt(
        node.SelectStmt,
        state,
        activeCtes,
        nestingLevel + 1
      );
      return;
    }

    // ColumnRef
    if (node.ColumnRef) {
      const fields: any[] = Array.isArray(node.ColumnRef.fields)
        ? node.ColumnRef.fields
        : [];
      for (const f of fields) {
        if (f?.A_Star) {
          if (state.role !== "admin") {
            throw new Error(
              `Wildcard column reference '*' inside expressions is prohibited for role '${state.role}'.`
            );
          }
        }
      }
      const stringParts = fields
        .map((f) => f?.String?.sval)
        .filter((s): s is string => typeof s === "string");
      if (stringParts.length > 0) {
        const colName = stringParts[stringParts.length - 1];
        this.checkColumnPermission(colName, state, localBaseTables);
      }
      return;
    }

    // SQLValueFunction (CURRENT_DATE, CURRENT_TIMESTAMP allowed; CURRENT_USER / SESSION_USER blocked)
    if (node.SQLValueFunction) {
      const op = String(node.SQLValueFunction.op ?? "");
      if (!ALLOWED_SQL_VALUE_FUNCTIONS.has(op)) {
        throw new Error(
          `PostgreSQL SQL value function '${op}' is not in the permitted allowlist.`
        );
      }
      return;
    }

    // FuncCall (scalar, aggregate, window, FILTER, aggregate ORDER BY, WITHIN GROUP)
    if (node.FuncCall) {
      const fc = node.FuncCall;
      const nameParts = (Array.isArray(fc.funcname) ? fc.funcname : [])
        .map((p: any) => p?.String?.sval)
        .filter((s: unknown): s is string => typeof s === "string")
        .map((s: string) => s.toLowerCase());

      if (nameParts.length === 0) {
        throw new Error("Unnamed PostgreSQL function call is forbidden.");
      }
      const funcName = nameParts[nameParts.length - 1];
      if (nameParts.length > 1) {
        const fnSchema = nameParts[0];
        const isAllowedPgGrammarSugar =
          nameParts.length === 2 &&
          fnSchema === "pg_catalog" &&
          PG_CATALOG_GRAMMAR_SUGARED_FUNCTIONS.has(funcName);

        if (!isAllowedPgGrammarSugar) {
          if (FORBIDDEN_PG_SCHEMAS.has(fnSchema) || fnSchema.startsWith("pg_")) {
            throw new Error(
              `Schema-qualified system function '${nameParts.join(".")}()' is forbidden.`
            );
          }
          if (!this.allowedSchemas.has(fnSchema)) {
            throw new Error(
              `Schema-qualified function '${nameParts.join(".")}()' is not permitted.`
            );
          }
        }
      }

      const isForbiddenPrefix = POSTGRES_FORBIDDEN_FUNCTION_PREFIXES.some(
        (prefix) => funcName.startsWith(prefix)
      );
      if (isForbiddenPrefix || !ALLOWED_FUNCTIONS_POSTGRES.has(funcName)) {
        throw new Error(
          `Function '${funcName}()' is not in the permitted PostgreSQL function allowlist.`
        );
      }
      state.functionsUsed.add(funcName);

      const args: any[] = Array.isArray(fc.args) ? fc.args : [];
      if (args.length > this.maxFunctionArgs) {
        throw new Error(
          `Function '${funcName}()' exceeds maximum argument count of ${this.maxFunctionArgs}.`
        );
      }

      if (fc.agg_star && funcName !== "count") {
        throw new Error(
          `Wildcard '*' argument is only permitted inside COUNT().`
        );
      }

      for (const arg of args) {
        this.validateExpr(
          arg,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      if (fc.agg_order) {
        this.validateExpr(
          fc.agg_order,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      if (fc.agg_filter) {
        this.validateExpr(
          fc.agg_filter,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      if (fc.over) {
        this.validateExpr(
          fc.over,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      if (fc.agg_within_group) {
        this.validateExpr(
          fc.agg_within_group,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      return;
    }

    // A_Expr (operators, LIKE, ILIKE, SIMILAR TO, JSON -> / ->>, regex ~ / ~*)
    if (node.A_Expr) {
      const ae = node.A_Expr;
      const kind = String(ae.kind ?? "");
      const opName = String(ae.name?.[0]?.String?.sval ?? "");

      if (kind === "AEXPR_SIMILAR") {
        throw new Error("Operator 'SIMILAR TO' is not permitted.");
      }

      if (DISALLOWED_PG_OPERATORS.has(opName)) {
        throw new Error(`Operator '${opName}' is not permitted.`);
      }

      if (
        kind === "AEXPR_LIKE" ||
        kind === "AEXPR_ILIKE" ||
        opName === "~~" ||
        opName === "!~~" ||
        opName === "~~*" ||
        opName === "!~~*"
      ) {
        state.functionsUsed.add("like");
        const patConst = ae.rexpr?.A_Const?.sval;
        if (!patConst || typeof patConst !== "object") {
          throw new Error(
            "LIKE/ILIKE pattern must be a static string literal to prevent dynamic pattern exhaustion."
          );
        }
        const patStr = String(patConst.sval ?? "");
        if (patStr.length > this.maxLikePatternLength) {
          throw new Error(
            `LIKE pattern exceeds maximum length of ${this.maxLikePatternLength} characters.`
          );
        }
      }

      if (ae.lexpr) {
        this.validateExpr(
          ae.lexpr,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      if (ae.rexpr) {
        this.validateExpr(
          ae.rexpr,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
      return;
    }

    // Generic exhaustive recursive walk for all remaining PG expression wrappers
    // (TypeCast, CaseExpr, CoalesceExpr, BoolExpr, NullTest, WindowDef, SortBy, ResTarget, etc.)
    for (const [key, val] of Object.entries(node)) {
      if (key === "location" || key === "TypeName") continue;
      if (val && typeof val === "object") {
        this.validateExpr(
          val,
          state,
          activeCtes,
          localBaseTables,
          nestingLevel
        );
      }
    }
  }
}
