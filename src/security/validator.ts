import pkg from "node-sql-parser";
const { Parser } = pkg;
import { TableMetadata, UserRole, ValidationResult } from "../types.js";
import { TABLE_METADATA } from "../database/seed.js";
import {
  ALLOWED_FUNCTIONS,
  ALLOWED_FUNCTIONS_POSTGRES,
  POSTGRES_FORBIDDEN_FUNCTION_PREFIXES,
  PII_COLUMNS,
  SQL_LIMITS,
  getAllowedTablesForRole,
  getAllowedTablesFromMap,
} from "./policy.js";

const DISALLOWED_CONTROL_CHARS_REGEX =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069\uFEFF]/;

const DISALLOWED_OPERATORS = new Set(["GLOB", "REGEXP", "MATCH", "->", "->>"]);

export type SQLDialect = "sqlite" | "postgresql";

export interface SQLValidatorOptions {
  dialect?: SQLDialect;
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
  extraAllowedViews?: string[];
  allowedSchemas?: string[];
  roleAllowedTables?: Record<UserRole, readonly string[]>;
  tableMetadata?: Record<string, TableMetadata>;
  piiColumns?: Set<string>;
  piiColumnsByTable?: Record<string, Set<string>>;
}

interface ValidationState {
  role: UserRole;
  allowedTables: Set<string>;
  tablesAccessed: Set<string>;
  columnsAccessed: Set<string>;
  functionsUsed: Set<string>;
  cteCount: number;
  compoundCount: number;
}

export class SQLValidator {
  private parser: any;
  public readonly dialect: SQLDialect;
  private maxRows: number;
  private defaultLimit: number;
  private maxSqlLength: number;
  private maxAstDepth: number;
  private maxCompoundSelects: number;
  private maxCtes: number;
  private maxJoins: number;
  private maxFunctionArgs: number;
  private maxLikePatternLength: number;
  private maxOffset: number;
  private extraAllowedViews: string[];
  private allowedSchemas: Set<string>;
  private roleAllowedTables?: Record<UserRole, readonly string[]>;
  private tableMetadata?: Record<string, TableMetadata>;
  private piiColumns: Set<string>;
  private piiColumnsByTable?: Record<string, Set<string>>;

  constructor(options: SQLValidatorOptions = {}) {
    this.parser = new Parser();
    this.dialect = options.dialect ?? "sqlite";
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
    this.extraAllowedViews = (options.extraAllowedViews ?? []).map((v) =>
      v.toLowerCase()
    );
    const defaultSchemas =
      this.dialect === "postgresql" ? ["public"] : ["main"];
    this.allowedSchemas = new Set(
      (options.allowedSchemas ?? defaultSchemas).map((s) => s.toLowerCase())
    );
    this.roleAllowedTables = options.roleAllowedTables;
    this.tableMetadata = options.tableMetadata;
    this.piiColumns = options.piiColumns ?? PII_COLUMNS;
    this.piiColumnsByTable = options.piiColumnsByTable;
  }

  /**
   * Scans tokens outside quotes (', ", `, [...]) for SQL comment markers (-- and /*).
   */
  public hasCommentTokens(sql: string): boolean {
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inBacktick = false;
    let inBracket = false;

    for (let i = 0; i < sql.length; i++) {
      const char = sql[i];
      const next = i + 1 < sql.length ? sql[i + 1] : "";

      if (char === "'" && !inDoubleQuote && !inBacktick && !inBracket) {
        if (inSingleQuote && next === "'") {
          i++;
          continue;
        }
        inSingleQuote = !inSingleQuote;
        continue;
      }
      if (char === '"' && !inSingleQuote && !inBacktick && !inBracket) {
        if (inDoubleQuote && next === '"') {
          i++;
          continue;
        }
        inDoubleQuote = !inDoubleQuote;
        continue;
      }
      if (char === "`" && !inSingleQuote && !inDoubleQuote && !inBracket) {
        if (inBacktick && next === "`") {
          i++;
          continue;
        }
        inBacktick = !inBacktick;
        continue;
      }
      if (
        char === "[" &&
        !inSingleQuote &&
        !inDoubleQuote &&
        !inBacktick &&
        !inBracket
      ) {
        inBracket = true;
        continue;
      }
      if (char === "]" && inBracket) {
        inBracket = false;
        continue;
      }

      if (!inSingleQuote && !inDoubleQuote && !inBacktick && !inBracket) {
        if (char === "-" && next === "-") {
          return true;
        }
        if (char === "/" && next === "*") {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Detects multiple statements separated by semicolons outside quotes.
   */
  public hasMultipleStatements(sql: string): boolean {
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inBacktick = false;
    let inBracket = false;
    let semicolonFound = false;

    for (let i = 0; i < sql.length; i++) {
      const char = sql[i];
      const next = i + 1 < sql.length ? sql[i + 1] : "";

      if (char === "'" && !inDoubleQuote && !inBacktick && !inBracket) {
        if (inSingleQuote && next === "'") {
          i++;
          continue;
        }
        inSingleQuote = !inSingleQuote;
        continue;
      }
      if (char === '"' && !inSingleQuote && !inBacktick && !inBracket) {
        if (inDoubleQuote && next === '"') {
          i++;
          continue;
        }
        inDoubleQuote = !inDoubleQuote;
        continue;
      }
      if (char === "`" && !inSingleQuote && !inDoubleQuote && !inBracket) {
        if (inBacktick && next === "`") {
          i++;
          continue;
        }
        inBacktick = !inBacktick;
        continue;
      }
      if (
        char === "[" &&
        !inSingleQuote &&
        !inDoubleQuote &&
        !inBacktick &&
        !inBracket
      ) {
        inBracket = true;
        continue;
      }
      if (char === "]" && inBracket) {
        inBracket = false;
        continue;
      }

      if (!inSingleQuote && !inDoubleQuote && !inBacktick && !inBracket) {
        if (char === ";") {
          semicolonFound = true;
        } else if (semicolonFound && char.trim() !== "") {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Strips quoted literals/identifiers so top-level keyword checks ignore string contents.
   */
  public stripQuotedSegments(sql: string): string {
    let out = "";
    let inSingle = false;
    let inDouble = false;
    let inBacktick = false;
    let inBracket = false;

    for (let i = 0; i < sql.length; i++) {
      const ch = sql[i];
      const next = i + 1 < sql.length ? sql[i + 1] : "";

      if (ch === "'" && !inDouble && !inBacktick && !inBracket) {
        if (inSingle && next === "'") {
          i++;
          continue;
        }
        inSingle = !inSingle;
        out += " ";
        continue;
      }
      if (ch === '"' && !inSingle && !inBacktick && !inBracket) {
        if (inDouble && next === '"') {
          i++;
          continue;
        }
        inDouble = !inDouble;
        out += " ";
        continue;
      }
      if (ch === "`" && !inSingle && !inDouble && !inBracket) {
        if (inBacktick && next === "`") {
          i++;
          continue;
        }
        inBacktick = !inBacktick;
        out += " ";
        continue;
      }
      if (ch === "[" && !inSingle && !inDouble && !inBacktick && !inBracket) {
        inBracket = true;
        out += " ";
        continue;
      }
      if (ch === "]" && inBracket) {
        inBracket = false;
        out += " ";
        continue;
      }

      out += !inSingle && !inDouble && !inBacktick && !inBracket ? ch : " ";
    }
    return out;
  }

  /**
   * Validates and normalizes an analytical SQL query locally in JavaScript.
   */
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
          "Authentication required: unauthenticated callers cannot validate or execute queries.",
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

    if (this.hasCommentTokens(trimmed)) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason:
          "SQL comments (-- or /* */) are forbidden to reduce comment-smuggling ambiguity.",
      };
    }

    if (this.hasMultipleStatements(trimmed)) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason:
          "Chained multiple SQL statements are strictly forbidden.",
      };
    }

    const unquotedSql = this.stripQuotedSegments(trimmed);
    if (/\bCROSS\s+JOIN\b/i.test(unquotedSql)) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason:
          "Unconstrained Cartesian CROSS JOIN is strictly prohibited to reduce compute exhaustion risk.",
      };
    }
    if (/\bNATURAL\s+(?:LEFT\s+|INNER\s+|OUTER\s+)?JOIN\b/i.test(unquotedSql)) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason:
          "NATURAL JOIN is prohibited; specify explicit join columns in an ON clause.",
      };
    }

    // Reject SQLite keywords that node-sql-parser may misparse or ignore
    const leadingKeywordMatch = trimmed.match(/^([a-z_]+)/i);
    const leadingKeyword = leadingKeywordMatch
      ? leadingKeywordMatch[1].toLowerCase()
      : "";
    if (leadingKeyword !== "select" && leadingKeyword !== "with") {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `Only SELECT statements are permitted. Statement keyword '${leadingKeyword.toUpperCase() || "UNKNOWN"}' is strictly forbidden.`,
      };
    }

    let ast: any;
    try {
      ast = this.parser.astify(trimmed, { database: this.dialect });
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `Syntax or parse error: ${err.message}`,
      };
    }

    if (Array.isArray(ast)) {
      if (ast.length !== 1) {
        return {
          valid: false,
          tablesAccessed: [],
          columnsAccessed: [],
          violationReason: "Multiple statement AST is strictly forbidden.",
        };
      }
      ast = ast[0];
    }

    if (!ast || ast.type !== "select") {
      const type = String(ast?.type || "unknown").toUpperCase();
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `Only SELECT statements are permitted. Statement type '${type}' is strictly forbidden.`,
      };
    }

    const state: ValidationState = {
      role,
      allowedTables: this.roleAllowedTables
        ? getAllowedTablesFromMap(
            role,
            this.roleAllowedTables,
            this.extraAllowedViews
          )
        : getAllowedTablesForRole(role, this.extraAllowedViews),
      tablesAccessed: new Set<string>(),
      columnsAccessed: new Set<string>(),
      functionsUsed: new Set<string>(),
      cteCount: 0,
      compoundCount: 0,
    };

    try {
      this.checkAstDepth(ast, 0);
      this.validateSelectNode(ast, state, new Set<string>(), 0);
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [...state.tablesAccessed],
        columnsAccessed: [...state.columnsAccessed],
        functionsUsed: [...state.functionsUsed],
        violationReason: err.message,
      };
    }

    // Clamp or inject LIMIT on the terminal node of the top-level compound chain
    let terminalSelect = ast;
    while (terminalSelect._next) {
      if (terminalSelect.limit && terminalSelect.limit.value?.length > 0) {
        return {
          valid: false,
          tablesAccessed: [...state.tablesAccessed],
          columnsAccessed: [...state.columnsAccessed],
          functionsUsed: [...state.functionsUsed],
          violationReason:
            "LIMIT clauses before UNION/INTERSECT/EXCEPT branches are invalid in SQLite.",
        };
      }
      terminalSelect = terminalSelect._next;
    }

    let limitApplied: number;
    try {
      limitApplied = this.enforceLimitClause(terminalSelect, true);
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [...state.tablesAccessed],
        columnsAccessed: [...state.columnsAccessed],
        functionsUsed: [...state.functionsUsed],
        violationReason: err.message,
      };
    }

    let sanitizedQuery: string;
    try {
      sanitizedQuery = this.parser.sqlify(ast, { database: this.dialect });
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [...state.tablesAccessed],
        columnsAccessed: [...state.columnsAccessed],
        functionsUsed: [...state.functionsUsed],
        violationReason: `Failed to serialize validated AST: ${err.message}`,
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

  private validateNonNegativeIntLiteral(node: any, label: string): number {
    if (
      !node ||
      node.type !== "number" ||
      !Number.isInteger(Number(node.value)) ||
      Number(node.value) < 0
    ) {
      throw new Error(`${label} value must be a non-negative integer literal.`);
    }
    return Number(node.value);
  }

  private enforceLimitClause(selectNode: any, injectDefault: boolean): number {
    const limitObj = selectNode.limit;
    const values =
      limitObj && Array.isArray(limitObj.value) ? limitObj.value : [];

    if (values.length === 0) {
      if (!injectDefault) {
        return this.defaultLimit;
      }
      selectNode.limit = {
        seperator: "",
        value: [{ type: "number", value: this.defaultLimit }],
      };
      return this.defaultLimit;
    }

    if (values.length === 1) {
      const parsedLimit = this.validateNonNegativeIntLiteral(
        values[0],
        "LIMIT"
      );
      if (parsedLimit > this.maxRows) {
        values[0].value = this.maxRows;
        return this.maxRows;
      }
      return parsedLimit;
    }

    if (values.length === 2) {
      const sep = String(limitObj.seperator || "").trim().toLowerCase();
      if (sep === ",") {
        // SQLite/MySQL syntax: LIMIT offset, count
        const parsedOffset = this.validateNonNegativeIntLiteral(
          values[0],
          "OFFSET"
        );
        const parsedCount = this.validateNonNegativeIntLiteral(
          values[1],
          "LIMIT"
        );
        if (parsedOffset > this.maxOffset) {
          throw new Error(
            `OFFSET value ${parsedOffset} exceeds maximum allowed offset of ${this.maxOffset}.`
          );
        }
        if (parsedCount > this.maxRows) {
          values[1].value = this.maxRows;
          return this.maxRows;
        }
        return parsedCount;
      }

      if (sep === "offset") {
        // Standard SQL syntax: LIMIT count OFFSET offset
        const parsedCount = this.validateNonNegativeIntLiteral(
          values[0],
          "LIMIT"
        );
        const parsedOffset = this.validateNonNegativeIntLiteral(
          values[1],
          "OFFSET"
        );
        if (parsedOffset > this.maxOffset) {
          throw new Error(
            `OFFSET value ${parsedOffset} exceeds maximum allowed offset of ${this.maxOffset}.`
          );
        }
        if (parsedCount > this.maxRows) {
          values[0].value = this.maxRows;
          return this.maxRows;
        }
        return parsedCount;
      }

      throw new Error(
        `Unsupported LIMIT/OFFSET clause separator '${limitObj.seperator}'.`
      );
    }

    throw new Error("Invalid LIMIT clause structure.");
  }

  private checkAstDepth(node: unknown, depth: number): void {
    if (depth > this.maxAstDepth) {
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

  private validateSelectNode(
    selectNode: any,
    state: ValidationState,
    outerCtes: Set<string>,
    nestingLevel: number
  ): void {
    if (!selectNode || selectNode.type !== "select") {
      const t = String(selectNode?.type || "unknown").toUpperCase();
      throw new Error(
        `Only SELECT statements are permitted. Nested statement type '${t}' is strictly forbidden.`
      );
    }

    if (
      selectNode.into &&
      (selectNode.into.expr || selectNode.into.position)
    ) {
      throw new Error("SELECT INTO statements are strictly forbidden.");
    }

    if (selectNode.for_update || selectNode.locking_read) {
      throw new Error("Locking SELECT clauses are strictly forbidden.");
    }

    const catalogMeta = this.tableMetadata ?? TABLE_METADATA;
    const activeCtes = new Set<string>(outerCtes);

    // 1. Validate WITH CTE definitions
    if (Array.isArray(selectNode.with) && selectNode.with.length > 0) {
      for (const cte of selectNode.with) {
        state.cteCount++;
        if (state.cteCount > this.maxCtes) {
          throw new Error(
            `Query exceeds maximum CTE count of ${this.maxCtes}.`
          );
        }

        const cteName = String(
          cte?.name?.value ?? cte?.name ?? ""
        ).toLowerCase();
        if (!cteName) {
          throw new Error("Invalid unnamed CTE definition.");
        }

        // Prevent CTE names from shadowing catalog or system tables
        if (
          catalogMeta[cteName] ||
          cteName.startsWith("sqlite_") ||
          this.extraAllowedViews.includes(cteName)
        ) {
          throw new Error(
            `CTE alias '${cteName}' cannot shadow catalog or SQLite system table names.`
          );
        }

        const cteAst = cte?.stmt?.ast ?? cte?.stmt;
        if (!cteAst || cteAst.type !== "select") {
          throw new Error(
            `CTE '${cteName}' must contain a valid SELECT query.`
          );
        }

        // Add CTE name to scope before recursion so WITH RECURSIVE self-references validate cleanly
        activeCtes.add(cteName);
        this.validateSelectNode(cteAst, state, activeCtes, nestingLevel + 1);
      }
    }

    // 2. Validate FROM relations and joins
    const localBaseTables: string[] = [];
    const seenRelations = new Set<string>();
    if (Array.isArray(selectNode.from)) {
      if (selectNode.from.length - 1 > this.maxJoins) {
        throw new Error(
          `Query exceeds maximum join count of ${this.maxJoins}.`
        );
      }

      for (let i = 0; i < selectNode.from.length; i++) {
        const item = selectNode.from[i];

        if (item.db) {
          const schemaName = String(item.db).toLowerCase();
          if (
            schemaName.startsWith("sqlite_") ||
            schemaName.startsWith("pg_") ||
            schemaName === "information_schema" ||
            !this.allowedSchemas.has(schemaName)
          ) {
            throw new Error(
              `External or attached database qualifier '${item.db}' is forbidden.`
            );
          }
        }

        if (item.expr?.ast) {
          // Derived-table subquery in FROM
          this.validateSelectNode(
            item.expr.ast,
            state,
            activeCtes,
            nestingLevel + 1
          );
        } else if (item.expr && !item.table) {
          // Table-valued function in FROM (e.g., pragma_table_info or json_each)
          throw new Error(
            "Table-valued functions in FROM clauses are forbidden."
          );
        } else if (item.table) {
          const tableName = String(item.table).toLowerCase();
          if (!activeCtes.has(tableName)) {
            state.tablesAccessed.add(tableName);
            localBaseTables.push(tableName);

            if (tableName.startsWith("sqlite_")) {
              throw new Error(
                `Access denied: SQLite system catalog table '${tableName}' is forbidden.`
              );
            }

            if (
              !catalogMeta[tableName] &&
              !this.extraAllowedViews.includes(tableName)
            ) {
              throw new Error(
                `Access denied: table '${tableName}' is not in the authorized catalog.`
              );
            }

            if (!state.allowedTables.has(tableName)) {
              throw new Error(
                `Access denied: table '${tableName}' requires admin privileges.`
              );
            }
          }
        }

        const currentRelation = String(
          item.as || item.table || ""
        ).toLowerCase();

        // Join constraints for relation index >= 1
        if (i >= 1) {
          const joinType = String(item.join || "").toUpperCase().trim();
          if (!joinType) {
            throw new Error(
              "Implicit comma-separated Cartesian joins are prohibited; use an explicit JOIN with an ON clause."
            );
          }
          if (joinType.includes("CROSS")) {
            throw new Error(
              "Unconstrained Cartesian CROSS JOIN is strictly prohibited to reduce compute exhaustion risk."
            );
          }
          if (joinType.includes("NATURAL")) {
            throw new Error(
              "NATURAL JOIN is prohibited; specify explicit join columns in an ON clause."
            );
          }
          if (
            !item.on &&
            (!Array.isArray(item.using) || item.using.length === 0)
          ) {
            throw new Error(
              "JOIN clauses must specify an explicit ON or USING condition."
            );
          }
          if (item.on) {
            this.validateJoinCondition(
              item.on,
              seenRelations,
              currentRelation
            );
            this.validateExpression(item.on, state, activeCtes, nestingLevel);
          }
          if (Array.isArray(item.using)) {
            for (const u of item.using) {
              const colName = String(u?.value ?? u ?? "").toLowerCase();
              if (colName) {
                this.checkColumnPermission(colName, state);
              }
            }
          }
        }

        if (currentRelation) {
          seenRelations.add(currentRelation);
        }
      }
    }

    // 2.5 Validate DISTINCT / DISTINCT ON expressions (PostgreSQL)
    if (selectNode.distinct && typeof selectNode.distinct === "object") {
      this.validateExpression(
        selectNode.distinct,
        state,
        activeCtes,
        nestingLevel
      );
    }

    // 3. Validate SELECT projection columns & wildcards
    let hasWildcard = false;
    if (selectNode.columns === "*") {
      hasWildcard = true;
    } else if (Array.isArray(selectNode.columns)) {
      for (const col of selectNode.columns) {
        if (!col?.expr) continue;
        if (
          col.expr.type === "column_ref" &&
          (col.expr.column === "*" || col.expr.column?.expr?.value === "*")
        ) {
          hasWildcard = true;
        } else if (col.expr.type === "star") {
          hasWildcard = true;
        } else {
          this.validateExpression(col.expr, state, activeCtes, nestingLevel);
        }
      }
    }

    if (hasWildcard && state.role !== "admin") {
      // Check both local tables and any base tables referenced in this query
      const candidateTables = new Set<string>([
        ...localBaseTables,
        ...state.tablesAccessed,
      ]);
      for (const table of candidateTables) {
        const meta = catalogMeta[table];
        if (meta && meta.columns.some((c) => c.isPII)) {
          throw new Error(
            `Wildcard SELECT * on table '${table}' containing PII columns is prohibited for role '${state.role}'. Explicitly select non-sensitive columns.`
          );
        }
        if (this.extraAllowedViews.includes(table)) {
          throw new Error(
            `Wildcard SELECT * on view '${table}' is prohibited for role '${state.role}'. Explicitly select permitted columns.`
          );
        }
      }
      // Even on a CTE (`WITH c AS (...) SELECT * FROM c`), require explicit columns for non-admin if no base table was directly local
      if (localBaseTables.length === 0) {
        throw new Error(
          `Wildcard SELECT * on derived relations or CTEs is prohibited for role '${state.role}'. Explicitly list columns.`
        );
      }
    }

    // 4. Validate WHERE, GROUP BY, HAVING, WINDOW, QUALIFY, ORDER BY, nested LIMIT
    if (selectNode.where) {
      this.validateExpression(
        selectNode.where,
        state,
        activeCtes,
        nestingLevel
      );
    }

    if (selectNode.groupby) {
      const groupItems = Array.isArray(selectNode.groupby)
        ? selectNode.groupby
        : Array.isArray(selectNode.groupby.columns)
          ? selectNode.groupby.columns
          : [selectNode.groupby];
      for (const g of groupItems) {
        if (g) this.validateExpression(g, state, activeCtes, nestingLevel);
      }
    }

    if (selectNode.having) {
      this.validateExpression(
        selectNode.having,
        state,
        activeCtes,
        nestingLevel
      );
    }

    if (selectNode.window) {
      this.validateExpression(
        selectNode.window,
        state,
        activeCtes,
        nestingLevel
      );
    }

    if (selectNode.qualify) {
      this.validateExpression(
        selectNode.qualify,
        state,
        activeCtes,
        nestingLevel
      );
    }

    if (Array.isArray(selectNode.orderby)) {
      for (const ord of selectNode.orderby) {
        if (ord?.expr) {
          this.validateExpression(ord.expr, state, activeCtes, nestingLevel);
        }
      }
    }

    if (nestingLevel > 0 && selectNode.limit?.value?.length > 0) {
      this.enforceLimitClause(selectNode, false);
    }

    // 5. Validate compound SELECT chain (UNION / UNION ALL / INTERSECT / EXCEPT)
    if (selectNode._next) {
      state.compoundCount++;
      if (state.compoundCount >= this.maxCompoundSelects) {
        throw new Error(
          `Query exceeds maximum compound SELECT count of ${this.maxCompoundSelects}.`
        );
      }
      this.validateSelectNode(
        selectNode._next,
        state,
        activeCtes,
        nestingLevel + 1
      );
    }
  }

  private validateJoinCondition(
    onExpr: any,
    seenRelations: Set<string>,
    currentRelation: string
  ): void {
    if (!this.containsColumnRef(onExpr)) {
      throw new Error(
        "Degenerate tautological or constant join condition (e.g., ON 1=1 or ON true) is strictly forbidden."
      );
    }

    if (this.hasTautologicalBranch(onExpr)) {
      throw new Error(
        "Degenerate tautological join condition (e.g., ON 1=1) is strictly forbidden."
      );
    }

    if (
      !this.hasCrossRelationJoinPredicate(
        onExpr,
        seenRelations,
        currentRelation
      )
    ) {
      throw new Error(
        "Degenerate tautological or non-correlating join condition is strictly forbidden; ON clause must compare columns across the joined relations."
      );
    }
  }

  private stripParenMetadata(node: any): any {
    if (!node || typeof node !== "object") return node;
    if (Array.isArray(node)) {
      return node.map((item) => this.stripParenMetadata(item));
    }
    const cleaned: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(node)) {
      if (key === "parentheses") continue;
      cleaned[key] = this.stripParenMetadata(val);
    }
    return cleaned;
  }

  private collectColumnRefs(
    node: any,
    out: Array<{ table: string | null; column: string }> = []
  ): Array<{ table: string | null; column: string }> {
    if (!node || typeof node !== "object") return out;
    if (Array.isArray(node)) {
      for (const item of node) {
        this.collectColumnRefs(item, out);
      }
      return out;
    }
    // Do not treat column refs hidden inside a scalar subquery as outer join columns
    if (node.ast || node.type === "select") {
      return out;
    }
    if (node.type === "column_ref") {
      const col = this.extractColumnName(node.column).toLowerCase();
      const tbl =
        typeof node.table === "string" && node.table.length > 0
          ? node.table.toLowerCase()
          : null;
      if (col) {
        out.push({ table: tbl, column: col });
      }
      return out;
    }
    for (const val of Object.values(node)) {
      if (val && typeof val === "object") {
        this.collectColumnRefs(val, out);
      }
    }
    return out;
  }

  private hasCrossRelationJoinPredicate(
    node: any,
    seenRelations: Set<string>,
    currentRelation: string
  ): boolean {
    if (!node || typeof node !== "object") return false;
    if (node.type === "expr" && node.expr) {
      return this.hasCrossRelationJoinPredicate(
        node.expr,
        seenRelations,
        currentRelation
      );
    }
    if (node.type !== "binary_expr") return false;

    const op = String(node.operator || "").toUpperCase();
    if (op === "AND") {
      return (
        this.hasCrossRelationJoinPredicate(
          node.left,
          seenRelations,
          currentRelation
        ) ||
        this.hasCrossRelationJoinPredicate(
          node.right,
          seenRelations,
          currentRelation
        )
      );
    }
    if (op === "OR") {
      return (
        this.hasCrossRelationJoinPredicate(
          node.left,
          seenRelations,
          currentRelation
        ) &&
        this.hasCrossRelationJoinPredicate(
          node.right,
          seenRelations,
          currentRelation
        )
      );
    }

    const ALLOWED_JOIN_COMPARATORS = new Set(["=", "==", "<", "<=", ">", ">="]);
    if (!ALLOWED_JOIN_COMPARATORS.has(op)) {
      return false;
    }

    const leftRefs = this.collectColumnRefs(node.left);
    const rightRefs = this.collectColumnRefs(node.right);
    if (leftRefs.length === 0 || rightRefs.length === 0) {
      return false;
    }

    const normLeft = JSON.stringify(this.stripParenMetadata(node.left));
    const normRight = JSON.stringify(this.stripParenMetadata(node.right));
    if (normLeft === normRight) {
      return false;
    }

    const leftTables = new Set(
      leftRefs.map((r) => r.table).filter((t): t is string => t !== null)
    );
    const rightTables = new Set(
      rightRefs.map((r) => r.table).filter((t): t is string => t !== null)
    );

    // When both sides carry table/alias qualifiers, require cross-relation linkage
    if (leftTables.size > 0 && rightTables.size > 0) {
      for (const lt of leftTables) {
        for (const rt of rightTables) {
          if (lt === rt) continue;
          if (!currentRelation || seenRelations.size === 0) {
            return true;
          }
          if (
            (lt === currentRelation && seenRelations.has(rt)) ||
            (rt === currentRelation && seenRelations.has(lt))
          ) {
            return true;
          }
        }
      }
      return false;
    }

    // Fallback for unqualified column names (e.g. ON id = customer_id):
    // require at least two distinct column names across left and right sides
    const leftCols = new Set(leftRefs.map((r) => r.column));
    const rightCols = new Set(rightRefs.map((r) => r.column));
    for (const lc of leftCols) {
      for (const rc of rightCols) {
        if (lc !== rc) {
          return true;
        }
      }
    }
    return false;
  }

  private containsColumnRef(node: any): boolean {
    if (!node || typeof node !== "object") return false;
    if (node.type === "column_ref") return true;
    if (Array.isArray(node)) {
      return node.some((item) => this.containsColumnRef(item));
    }
    return Object.values(node).some(
      (v) => typeof v === "object" && v !== null && this.containsColumnRef(v)
    );
  }

  private hasTautologicalBranch(node: any): boolean {
    if (!node || typeof node !== "object") return false;

    if (
      node.type === "bool" ||
      node.type === "number" ||
      node.type === "single_quote_string"
    ) {
      return true;
    }

    if (node.type === "binary_expr") {
      const op = String(node.operator || "").toUpperCase();
      if (op === "OR") {
        return (
          this.hasTautologicalBranch(node.left) ||
          this.hasTautologicalBranch(node.right)
        );
      }
      if (op === "AND") {
        return (
          !this.containsColumnRef(node) ||
          (this.isSelfEqualOrConstantComparison(node.left) &&
            this.isSelfEqualOrConstantComparison(node.right))
        );
      }
      return this.isSelfEqualOrConstantComparison(node);
    }

    return false;
  }

  private isSelfEqualOrConstantComparison(node: any): boolean {
    if (!node || typeof node !== "object") return false;
    if (!this.containsColumnRef(node)) return true;
    if (node.type === "binary_expr") {
      const op = String(node.operator || "").toUpperCase();
      if (
        op === "=" ||
        op === "==" ||
        op === "IS" ||
        op === ">=" ||
        op === "<="
      ) {
        if (
          JSON.stringify(this.stripParenMetadata(node.left)) ===
          JSON.stringify(this.stripParenMetadata(node.right))
        ) {
          return true;
        }
      }
    }
    return false;
  }

  private isRestrictedPiiColumn(normalized: string, state: ValidationState): boolean {
    if (this.piiColumns.has(normalized)) return true;
    if (this.piiColumnsByTable) {
      for (const tbl of state.tablesAccessed) {
        if (this.piiColumnsByTable[tbl]?.has(normalized)) {
          return true;
        }
      }
    }
    return false;
  }

  private checkColumnPermission(colName: string, state: ValidationState): void {
    const normalized = colName.toLowerCase();
    if (!normalized || normalized === "*") return;
    state.columnsAccessed.add(normalized);
    if (
      state.role !== "admin" &&
      this.isRestrictedPiiColumn(normalized, state)
    ) {
      throw new Error(
        `Access denied: column '${normalized}' contains sensitive PII and requires admin privileges.`
      );
    }
  }

  private extractColumnName(colField: any): string {
    if (typeof colField === "string") return colField;
    if (colField && typeof colField === "object") {
      if (typeof colField.expr?.value === "string") return colField.expr.value;
      if (typeof colField.value === "string") return colField.value;
    }
    return "";
  }

  private extractFunctionName(node: any): string {
    if (typeof node.name === "string") {
      return node.name.toLowerCase();
    }
    if (
      node.name &&
      Array.isArray(node.name.name) &&
      node.name.name[0]?.value
    ) {
      return String(node.name.name[0].value).toLowerCase();
    }
    if (node.name && typeof node.name === "object" && node.name.value) {
      return String(node.name.value).toLowerCase();
    }
    return "";
  }

  private validateExpression(
    node: any,
    state: ValidationState,
    activeCtes: Set<string>,
    nestingLevel: number
  ): void {
    if (!node || typeof node !== "object") return;

    if (Array.isArray(node)) {
      for (const item of node) {
        this.validateExpression(item, state, activeCtes, nestingLevel);
      }
      return;
    }

    // Subquery inside scalar, IN (...), or EXISTS (...)
    if (node.ast && typeof node.ast === "object") {
      this.validateSelectNode(node.ast, state, activeCtes, nestingLevel + 1);
      return;
    }

    if (node.type === "select") {
      this.validateSelectNode(node, state, activeCtes, nestingLevel + 1);
      return;
    }

    if (node.type === "column_ref") {
      const colName = this.extractColumnName(node.column).toLowerCase();
      if (colName === "*") {
        if (state.role !== "admin") {
          throw new Error(
            `Wildcard column reference '*' inside expressions is prohibited for role '${state.role}'.`
          );
        }
      } else if (colName) {
        this.checkColumnPermission(colName, state);
      }
      return;
    }

    if (node.type === "function" || node.type === "aggr_func") {
      const funcName = this.extractFunctionName(node);
      const argValues = Array.isArray(node.args?.value)
        ? node.args.value
        : node.args?.expr
          ? [node.args.expr]
          : [];

      // EXISTS subquery operator is represented as a function node in node-sql-parser
      if (funcName === "exists") {
        for (const arg of argValues) {
          this.validateExpression(arg, state, activeCtes, nestingLevel);
        }
        return;
      }

      if (this.dialect === "postgresql") {
        const isForbiddenPrefix = POSTGRES_FORBIDDEN_FUNCTION_PREFIXES.some(
          (prefix) => funcName.startsWith(prefix)
        );
        if (isForbiddenPrefix || !ALLOWED_FUNCTIONS_POSTGRES.has(funcName)) {
          throw new Error(
            `Function '${funcName || "unknown"}()' is not in the permitted PostgreSQL function allowlist.`
          );
        }
      } else {
        if (!funcName || !ALLOWED_FUNCTIONS.has(funcName)) {
          throw new Error(
            `Function '${funcName || "unknown"}()' is not in the permitted SQLite function allowlist.`
          );
        }
      }
      state.functionsUsed.add(funcName);

      if (
        (funcName === "coalesce" ||
          funcName === "ifnull" ||
          funcName === "nullif") &&
        argValues.length < 2
      ) {
        throw new Error(
          `Function '${funcName}()' requires at least 2 arguments.`
        );
      }

      // Check argument count bound
      if (argValues.length > this.maxFunctionArgs) {
        throw new Error(
          `Function '${funcName}()' exceeds maximum argument count of ${this.maxFunctionArgs}.`
        );
      }

      if (funcName === "like" && argValues.length >= 2) {
        const patArg = argValues[0];
        if (
          patArg?.type !== "single_quote_string" &&
          patArg?.type !== "string"
        ) {
          throw new Error(
            "LIKE pattern must be a static string literal to prevent dynamic pattern exhaustion."
          );
        }
        if (
          typeof patArg?.value === "string" &&
          patArg.value.length > this.maxLikePatternLength
        ) {
          throw new Error(
            `LIKE pattern exceeds maximum length of ${this.maxLikePatternLength} characters.`
          );
        }
      }

      for (const arg of argValues) {
        // Allow COUNT(*) star inside aggregate COUNT only
        if (funcName === "count" && arg?.type === "star") {
          continue;
        }
        this.validateExpression(arg, state, activeCtes, nestingLevel);
      }

      // Walk aggregate ORDER BY (e.g. COUNT(name ORDER BY col)), FILTER (WHERE ...),
      // WITHIN GROUP (ORDER BY ...), and inline OVER (...) clauses.
      if (node.args?.orderby) {
        this.validateExpression(
          node.args.orderby,
          state,
          activeCtes,
          nestingLevel
        );
      }

      if (node.filter) {
        this.validateExpression(node.filter, state, activeCtes, nestingLevel);
      }

      if (node.within_group_orderby) {
        this.validateExpression(
          node.within_group_orderby,
          state,
          activeCtes,
          nestingLevel
        );
      }

      if (node.over) {
        this.validateExpression(node.over, state, activeCtes, nestingLevel);
      }
      return;
    }

    if (node.type === "binary_expr") {
      const op = String(node.operator || "").toUpperCase();
      if (DISALLOWED_OPERATORS.has(op)) {
        throw new Error(`Operator '${op}' is not permitted.`);
      }
      if (
        op === "LIKE" ||
        op === "NOT LIKE" ||
        op === "ILIKE" ||
        op === "NOT ILIKE"
      ) {
        state.functionsUsed.add("like");
        const patNode = node.right;
        if (
          patNode?.type !== "single_quote_string" &&
          patNode?.type !== "string"
        ) {
          throw new Error(
            "LIKE pattern must be a static string literal to prevent dynamic pattern exhaustion."
          );
        }
        const pat = patNode?.value;
        if (
          typeof pat === "string" &&
          pat.length > this.maxLikePatternLength
        ) {
          throw new Error(
            `LIKE pattern exceeds maximum length of ${this.maxLikePatternLength} characters.`
          );
        }
      }
      this.validateExpression(node.left, state, activeCtes, nestingLevel);
      this.validateExpression(node.right, state, activeCtes, nestingLevel);
      return;
    }

    for (const [key, val] of Object.entries(node)) {
      if (key === "target") continue;
      if (val && typeof val === "object") {
        this.validateExpression(val, state, activeCtes, nestingLevel);
      }
    }
  }
}

export const sqlValidator = new SQLValidator();
