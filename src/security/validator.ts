import pkg from "node-sql-parser";
const { Parser } = pkg;
import { UserRole, ValidationResult } from "../types.js";
import { TABLE_METADATA } from "../database/seed.js";
import {
  ALLOWED_FUNCTIONS,
  ALLOWED_FUNCTIONS_POSTGRES,
  POSTGRES_FORBIDDEN_FUNCTION_PREFIXES,
  PII_COLUMNS,
  SQL_LIMITS,
  getAllowedTablesForRole,
} from "./policy.js";

const DISALLOWED_CONTROL_CHARS_REGEX =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069\uFEFF]/;

const DISALLOWED_OPERATORS = new Set(["GLOB", "REGEXP", "MATCH"]);

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
  extraAllowedViews?: string[];
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
  private extraAllowedViews: string[];

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
    this.extraAllowedViews = (options.extraAllowedViews ?? []).map((v) =>
      v.toLowerCase()
    );
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
  private stripQuotedSegments(sql: string): string {
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
      allowedTables: getAllowedTablesForRole(role, this.extraAllowedViews),
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

    let limitApplied = this.defaultLimit;
    if (
      terminalSelect.limit &&
      Array.isArray(terminalSelect.limit.value) &&
      terminalSelect.limit.value.length > 0
    ) {
      const limitNode = terminalSelect.limit.value[0];
      if (limitNode.type !== "number" || !Number.isInteger(Number(limitNode.value)) || Number(limitNode.value) < 0) {
        return {
          valid: false,
          tablesAccessed: [...state.tablesAccessed],
          columnsAccessed: [...state.columnsAccessed],
          functionsUsed: [...state.functionsUsed],
          violationReason: "LIMIT value must be a non-negative integer literal.",
        };
      }
      const parsedLimit = Number(limitNode.value);
      if (parsedLimit > this.maxRows) {
        terminalSelect.limit.value[0].value = this.maxRows;
        limitApplied = this.maxRows;
      } else {
        limitApplied = parsedLimit;
      }
    } else {
      terminalSelect.limit = {
        seperator: "",
        value: [{ type: "number", value: this.defaultLimit }],
      };
      limitApplied = this.defaultLimit;
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
          TABLE_METADATA[cteName] ||
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
    if (Array.isArray(selectNode.from)) {
      if (selectNode.from.length - 1 > this.maxJoins) {
        throw new Error(
          `Query exceeds maximum join count of ${this.maxJoins}.`
        );
      }

      for (let i = 0; i < selectNode.from.length; i++) {
        const item = selectNode.from[i];

        if (item.db && String(item.db).toLowerCase() !== "main") {
          throw new Error(
            `External or attached database qualifier '${item.db}' is forbidden.`
          );
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
              !TABLE_METADATA[tableName] &&
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
          if (!item.on && (!Array.isArray(item.using) || item.using.length === 0)) {
            throw new Error(
              "JOIN clauses must specify an explicit ON or USING condition."
            );
          }
          if (item.on) {
            this.validateJoinCondition(item.on);
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
      }
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
        const meta = TABLE_METADATA[table];
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

    // 4. Validate WHERE, GROUP BY, HAVING, ORDER BY, WINDOW
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

    if (Array.isArray(selectNode.orderby)) {
      for (const ord of selectNode.orderby) {
        if (ord?.expr) {
          this.validateExpression(ord.expr, state, activeCtes, nestingLevel);
        }
      }
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

  private validateJoinCondition(onExpr: any): void {
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

    if (node.type === "bool" || node.type === "number" || node.type === "single_quote_string") {
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
      if (op === "=" || op === "==" || op === "IS" || op === ">=" || op === "<=") {
        if (JSON.stringify(node.left) === JSON.stringify(node.right)) {
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
    if (state.role !== "admin" && PII_COLUMNS.has(normalized)) {
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
      if (op === "LIKE" || op === "NOT LIKE") {
        state.functionsUsed.add("like");
        const pat = node.right?.value;
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
