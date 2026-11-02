import pkg from "node-sql-parser";
const { Parser } = pkg;
import { UserRole, ValidationResult } from "../types.js";
import { TABLE_METADATA } from "../database/seed.js";

const PII_COLUMNS = new Set([
  "billing_email",
  "stripe_customer_id",
  "webhook_secret",
  "client_ip",
]);

const ADMIN_ONLY_TABLES = new Set(["security_incidents", "api_keys"]);

const FORBIDDEN_FUNCTIONS = new Set([
  "read_csv",
  "read_csv_auto",
  "read_parquet",
  "parquet_scan",
  "glob",
  "load_extension",
  "eval",
  "sleep",
  "repeat",
  "st_read",
]);

export class SQLValidator {
  private parser: any;
  private maxRows: number;
  private defaultLimit: number;

  constructor(options: { maxRows?: number; defaultLimit?: number } = {}) {
    this.parser = new Parser();
    this.maxRows = options.maxRows ?? 1000;
    this.defaultLimit = options.defaultLimit ?? 100;
  }

  /**
   * Scan tokens outside quotes for forbidden comment markers (-- and /*).
   */
  public hasCommentTokens(sql: string): boolean {
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inBacktick = false;

    for (let i = 0; i < sql.length; i++) {
      const char = sql[i];
      const next = i + 1 < sql.length ? sql[i + 1] : "";

      if (char === "'" && !inDoubleQuote && !inBacktick) {
        if (inSingleQuote && next === "'") {
          i++; // escaped single quote
          continue;
        }
        inSingleQuote = !inSingleQuote;
        continue;
      }
      if (char === '"' && !inSingleQuote && !inBacktick) {
        if (inDoubleQuote && next === '"') {
          i++; // escaped double quote
          continue;
        }
        inDoubleQuote = !inDoubleQuote;
        continue;
      }
      if (char === "`" && !inSingleQuote && !inDoubleQuote) {
        inBacktick = !inBacktick;
        continue;
      }

      if (!inSingleQuote && !inDoubleQuote && !inBacktick) {
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
   * Detect multiple statements separated by semicolons outside quotes.
   */
  public hasMultipleStatements(sql: string): boolean {
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inBacktick = false;
    let semicolonFound = false;

    for (let i = 0; i < sql.length; i++) {
      const char = sql[i];
      const next = i + 1 < sql.length ? sql[i + 1] : "";

      if (char === "'" && !inDoubleQuote && !inBacktick) {
        if (inSingleQuote && next === "'") {
          i++;
          continue;
        }
        inSingleQuote = !inSingleQuote;
        continue;
      }
      if (char === '"' && !inSingleQuote && !inBacktick) {
        if (inDoubleQuote && next === '"') {
          i++;
          continue;
        }
        inDoubleQuote = !inDoubleQuote;
        continue;
      }
      if (char === "`" && !inSingleQuote && !inDoubleQuote) {
        inBacktick = !inBacktick;
        continue;
      }

      if (!inSingleQuote && !inDoubleQuote && !inBacktick) {
        if (char === ";") {
          semicolonFound = true;
        } else if (semicolonFound && char.trim() !== "") {
          return true; // Characters after semicolon
        }
      }
    }
    return false;
  }

  /**
   * Validates and sanitizes an analytical SQL query with zero token cost.
   */
  public validate(
    query: string,
    role: UserRole = "public_viewer"
  ): ValidationResult {
    const trimmed = query.trim();
    if (!trimmed) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: "Query cannot be empty",
      };
    }

    // 1. Scan for comments
    if (this.hasCommentTokens(trimmed)) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason:
          "SQL comments (-- or /* */) are forbidden to prevent comment smuggling payloads.",
      };
    }

    // 2. Scan for multi-statement execution
    if (this.hasMultipleStatements(trimmed)) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: "Chained multiple SQL statements are strictly forbidden.",
      };
    }

    // 3. Parse AST
    let ast: any;
    try {
      ast = this.parser.astify(trimmed);
    } catch (err: any) {
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `Syntax or parse error: ${err.message}`,
      };
    }

    if (Array.isArray(ast)) {
      if (ast.length > 1) {
        return {
          valid: false,
          tablesAccessed: [],
          columnsAccessed: [],
          violationReason: "Multiple statement AST is strictly forbidden.",
        };
      }
      ast = ast[0];
    }

    // 4. Validate statement type: SELECT ONLY
    if (!ast || ast.type !== "select") {
      const type = ast?.type || "unknown";
      return {
        valid: false,
        tablesAccessed: [],
        columnsAccessed: [],
        violationReason: `Only SELECT statements are permitted. Mutating statement type '${type.toUpperCase()}' is strictly forbidden.`,
      };
    }

    // 5. Extract tables and check permissions
    const tablesAccessed: string[] = [];
    if (ast.from && Array.isArray(ast.from)) {
      for (const item of ast.from) {
        if (item.table) {
          const tableName = item.table.toLowerCase();
          tablesAccessed.push(tableName);

          // Check if table exists in catalog
          if (
            !TABLE_METADATA[tableName] &&
            tableName !== "sqlite_master" &&
            tableName !== "sqlite_schema"
          ) {
            return {
              valid: false,
              tablesAccessed,
              columnsAccessed: [],
              violationReason: `Access denied: table '${tableName}' is not in the authorized catalog.`,
            };
          }

          // Check role restrictions
          if (role !== "admin" && ADMIN_ONLY_TABLES.has(tableName)) {
            return {
              valid: false,
              tablesAccessed,
              columnsAccessed: [],
              violationReason: `Access denied: table '${tableName}' requires admin privileges.`,
            };
          }
        }
      }
    }

    // 6. Check joins and Cartesian products
    if (ast.from && Array.isArray(ast.from) && ast.from.length > 1) {
      for (let i = 1; i < ast.from.length; i++) {
        const joinItem = ast.from[i];
        if (joinItem.join && joinItem.join.toUpperCase() === "CROSS JOIN") {
          return {
            valid: false,
            tablesAccessed,
            columnsAccessed: [],
            violationReason:
              "Unconstrained Cartesian CROSS JOIN is strictly prohibited to prevent compute exhaustion.",
          };
        }
        if (joinItem.on) {
          // Check for tautological join condition like 1=1 or true
          const onExpr = joinItem.on;
          if (
            onExpr.type === "binary_expr" &&
            onExpr.operator === "=" &&
            JSON.stringify(onExpr.left) === JSON.stringify(onExpr.right)
          ) {
            return {
              valid: false,
              tablesAccessed,
              columnsAccessed: [],
              violationReason:
                "Degenerate tautological join condition (e.g., ON 1=1) is strictly forbidden.",
            };
          }
        }
      }
    }

    // 7. Check columns, PII, and function calls
    const columnsAccessed: string[] = [];
    let hasWildcard = false;

    if (ast.columns && Array.isArray(ast.columns)) {
      for (const col of ast.columns) {
        if (col.expr) {
          try {
            this.checkForbiddenFunctions(col.expr);
          } catch (err: any) {
            return {
              valid: false,
              tablesAccessed,
              columnsAccessed,
              violationReason: err.message,
            };
          }

          if (col.expr.type === "column_ref") {
            const colName = (col.expr.column || "").toLowerCase();
            if (colName === "*") {
              hasWildcard = true;
            } else if (colName) {
              columnsAccessed.push(colName);
              if (role !== "admin" && PII_COLUMNS.has(colName)) {
                return {
                  valid: false,
                  tablesAccessed,
                  columnsAccessed,
                  violationReason: `Access denied: column '${colName}' contains sensitive PII and requires admin privileges.`,
                };
              }
            }
          }
        }
      }
    }

    // If non-admin requests wildcard on table with PII
    if (role !== "admin" && hasWildcard) {
      for (const table of tablesAccessed) {
        const meta = TABLE_METADATA[table];
        if (meta && meta.columns.some((c) => c.isPII)) {
          return {
            valid: false,
            tablesAccessed,
            columnsAccessed,
            violationReason: `Wildcard SELECT * on table '${table}' containing PII columns is prohibited for role '${role}'. Explicitly select non-sensitive columns.`,
          };
        }
      }
    }

    // Also check functions in WHERE clause
    if (ast.where) {
      try {
        this.checkForbiddenFunctions(ast.where);
      } catch (err: any) {
        return {
          valid: false,
          tablesAccessed,
          columnsAccessed,
          violationReason: err.message,
        };
      }
    }

    // 8. Clamp or inject LIMIT
    let limitApplied = this.defaultLimit;
    if (ast.limit && ast.limit.value && ast.limit.value.length > 0) {
      const parsedLimit = Number(ast.limit.value[0].value);
      if (!isNaN(parsedLimit)) {
        if (parsedLimit > this.maxRows) {
          ast.limit.value[0].value = this.maxRows;
          limitApplied = this.maxRows;
        } else {
          limitApplied = parsedLimit;
        }
      }
    } else {
      ast.limit = {
        seperator: "",
        value: [{ type: "number", value: this.defaultLimit }],
      };
      limitApplied = this.defaultLimit;
    }

    // 9. SQLify sanitized AST
    let sanitizedQuery = "";
    try {
      sanitizedQuery = this.parser.sqlify(ast);
    } catch {
      sanitizedQuery = trimmed;
    }

    return {
      valid: true,
      sanitizedQuery,
      astType: "select",
      tablesAccessed,
      columnsAccessed,
      limitInjected: limitApplied,
    };
  }

  private checkForbiddenFunctions(node: any): void {
    if (!node || typeof node !== "object") return;

    if (node.type === "function") {
      let funcName = "";
      if (typeof node.name === "string") {
        funcName = node.name.toLowerCase();
      } else if (node.name && Array.isArray(node.name.name) && node.name.name[0]?.value) {
        funcName = String(node.name.name[0].value).toLowerCase();
      } else if (node.name && typeof node.name === "object") {
        funcName = String(node.name.value || "").toLowerCase();
      }

      if (FORBIDDEN_FUNCTIONS.has(funcName)) {
        throw new Error(
          `Forbidden dangerous function call '${funcName}()' detected.`
        );
      }
    }

    for (const key of Object.keys(node)) {
      if (typeof node[key] === "object" && node[key] !== null) {
        this.checkForbiddenFunctions(node[key]);
      }
    }
  }
}

export const sqlValidator = new SQLValidator();
