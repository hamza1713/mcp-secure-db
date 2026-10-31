"""Layer 2: Deterministic Zero-Token SQL AST Validator & Policy Engine (sqlglot)."""

from __future__ import annotations

import re
from typing import Any

import sqlglot
from pydantic import BaseModel, Field
from sqlglot import exp
from sqlglot.errors import ParseError

from mcp_secure_db.security.rbac import (
    ADMIN_ONLY_TABLES,
    ALL_KNOWN_TABLES,
    PII_COLUMNS_BY_TABLE,
    RESTRICTED_PII_COLUMNS,
    SAFE_COLUMNS_BY_TABLE,
    Role,
)


class SQLSecurityError(ValueError):
    """Raised when a SQL query violates AST security, DoS, or RBAC governance policies."""

    def __init__(self, message: str, violation_category: str = "AST_POLICY_VIOLATION") -> None:
        super().__init__(message)
        self.violation_category = violation_category


class SQLValidationResult(BaseModel):
    """Structured result of deterministic AST validation."""

    is_safe: bool = Field(description="Whether the query passed all AST & RBAC checks")
    original_sql: str = Field(description="Raw input SQL string")
    sanitized_sql: str | None = Field(default=None, description="Transpiled & LIMIT-bounded DuckDB SQL")
    role_checked: Role = Field(description="Caller RBAC role evaluated against policy")
    tables_accessed: list[str] = Field(default_factory=list, description="Physical tables referenced")
    columns_accessed: list[str] = Field(default_factory=list, description="Columns referenced")
    limit_applied: int | None = Field(default=None, description="Row limit enforced on the query")
    violation_category: str | None = Field(default=None, description="Error category if blocked")
    violation_reason: str | None = Field(default=None, description="Detailed explanation if blocked")


# Forbidden DuckDB functions capable of SSRF, local file exfiltration, or CPU/RAM bombs
FORBIDDEN_FUNCTIONS: frozenset[str] = frozenset(
    {
        "read_csv",
        "read_csv_auto",
        "read_parquet",
        "read_json",
        "read_json_auto",
        "read_ndjson",
        "read_ndjson_auto",
        "read_text",
        "read_blob",
        "parquet_scan",
        "csv_scan",
        "json_scan",
        "sqlite_scan",
        "postgres_scan",
        "mysql_scan",
        "iceberg_scan",
        "delta_scan",
        "glob",
        "st_read",
        "getenv",
        "current_setting",
        "query",
        "query_table",
        "repeat",
        "range",
        "generate_series",
        "sleep",
    }
)

FORBIDDEN_FUNCTION_PREFIXES: tuple[str, ...] = (
    "read_",
    "pragma_",
    "duckdb_",
    " parquet_",
    "sqlite_",
    "postgres_",
)

# Forbidden SQL keywords in raw/command form that should never appear as statements
FORBIDDEN_EXP_TYPES: tuple[type[exp.Expression], ...] = tuple(
    cls
    for cls in (
        getattr(exp, "Drop", None),
        getattr(exp, "Delete", None),
        getattr(exp, "Update", None),
        getattr(exp, "Insert", None),
        getattr(exp, "Create", None),
        getattr(exp, "Alter", None),
        getattr(exp, "Command", None),
        getattr(exp, "Copy", None),
        getattr(exp, "Pragma", None),
        getattr(exp, "Set", None),
        getattr(exp, "LoadData", None),
        getattr(exp, "Attach", None),
        getattr(exp, "Detach", None),
        getattr(exp, "Transaction", None),
        getattr(exp, "Commit", None),
        getattr(exp, "Rollback", None),
        getattr(exp, "Grant", None),
        getattr(exp, "Revoke", None),
        getattr(exp, "Merge", None),
        getattr(exp, "TruncateTable", None),
        getattr(exp, "Use", None),
        getattr(exp, "Install", None),
        getattr(exp, "Summarize", None),
        getattr(exp, "Describe", None),
        getattr(exp, "Show", None),
    )
    if cls is not None
)

_COMMENT_PATTERN = re.compile(r"(--|/\*|\*/)")
_FILE_OR_URL_TABLE_PATTERN = re.compile(
    r"([/\\]|://|\.\.|\.(csv|parquet|json|ndjson|db|duckdb|sqlite|txt|log|env|pem|key)$)",
    re.IGNORECASE,
)


class SQLValidator:
    """Zero-token-cost deterministic SQL AST validator built on sqlglot (DuckDB dialect)."""

    def __init__(
        self,
        max_rows: int = 1000,
        default_limit: int = 100,
        max_joins: int = 4,
        max_query_length: int = 8192,
    ) -> None:
        self.max_rows = max_rows
        self.default_limit = min(default_limit, max_rows)
        self.max_joins = max_joins
        self.max_query_length = max_query_length

    def validate_and_sanitize(
        self,
        sql: str,
        role: Role = Role.ANALYST,
        requested_limit: int | None = None,
    ) -> SQLValidationResult:
        """Validate a SQL query against all AST & RBAC policies and return sanitized SQL.

        Raises:
            SQLSecurityError: If any security, DoS, or RBAC policy is violated.
        """
        if not sql or not sql.strip():
            raise SQLSecurityError("SQL query cannot be empty.", "EMPTY_QUERY")

        cleaned = sql.strip()
        if len(cleaned) > self.max_query_length:
            raise SQLSecurityError(
                f"Query length ({len(cleaned)} chars) exceeds maximum allowed ({self.max_query_length}).",
                "QUERY_TOO_LONG",
            )

        # 1. Lexical tokenization: Block SQL comments (-- or /* */) and multi-statements
        # Using sqlglot.tokenize ensures comments and semicolons inside string literals
        # (e.g. WHERE name = 'foo--bar' or 'Acme; Inc.') are not falsely blocked.
        try:
            tokens = sqlglot.tokenize(cleaned, read="duckdb")
        except Exception as exc:
            raise SQLSecurityError(f"Malformed SQL syntax rejected by tokenizer: {exc}", "SYNTAX_ERROR") from exc

        if not tokens:
            raise SQLSecurityError(
                "SQL comments ('--' or '/* */') or empty inputs are forbidden.",
                "COMMENT_SMUGGLING",
            )

        if any(t.comments for t in tokens):
            raise SQLSecurityError(
                "SQL comments ('--' or '/* */') are forbidden to prevent comment-smuggled injection payloads.",
                "COMMENT_SMUGGLING",
            )

        # Multi-statement detection: semicolon tokens are only allowed as the trailing token
        semicolon_indices = [
            i for i, t in enumerate(tokens) if t.token_type == sqlglot.TokenType.SEMICOLON
        ]
        if any(idx < len(tokens) - 1 for idx in semicolon_indices):
            raise SQLSecurityError(
                "Multi-statement SQL queries (';') are strictly forbidden.",
                "MULTI_STATEMENT_SMUGGLING",
            )

        # 2. Parse into DuckDB AST via sqlglot
        try:
            statements = sqlglot.parse(cleaned, read="duckdb", error_level=sqlglot.ErrorLevel.RAISE)
        except ParseError as exc:
            raise SQLSecurityError(f"Malformed SQL syntax rejected by parser: {exc}", "SYNTAX_ERROR") from exc

        if len(statements) != 1 or statements[0] is None:
            raise SQLSecurityError(
                f"Expected exactly 1 SQL statement, found {len(statements)}.",
                "MULTI_STATEMENT_SMUGGLING",
            )

        ast = statements[0]

        # Also check if sqlglot attached any comments to any AST node
        for node in ast.walk():
            if getattr(node, "comments", None):
                raise SQLSecurityError(
                    "SQL comments are forbidden by security policy.",
                    "COMMENT_SMUGGLING",
                )

        # 3. Verify root expression is strictly a read-only SELECT or Set Operation (UNION/INTERSECT/EXCEPT)
        if not isinstance(ast, (exp.Select, exp.Union, exp.Intersect, exp.Except)):
            raise SQLSecurityError(
                f"Only read-only SELECT queries are permitted. Found root statement type: '{type(ast).__name__}'.",
                "FORBIDDEN_STATEMENT_TYPE",
            )

        # 4. Walk entire AST to block DDL/DML nodes, external file/SSRF functions, and Cartesian joins
        self._check_forbidden_nodes_and_functions(ast)
        self._check_join_and_dos_complexity(ast)

        # 5. Extract physical tables & columns and enforce RBAC table/PII governance
        tables, columns = self._check_rbac_table_and_column_policy(ast, role)

        # 6. Enforce bounded LIMIT <= max_rows
        target_limit = self.default_limit
        if requested_limit is not None:
            target_limit = max(1, min(requested_limit, self.max_rows))

        ast, enforced_limit = self._enforce_row_limit(ast, target_limit)
        sanitized_sql = ast.sql(dialect="duckdb")

        return SQLValidationResult(
            is_safe=True,
            original_sql=sql,
            sanitized_sql=sanitized_sql,
            role_checked=role,
            tables_accessed=sorted(tables),
            columns_accessed=sorted(columns),
            limit_applied=enforced_limit,
        )

    def inspect_query(
        self,
        sql: str,
        role: Role = Role.ANALYST,
        requested_limit: int | None = None,
    ) -> SQLValidationResult:
        """Non-raising inspection wrapper that returns structured pass/fail diagnostics."""
        try:
            return self.validate_and_sanitize(sql=sql, role=role, requested_limit=requested_limit)
        except SQLSecurityError as exc:
            return SQLValidationResult(
                is_safe=False,
                original_sql=sql,
                sanitized_sql=None,
                role_checked=role,
                violation_category=exc.violation_category,
                violation_reason=str(exc),
            )

    def _check_forbidden_nodes_and_functions(self, ast: exp.Expression) -> None:
        """Scan every AST node for mutating operations and DuckDB SSRF/file-read functions."""
        for node in ast.walk():
            if isinstance(node, FORBIDDEN_EXP_TYPES):
                raise SQLSecurityError(
                    f"Forbidden SQL operation detected in AST: '{type(node).__name__}'. "
                    "All DDL, DML, transaction, and administrative statements are blocked.",
                    "MUTATING_OR_ADMIN_OPERATION",
                )

            if isinstance(node, (exp.Select,)) and node.args.get("into"):
                raise SQLSecurityError(
                    "SELECT ... INTO table creation is forbidden.",
                    "MUTATING_OR_ADMIN_OPERATION",
                )

            # Check function calls (both typed exp.Func and untyped exp.Anonymous)
            if isinstance(node, exp.Func):
                func_name = (
                    node.name.lower()
                    if isinstance(node, exp.Anonymous)
                    else node.sql_name().lower()
                )
                if func_name in FORBIDDEN_FUNCTIONS or func_name.startswith(FORBIDDEN_FUNCTION_PREFIXES):
                    raise SQLSecurityError(
                        f"Forbidden DuckDB function '{func_name}()' blocked: external file reads, "
                        "network requests (SSRF), system pragmas, and synthetic row generators are disabled.",
                        "EXTERNAL_ACCESS_OR_DOS_FUNCTION",
                    )

    def _check_join_and_dos_complexity(self, ast: exp.Expression) -> None:
        """Block Cartesian joins (CROSS JOIN / comma joins) and excessive join fan-out."""
        joins = list(ast.find_all(exp.Join))
        if len(joins) > self.max_joins:
            raise SQLSecurityError(
                f"Query contains {len(joins)} JOINs, exceeding the safety maximum of {self.max_joins}.",
                "DOS_COMPLEXITY_EXCEEDED",
            )

        for join in joins:
            join_kind = (join.kind or "").upper()
            on_clause = join.args.get("on")
            has_using = bool(join.args.get("using"))
            if join_kind == "CROSS" or (not on_clause and not has_using):
                raise SQLSecurityError(
                    "Unconstrained CROSS JOIN or implicit Cartesian comma-join is forbidden to prevent "
                    "compute exhaustion (DoS). Always provide an explicit ON or USING clause.",
                    "CARTESIAN_JOIN_DOS",
                )

            if on_clause:
                cols_in_on = list(on_clause.find_all(exp.Column))
                if not cols_in_on:
                    raise SQLSecurityError(
                        "Degenerate Cartesian JOIN with literal tautology (e.g. 'ON 1=1' or 'ON true') "
                        "is forbidden to prevent compute exhaustion (DoS). Join predicates must reference columns.",
                        "CARTESIAN_JOIN_DOS",
                    )
                for eq in on_clause.find_all(exp.EQ, exp.GTE, exp.LTE):
                    if eq.left == eq.right:
                        raise SQLSecurityError(
                            "Degenerate Cartesian JOIN with self-comparison tautology (e.g. 'ON x=x') "
                            "is forbidden to prevent compute exhaustion (DoS). Join conditions cannot compare identical columns.",
                            "CARTESIAN_JOIN_DOS",
                        )

    def _check_rbac_table_and_column_policy(
        self,
        ast: exp.Expression,
        role: Role,
    ) -> tuple[set[str], set[str]]:
        """Validate referenced tables and columns against caller role & PII rules."""
        cte_aliases: set[str] = {
            cte.alias_or_name.lower()
            for cte in ast.find_all(exp.CTE)
            if cte.alias_or_name
        }

        physical_tables: set[str] = set()
        for table_node in ast.find_all(exp.Table):
            raw_table_name = table_node.name
            if not raw_table_name:
                continue
            table_lower = raw_table_name.lower()
            if table_lower in cte_aliases:
                continue

            # Check if table name is actually a DuckDB file path or URL (e.g. FROM '/etc/passwd')
            if _FILE_OR_URL_TABLE_PATTERN.search(raw_table_name) or table_node.db or table_node.catalog:
                raise SQLSecurityError(
                    f"External file path, URL, or cross-catalog table reference '{table_node.sql()}' is forbidden.",
                    "EXTERNAL_FILE_OR_SSRF_ATTEMPT",
                )

            if table_lower not in ALL_KNOWN_TABLES:
                raise SQLSecurityError(
                    f"Unknown table '{raw_table_name}'. Available tables: {sorted(ALL_KNOWN_TABLES - ADMIN_ONLY_TABLES if role != Role.ADMIN else ALL_KNOWN_TABLES)}.",
                    "UNKNOWN_TABLE",
                )

            if role != Role.ADMIN and table_lower in ADMIN_ONLY_TABLES:
                raise SQLSecurityError(
                    f"Access denied: table '{table_lower}' is restricted to 'admin' role (caller role is '{role.value}').",
                    "RBAC_TABLE_RESTRICTED",
                )

            physical_tables.add(table_lower)

        if not physical_tables:
            raise SQLSecurityError(
                "Query must reference at least one authorized table in the analytical catalog.",
                "NO_TABLE_REFERENCED",
            )

        referenced_columns: set[str] = set()
        for col_node in ast.find_all(exp.Column):
            col_name = col_node.name.lower()
            if not col_name:
                continue
            referenced_columns.add(col_name)

            if role != Role.ADMIN and col_name in RESTRICTED_PII_COLUMNS:
                raise SQLSecurityError(
                    f"Column-level security violation: column '{col_name}' contains restricted PII/secrets "
                    f"and cannot be accessed by role '{role.value}' (requires 'admin').",
                    "RBAC_PII_COLUMN_RESTRICTED",
                )

        # Block SELECT * on tables that contain PII columns for non-admin roles
        # Note: exp.Count(this=exp.Star()) i.e. COUNT(*) is safe and does not expose PII columns
        if role != Role.ADMIN:
            has_projection_star = False
            for star_node in ast.find_all(exp.Star):
                if not isinstance(star_node.parent, exp.Count):
                    has_projection_star = True
                    break

            if has_projection_star:
                tables_with_pii = sorted(
                    t for t in physical_tables if PII_COLUMNS_BY_TABLE.get(t)
                )
                if tables_with_pii:
                    safe_hints = {
                        t: list(SAFE_COLUMNS_BY_TABLE[t]) for t in tables_with_pii
                    }
                    raise SQLSecurityError(
                        f"Wildcard 'SELECT *' is blocked on PII-bearing table(s) {tables_with_pii} for role "
                        f"'{role.value}'. Specify allowed non-PII columns explicitly: {safe_hints}.",
                        "RBAC_WILDCARD_ON_PII_TABLE",
                    )

        return physical_tables, referenced_columns

    def _enforce_row_limit(
        self,
        ast: exp.Expression,
        target_limit: int,
    ) -> tuple[exp.Expression, int]:
        """Inject or clamp query LIMIT so it never exceeds self.max_rows (root and subqueries)."""
        for lim in ast.find_all(exp.Limit):
            if lim.expression is not None:
                try:
                    val = int(str(lim.expression.this))
                    if val > self.max_rows:
                        lim.set("expression", exp.Literal.number(self.max_rows))
                except (ValueError, TypeError):
                    pass

        existing_limit_node = ast.args.get("limit")
        if isinstance(existing_limit_node, exp.Limit) and existing_limit_node.expression is not None:
            try:
                current_val = int(str(existing_limit_node.expression.this))
                clamped_val = max(1, min(current_val, self.max_rows))
                ast = ast.limit(clamped_val, copy=True)
                return ast, clamped_val
            except (ValueError, TypeError):
                pass

        enforced = max(1, min(target_limit, self.max_rows))
        ast = ast.limit(enforced, copy=True)
        return ast, enforced
