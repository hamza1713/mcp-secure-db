"""Adversarial security test suite testing AST firewall, DuckDB engine sandbox, and RBAC."""

import json
import pytest
import duckdb
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from mcp_secure_db.database.engine import (
    QueryTimeoutError,
    SecureDuckDBEngine,
)
from mcp_secure_db.security.rbac import (
    CallerPrincipal,
    HybridHTTPAuthMiddleware,
    RBACMiddleware,
    Role,
    SecureDBBearerAuthProvider,
    get_current_principal,
    resolve_principal_from_token,
    set_current_principal,
)
from mcp_secure_db.security.validator import (
    SQLSecurityError,
    SQLValidator,
)
from mcp_secure_db.server import create_server


@pytest.fixture
def validator() -> SQLValidator:
    return SQLValidator(max_rows=1000, default_limit=100, max_joins=4)


@pytest.fixture
def engine() -> SecureDuckDBEngine:
    return SecureDuckDBEngine(timeout_seconds=5.0)


# =============================================================================
# 1. Join Tautology Variants
# =============================================================================


def test_adversarial_join_tautology_numeric(validator: SQLValidator) -> None:
    # ON 2>1 has no columns -> Blocked by AST
    sql = "SELECT a.org_name, b.tool_name FROM organizations a JOIN tool_invocations b ON 2 > 1"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "CARTESIAN_JOIN_DOS"


def test_adversarial_join_tautology_string(validator: SQLValidator) -> None:
    # ON 'a'='a' has no columns -> Blocked by AST
    sql = "SELECT a.org_name, b.tool_name FROM organizations a JOIN tool_invocations b ON 'a' = 'a'"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "CARTESIAN_JOIN_DOS"


def test_adversarial_join_tautology_boolean(validator: SQLValidator) -> None:
    # ON TRUE has no columns -> Blocked by AST
    sql = "SELECT a.org_name, b.tool_name FROM organizations a JOIN tool_invocations b ON TRUE"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "CARTESIAN_JOIN_DOS"


def test_adversarial_join_tautology_self_comparison(validator: SQLValidator) -> None:
    # ON a.org_id = a.org_id (x=x) -> Blocked by AST
    sql = "SELECT a.org_name, b.tool_name FROM organizations a JOIN tool_invocations b ON a.org_id = a.org_id"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "CARTESIAN_JOIN_DOS"


# =============================================================================
# 2. Row-Explosion Without JOIN Keywords
# =============================================================================


def test_adversarial_generate_series_blocked(validator: SQLValidator) -> None:
    sql = "SELECT generate_series(1, 10000000) FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "EXTERNAL_ACCESS_OR_DOS_FUNCTION"


def test_adversarial_range_function_blocked(validator: SQLValidator) -> None:
    sql = "SELECT range(1, 10000000) FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "EXTERNAL_ACCESS_OR_DOS_FUNCTION"


def test_adversarial_unnest_bounded_by_limit(validator: SQLValidator, engine: SecureDuckDBEngine) -> None:
    # unnest([1, 2, 3]) is valid syntax and allowed by AST, but clamped by LIMIT <= 1000
    sql = "SELECT unnest([1, 2, 3]) AS val FROM organizations"
    res = engine.execute_query(sql, role=Role.ANALYST)
    assert res.status == "success"
    assert res.row_count <= 1000
    assert res.limit_enforced <= 1000


# =============================================================================
# 3. Recursive CTE Without Termination
# =============================================================================


def test_adversarial_recursive_cte_stopped_by_watchdog(engine: SecureDuckDBEngine) -> None:
    # Recursive CTE without termination: AST allows valid syntax, but watchdog interrupts execution
    heavy_sql = """
    WITH RECURSIVE nums(x) AS (
        SELECT 1
        UNION ALL
        SELECT x + 1 FROM nums WHERE x < 200000000
    )
    SELECT o.org_name, COUNT(n1.x)
    FROM organizations o
    JOIN nums n1 ON length(o.org_id) = n1.x % 10 + 6
    JOIN nums n2 ON n1.x = n2.x
    WHERE o.org_id = 'org_01'
    GROUP BY o.org_name
    """
    with pytest.raises(QueryTimeoutError, match="Query aborted by sandbox watchdog"):
        engine.execute_query(heavy_sql, role=Role.ADMIN, timeout_override=0.01)


# =============================================================================
# 4. Self-Joins on Low-Cardinality Columns
# =============================================================================


def test_adversarial_self_join_low_cardinality_bounded(engine: SecureDuckDBEngine) -> None:
    # 1 join on low-cardinality plan_tier is allowed by AST, bounded by LIMIT <= 1000
    sql = "SELECT a.org_name, b.org_name FROM organizations a JOIN organizations b ON a.plan_tier = b.plan_tier"
    res = engine.execute_query(sql, role=Role.ANALYST)
    assert res.status == "success"
    assert res.row_count <= 1000


def test_adversarial_excessive_self_joins_blocked_by_ast(validator: SQLValidator) -> None:
    # 5 joins exceeds max_joins=4 -> Blocked by AST
    sql = """
    SELECT a.org_name
    FROM organizations a
    JOIN organizations b ON a.plan_tier = b.plan_tier
    JOIN organizations c ON b.plan_tier = c.plan_tier
    JOIN organizations d ON c.plan_tier = d.plan_tier
    JOIN organizations e ON d.plan_tier = e.plan_tier
    JOIN organizations f ON e.plan_tier = f.plan_tier
    """
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "DOS_COMPLEXITY_EXCEEDED"


# =============================================================================
# 5. Comment and Whitespace Evasion, Unicode Lookalikes, Nested Subqueries
# =============================================================================


def test_adversarial_comment_line_evasion(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations -- injected comment\nWHERE 1=1"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "COMMENT_SMUGGLING"


def test_adversarial_comment_block_evasion(validator: SQLValidator) -> None:
    sql = "SELECT org_name /* block comment */ FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "COMMENT_SMUGGLING"


def test_adversarial_nested_subquery_comment_evasion(validator: SQLValidator) -> None:
    sql = "SELECT * FROM (SELECT org_name FROM organizations /* comment */) sub"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "COMMENT_SMUGGLING"


def test_adversarial_mixed_case_comment_evasion(validator: SQLValidator) -> None:
    sql = "sElEcT org_name FrOm organizations -- smuggled comment\nWHERE 1=1"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "COMMENT_SMUGGLING"


def test_adversarial_unicode_lookalike_syntax_error(validator: SQLValidator) -> None:
    # Cyrillic 'С' lookalike in SELECT keyword -> Syntax error in tokenizer/parser
    sql = "\u0421ELECT org_name FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "SYNTAX_ERROR"


# =============================================================================
# 6. Multi-Statement Attempts (Including String Literals)
# =============================================================================


def test_adversarial_multi_statement_semicolon(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations; DROP TABLE organizations;"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "MULTI_STATEMENT_SMUGGLING"


def test_adversarial_safe_string_literal_with_semicolon(validator: SQLValidator) -> None:
    # Semicolon inside a string literal is safe and allowed
    sql = "SELECT org_name FROM organizations WHERE org_name = 'Acme; Robotics'"
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.is_safe is True
    assert "Acme; Robotics" in (res.sanitized_sql or "")


def test_adversarial_string_literal_breakout_blocked(validator: SQLValidator) -> None:
    # Attempt to break out of literal with quote and semicolon
    sql = "SELECT org_name FROM organizations WHERE org_name = 'Acme'; DROP TABLE organizations; --'"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category in ("MULTI_STATEMENT_SMUGGLING", "COMMENT_SMUGGLING")


# =============================================================================
# 7. PII Bypass Attempts
# =============================================================================


def test_adversarial_pii_wildcard_star(validator: SQLValidator) -> None:
    sql = "SELECT * FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "RBAC_WILDCARD_ON_PII_TABLE"


def test_adversarial_pii_column_aliasing(validator: SQLValidator) -> None:
    sql = "SELECT billing_email AS user_email FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "RBAC_PII_COLUMN_RESTRICTED"


def test_adversarial_pii_subquery_wrapping(validator: SQLValidator) -> None:
    sql = "SELECT sub.e FROM (SELECT billing_email AS e FROM organizations) sub"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "RBAC_PII_COLUMN_RESTRICTED"


def test_adversarial_pii_cte_wrapping(validator: SQLValidator) -> None:
    sql = "WITH c AS (SELECT billing_email FROM organizations) SELECT * FROM c"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "RBAC_PII_COLUMN_RESTRICTED"


def test_adversarial_pii_union(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations UNION SELECT billing_email FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "RBAC_PII_COLUMN_RESTRICTED"


def test_adversarial_pii_expression_reconstruction(validator: SQLValidator) -> None:
    sql = "SELECT concat(billing_email, '') FROM organizations"
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert exc_info.value.violation_category == "RBAC_PII_COLUMN_RESTRICTED"


# =============================================================================
# 8. LIMIT and OFFSET Bypass Attempts
# =============================================================================


def test_adversarial_huge_limit_clamped(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations LIMIT 999999999"
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.is_safe is True
    assert res.limit_applied == 1000
    assert "LIMIT 1000" in (res.sanitized_sql or "")


def test_adversarial_subquery_limit_clamped(validator: SQLValidator) -> None:
    sql = "SELECT sub.org_name FROM (SELECT org_name FROM organizations LIMIT 9999999) sub"
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.is_safe is True
    # Subquery limit is clamped to 1000 and root limit is injected/enforced
    assert "LIMIT 1000" in (res.sanitized_sql or "")


def test_adversarial_offset_abuse_bounded_by_engine(engine: SecureDuckDBEngine) -> None:
    # OFFSET abuse does not bypass limits; returns empty result set safely
    sql = "SELECT org_name FROM organizations LIMIT 10 OFFSET 1000000"
    res = engine.execute_query(sql, role=Role.ANALYST)
    assert res.status == "success"
    assert res.row_count == 0


# =============================================================================
# 9. RBAC Authentication & Authorization Bypasses
# =============================================================================


def test_adversarial_rbac_forged_bearer_token() -> None:
    principal = resolve_principal_from_token("Bearer forged-token-xyz")
    assert principal is None


def test_adversarial_rbac_empty_token() -> None:
    principal = resolve_principal_from_token("")
    assert principal is None


def test_adversarial_rbac_case_insensitive_header() -> None:
    # Headers with mixed case are normalized
    headers = {"AUTHORIZATION": "Bearer token-analyst-demo"}
    raw_token = headers.get("AUTHORIZATION")
    principal = resolve_principal_from_token(raw_token)
    assert principal is not None
    assert principal.role == Role.ANALYST


@pytest.mark.asyncio
async def test_adversarial_public_viewer_calling_analyst_tool_blocked() -> None:
    # A public_viewer calling execute_analytical_sql directly is blocked
    server = create_server()
    set_current_principal(CallerPrincipal(role=Role.PUBLIC_VIEWER))

    with pytest.raises(Exception, match="Role 'public_viewer' is restricted"):
        await server.call_tool(
            "execute_analytical_sql",
            {"sql": "SELECT org_name FROM organizations"},
        )


# =============================================================================
# 10. Engine Sandboxing Without AST (Direct C++ Wall Verification)
# =============================================================================


def test_adversarial_engine_blocks_file_reads_even_if_ast_skipped(engine: SecureDuckDBEngine) -> None:
    # Direct execution on DuckDB connection skipping the AST validator entirely
    # DuckDB's C++ kernel setting enable_external_access=false must block them

    with pytest.raises(duckdb.PermissionException, match="file system operations are disabled"):
        engine._conn.execute("SELECT * FROM read_csv('secret.csv')")

    with pytest.raises(duckdb.PermissionException, match="file system operations are disabled"):
        engine._conn.execute("SELECT * FROM glob('*.csv')")

    with pytest.raises(duckdb.PermissionException, match="file system operations are disabled"):
        engine._conn.execute("SELECT * FROM read_parquet('secret.parquet')")
