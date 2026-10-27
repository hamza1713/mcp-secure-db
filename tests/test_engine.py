"""Tests for Layers 3 & 4: Sandboxed DuckDB Engine, Interrupt Watchdog, and Telemetry."""

import time
import pytest
from mcp_secure_db.database.engine import (
    AuditLogger,
    QueryExecutionResult,
    QueryTimeoutError,
    SecureDuckDBEngine,
)
from mcp_secure_db.security.rbac import Role
from mcp_secure_db.security.validator import SQLSecurityError


@pytest.fixture
def engine() -> SecureDuckDBEngine:
    return SecureDuckDBEngine(timeout_seconds=5.0)


# -----------------------------------------------------------------------------
# Pre-seeded Dataset & C++ Hardening
# -----------------------------------------------------------------------------


def test_tables_seeded_with_expected_counts(engine: SecureDuckDBEngine) -> None:
    catalog = engine.list_accessible_tables(role=Role.ADMIN)
    table_counts = {item["table_name"]: item["row_count"] for item in catalog}

    assert table_counts["organizations"] == 10
    assert table_counts["mcp_servers"] == 12
    assert table_counts["tool_invocations"] == 20
    assert table_counts["subscriptions"] == 10
    assert table_counts["api_keys"] == 4
    assert table_counts["security_incidents"] == 4


def test_duckdb_configuration_locked(engine: SecureDuckDBEngine) -> None:
    # Attempting to change memory_limit or enable_external_access must fail
    with pytest.raises(Exception):
        engine._conn.execute("SET memory_limit = '10GB';")
    with pytest.raises(Exception):
        engine._conn.execute("SET enable_external_access = true;")


# -----------------------------------------------------------------------------
# Metadata & Schema Introspection
# -----------------------------------------------------------------------------


def test_list_accessible_tables_rbac_filter(engine: SecureDuckDBEngine) -> None:
    viewer_tables = engine.list_accessible_tables(role=Role.PUBLIC_VIEWER)
    analyst_tables = engine.list_accessible_tables(role=Role.ANALYST)
    admin_tables = engine.list_accessible_tables(role=Role.ADMIN)

    viewer_names = {t["table_name"] for t in viewer_tables}
    analyst_names = {t["table_name"] for t in analyst_tables}
    admin_names = {t["table_name"] for t in admin_tables}

    assert viewer_names == {"organizations", "mcp_servers", "tool_invocations", "subscriptions"}
    assert analyst_names == viewer_names
    assert admin_names == {
        "organizations",
        "mcp_servers",
        "tool_invocations",
        "subscriptions",
        "api_keys",
        "security_incidents",
    }


def test_describe_table_schema_analyst_vs_admin(engine: SecureDuckDBEngine) -> None:
    schema_analyst = engine.describe_table_schema("organizations", role=Role.ANALYST)
    assert schema_analyst["caller_role"] == "analyst"
    assert schema_analyst["select_star_allowed_for_caller"] is False

    col_map = {c["column_name"]: c for c in schema_analyst["columns"]}
    assert col_map["org_name"]["queryable_by_current_role"] is True
    assert col_map["billing_email"]["queryable_by_current_role"] is False
    assert col_map["billing_email"]["access_policy"] == "ADMIN_ONLY_PII"

    schema_admin = engine.describe_table_schema("organizations", role=Role.ADMIN)
    col_map_admin = {c["column_name"]: c for c in schema_admin["columns"]}
    assert schema_admin["select_star_allowed_for_caller"] is True
    assert col_map_admin["billing_email"]["queryable_by_current_role"] is True


def test_describe_table_blocked_for_analyst_on_admin_table(engine: SecureDuckDBEngine) -> None:
    with pytest.raises(PermissionError, match="restricted to 'admin' role"):
        engine.describe_table_schema("api_keys", role=Role.ANALYST)


def test_describe_unknown_table_raises_value_error(engine: SecureDuckDBEngine) -> None:
    with pytest.raises(ValueError, match="Unknown table 'ghost_table'"):
        engine.describe_table_schema("ghost_table", role=Role.ANALYST)


# -----------------------------------------------------------------------------
# Query Execution & Guardrails
# -----------------------------------------------------------------------------


def test_public_viewer_cannot_execute_sql(engine: SecureDuckDBEngine) -> None:
    with pytest.raises(PermissionError, match="Role 'public_viewer' is restricted"):
        engine.execute_query("SELECT org_name FROM organizations", role=Role.PUBLIC_VIEWER)


def test_analyst_executes_safe_query(engine: SecureDuckDBEngine) -> None:
    sql = "SELECT org_name, mrr_usd, region FROM organizations WHERE plan_tier = 'enterprise'"
    res = engine.execute_query(sql, role=Role.ANALYST)

    assert isinstance(res, QueryExecutionResult)
    assert res.status == "success"
    assert res.role == Role.ANALYST
    assert res.row_count > 0
    assert "org_name" in res.columns
    assert "billing_email" not in res.columns
    assert res.execution_time_ms >= 0.0
    assert "LIMIT 100" in res.sanitized_sql


def test_admin_executes_pii_query(engine: SecureDuckDBEngine) -> None:
    sql = "SELECT org_name, billing_email FROM organizations WHERE org_id = 'org_01'"
    res = engine.execute_query(sql, role=Role.ADMIN)

    assert res.row_count == 1
    assert res.rows[0]["org_name"] == "Acme Robotics AI"
    assert res.rows[0]["billing_email"] == "finance@acmerobotics.ai"


def test_ast_violation_records_audit_and_raises(engine: SecureDuckDBEngine) -> None:
    with pytest.raises(SQLSecurityError):
        engine.execute_query("DROP TABLE organizations", role=Role.ANALYST)

    recent = engine.audit_logger.get_recent(limit=5)
    assert any(
        e["status"] == "BLOCKED_AST" and e["violation_category"] == "FORBIDDEN_STATEMENT_TYPE"
        for e in recent
    )


# -----------------------------------------------------------------------------
# Interrupt Watchdog & Timeout
# -----------------------------------------------------------------------------


def test_query_timeout_watchdog_interrupts(engine: SecureDuckDBEngine) -> None:
    # A heavy cross product inside a CTE or recursive query that runs longer than timeout
    # We test with timeout_override = 0.0001s to ensure deterministic triggering
    heavy_sql = """
    WITH RECURSIVE nums(x) AS (
        SELECT 1
        UNION ALL
        SELECT x + 1 FROM nums WHERE x < 2000000
    )
    SELECT o.org_name, COUNT(n1.x)
    FROM organizations o
    JOIN nums n1 ON length(o.org_id) = n1.x % 10 + 6
    JOIN nums n2 ON n1.x = n2.x
    WHERE o.org_id = 'org_01'
    GROUP BY o.org_name
    """
    with pytest.raises(QueryTimeoutError, match="Query aborted by sandbox watchdog"):
        engine.execute_query(heavy_sql, role=Role.ADMIN, timeout_override=0.001)

    recent = engine.audit_logger.get_recent(limit=5, status_filter="TIMEOUT")
    assert len(recent) > 0
    assert recent[0]["status"] == "TIMEOUT"
    assert recent[0]["violation_category"] == "EXECUTION_TIMEOUT"


# -----------------------------------------------------------------------------
# Audit Logger & Telemetry Aggregation
# -----------------------------------------------------------------------------


def test_audit_logger_summary_stats() -> None:
    logger = AuditLogger(max_entries=10)
    logger.record(Role.ANALYST, "execute_analytical_sql", "ALLOWED", execution_time_ms=12.5, row_count=5)
    logger.record(Role.ANALYST, "execute_analytical_sql", "BLOCKED_AST", violation_category="COMMENT_SMUGGLING")
    logger.record(Role.PUBLIC_VIEWER, "execute_analytical_sql", "BLOCKED_RBAC", violation_category="RBAC_UNAUTHORIZED")

    stats = logger.summary_stats()
    assert stats["total_events_logged"] == 3
    assert stats["events_by_status"]["ALLOWED"] == 1
    assert stats["events_by_status"]["BLOCKED_AST"] == 1
    assert stats["blocked_by_category"]["COMMENT_SMUGGLING"] == 1
    assert stats["avg_allowed_execution_ms"] == 12.5
