"""Comprehensive tests for Layer 2: SQL AST Validator & Policy Engine."""

import pytest
from mcp_secure_db.security.rbac import Role
from mcp_secure_db.security.validator import SQLSecurityError, SQLValidator


@pytest.fixture
def validator() -> SQLValidator:
    return SQLValidator(max_rows=1000, default_limit=100, max_joins=4)


# -----------------------------------------------------------------------------
# Input Sanitization & Smuggling Attacks
# -----------------------------------------------------------------------------


def test_empty_query(validator: SQLValidator) -> None:
    with pytest.raises(SQLSecurityError, match="SQL query cannot be empty"):
        validator.validate_and_sanitize("")
    with pytest.raises(SQLSecurityError, match="SQL query cannot be empty"):
        validator.validate_and_sanitize("   \n\t  ")


def test_query_too_long(validator: SQLValidator) -> None:
    long_query = "SELECT org_name FROM organizations WHERE " + " AND ".join(["1=1"] * 2000)
    with pytest.raises(SQLSecurityError, match="exceeds maximum allowed"):
        validator.validate_and_sanitize(long_query)


def test_comment_smuggling_line_comment(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations -- hidden injection payload"
    with pytest.raises(SQLSecurityError, match="SQL comments"):
        validator.validate_and_sanitize(sql)


def test_comment_smuggling_block_comment(validator: SQLValidator) -> None:
    sql = "SELECT org_name /* bypass attempt */ FROM organizations"
    with pytest.raises(SQLSecurityError, match="SQL comments"):
        validator.validate_and_sanitize(sql)


def test_comment_smuggling_pure_comment(validator: SQLValidator) -> None:
    with pytest.raises(SQLSecurityError, match="SQL comments"):
        validator.validate_and_sanitize("-- just a comment with no tokens")
    with pytest.raises(SQLSecurityError, match="SQL comments"):
        validator.validate_and_sanitize("/* pure block comment */")


def test_string_literals_with_comment_patterns_allowed(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations WHERE org_name = 'foo--bar' AND region = '/*not a comment*/'"
    result = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert result.is_safe is True
    assert "organizations" in result.tables_accessed


def test_string_literals_with_semicolon_allowed(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations WHERE org_name = 'Acme; Inc.'"
    result = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert result.is_safe is True
    assert "organizations" in result.tables_accessed


def test_multi_statement_semicolon(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations; DROP TABLE organizations;"
    with pytest.raises(SQLSecurityError, match="Multi-statement SQL queries"):
        validator.validate_and_sanitize(sql)


def test_single_trailing_semicolon_allowed(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations;"
    result = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert result.is_safe is True
    assert "organizations" in result.tables_accessed


def test_syntax_error_rejected(validator: SQLValidator) -> None:
    sql = "SELECT FROM WHERE"
    with pytest.raises(SQLSecurityError, match="Malformed SQL syntax"):
        validator.validate_and_sanitize(sql)


# -----------------------------------------------------------------------------
# Mutating DDL / DML / Admin Statements
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutating_sql",
    [
        "DROP TABLE organizations",
        "DELETE FROM organizations WHERE org_id = 'org_01'",
        "UPDATE organizations SET mrr_usd = 999999 WHERE org_id = 'org_01'",
        "INSERT INTO organizations (org_id, org_name) VALUES ('x', 'y')",
        "CREATE TABLE test_leak AS SELECT * FROM organizations",
        "ALTER TABLE organizations ADD COLUMN hacked TEXT",
        "TRUNCATE TABLE organizations",
        "COPY organizations TO '/tmp/leak.csv'",
        "PRAGMA memory_limit = '10GB'",
        "ATTACH '/tmp/malicious.db'",
        "DETACH my_db",
    ],
)
def test_mutating_operations_blocked(validator: SQLValidator, mutating_sql: str) -> None:
    with pytest.raises(SQLSecurityError) as exc_info:
        validator.validate_and_sanitize(mutating_sql)
    assert exc_info.value.violation_category in {
        "FORBIDDEN_STATEMENT_TYPE",
        "MUTATING_OR_ADMIN_OPERATION",
    }


def test_select_into_blocked(validator: SQLValidator) -> None:
    sql = "SELECT org_name INTO new_table FROM organizations"
    with pytest.raises(SQLSecurityError, match="SELECT ... INTO"):
        validator.validate_and_sanitize(sql)


# -----------------------------------------------------------------------------
# DuckDB SSRF / External File Reads / DoS Functions
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "SELECT * FROM read_csv('/etc/passwd')",
        "SELECT * FROM read_csv_auto('http://169.254.169.254/latest/meta-data/')",
        "SELECT * FROM read_parquet('s3://internal-bucket/data.parquet')",
        "SELECT * FROM parquet_scan('confidential.parquet')",
        "SELECT * FROM glob('*.csv')",
        "SELECT * FROM st_read('/secret/shape.shp')",
        "SELECT org_name FROM organizations WHERE repeat('a', 1000000) = 'a'",
        "SELECT org_name FROM organizations WHERE sleep(5) = 0",
    ],
)
def test_forbidden_functions_blocked(validator: SQLValidator, payload: str) -> None:
    with pytest.raises(SQLSecurityError, match="Forbidden DuckDB function"):
        validator.validate_and_sanitize(payload)


def test_file_path_table_reference_blocked(validator: SQLValidator) -> None:
    sql = "SELECT * FROM '/etc/shadow'"
    with pytest.raises(SQLSecurityError, match="External file path, URL, or cross-catalog"):
        validator.validate_and_sanitize(sql)


# -----------------------------------------------------------------------------
# Cartesian Joins & DoS Fan-out
# -----------------------------------------------------------------------------


def test_cartesian_cross_join_blocked(validator: SQLValidator) -> None:
    sql = "SELECT a.org_name, b.tool_name FROM organizations a CROSS JOIN tool_invocations b"
    with pytest.raises(SQLSecurityError, match="Cartesian"):
        validator.validate_and_sanitize(sql)


def test_cartesian_comma_join_blocked(validator: SQLValidator) -> None:
    sql = "SELECT a.org_name, b.tool_name FROM organizations a, tool_invocations b"
    with pytest.raises(SQLSecurityError, match="Cartesian"):
        validator.validate_and_sanitize(sql)


@pytest.mark.parametrize(
    "tautology_join",
    [
        "SELECT a.org_name, b.tool_name FROM organizations a JOIN tool_invocations b ON 1=1",
        "SELECT a.org_name, b.tool_name FROM organizations a JOIN tool_invocations b ON true",
        "SELECT a.org_name, b.tool_name FROM organizations a JOIN tool_invocations b ON 'a'='a'",
    ],
)
def test_cartesian_literal_tautology_blocked(validator: SQLValidator, tautology_join: str) -> None:
    with pytest.raises(SQLSecurityError, match="Degenerate Cartesian JOIN with literal tautology"):
        validator.validate_and_sanitize(tautology_join)


def test_constrained_join_allowed(validator: SQLValidator) -> None:
    sql = (
        "SELECT o.org_name, s.server_name "
        "FROM organizations o "
        "JOIN mcp_servers s ON o.org_id = s.org_id"
    )
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.is_safe is True
    assert set(res.tables_accessed) == {"organizations", "mcp_servers"}


def test_excessive_join_count_blocked(validator: SQLValidator) -> None:
    # 5 joins exceeds max_joins=4
    sql = (
        "SELECT o.org_name "
        "FROM organizations o "
        "JOIN mcp_servers s1 ON o.org_id = s1.org_id "
        "JOIN mcp_servers s2 ON o.org_id = s2.org_id "
        "JOIN mcp_servers s3 ON o.org_id = s3.org_id "
        "JOIN mcp_servers s4 ON o.org_id = s4.org_id "
        "JOIN mcp_servers s5 ON o.org_id = s5.org_id"
    )
    with pytest.raises(SQLSecurityError, match="exceeding the safety maximum"):
        validator.validate_and_sanitize(sql)


# -----------------------------------------------------------------------------
# RBAC Table Governance
# -----------------------------------------------------------------------------


def test_unknown_table_rejected(validator: SQLValidator) -> None:
    sql = "SELECT id FROM users"
    with pytest.raises(SQLSecurityError, match="Unknown table 'users'"):
        validator.validate_and_sanitize(sql)


def test_admin_only_table_blocked_for_analyst(validator: SQLValidator) -> None:
    sql = "SELECT key_id FROM api_keys"
    with pytest.raises(SQLSecurityError, match="restricted to 'admin' role"):
        validator.validate_and_sanitize(sql, role=Role.ANALYST)


def test_admin_only_table_blocked_for_public_viewer(validator: SQLValidator) -> None:
    sql = "SELECT incident_id FROM security_incidents"
    with pytest.raises(SQLSecurityError, match="restricted to 'admin' role"):
        validator.validate_and_sanitize(sql, role=Role.PUBLIC_VIEWER)


def test_admin_only_table_allowed_for_admin(validator: SQLValidator) -> None:
    sql = "SELECT incident_id, attack_vector FROM security_incidents"
    res = validator.validate_and_sanitize(sql, role=Role.ADMIN)
    assert res.is_safe is True
    assert "security_incidents" in res.tables_accessed


# -----------------------------------------------------------------------------
# Column-Level PII & Secret Governance
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pii_sql,target_col",
    [
        ("SELECT billing_email FROM organizations", "billing_email"),
        ("SELECT stripe_customer_id FROM organizations", "stripe_customer_id"),
        ("SELECT webhook_secret FROM mcp_servers", "webhook_secret"),
        ("SELECT client_ip FROM tool_invocations", "client_ip"),
    ],
)
def test_pii_columns_blocked_for_analyst(
    validator: SQLValidator, pii_sql: str, target_col: str
) -> None:
    with pytest.raises(SQLSecurityError, match=f"column '{target_col}' contains restricted PII"):
        validator.validate_and_sanitize(pii_sql, role=Role.ANALYST)


def test_pii_columns_allowed_for_admin(validator: SQLValidator) -> None:
    sql = "SELECT org_name, billing_email, stripe_customer_id FROM organizations"
    res = validator.validate_and_sanitize(sql, role=Role.ADMIN)
    assert res.is_safe is True
    assert "billing_email" in res.columns_accessed


def test_select_star_blocked_on_pii_table_for_analyst(validator: SQLValidator) -> None:
    sql = "SELECT * FROM organizations"
    with pytest.raises(SQLSecurityError, match="Wildcard 'SELECT \\*' is blocked on PII-bearing table"):
        validator.validate_and_sanitize(sql, role=Role.ANALYST)


def test_select_star_allowed_for_admin(validator: SQLValidator) -> None:
    sql = "SELECT * FROM organizations"
    res = validator.validate_and_sanitize(sql, role=Role.ADMIN)
    assert res.is_safe is True


def test_count_star_allowed_for_analyst(validator: SQLValidator) -> None:
    sql = "SELECT COUNT(*) FROM organizations"
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.is_safe is True


# -----------------------------------------------------------------------------
# Row Limit Injection & Clamping
# -----------------------------------------------------------------------------


def test_limit_injected_when_missing(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations"
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.limit_applied == 100
    assert "LIMIT 100" in (res.sanitized_sql or "")


def test_limit_clamped_when_exceeding_max(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations LIMIT 5000"
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.limit_applied == 1000
    assert "LIMIT 1000" in (res.sanitized_sql or "")


def test_smaller_limit_respected(validator: SQLValidator) -> None:
    sql = "SELECT org_name FROM organizations LIMIT 25"
    res = validator.validate_and_sanitize(sql, role=Role.ANALYST)
    assert res.limit_applied == 25
    assert "LIMIT 25" in (res.sanitized_sql or "")


# -----------------------------------------------------------------------------
# inspect_query Non-Raising Wrapper
# -----------------------------------------------------------------------------


def test_inspect_query_returns_diagnostics(validator: SQLValidator) -> None:
    res_bad = validator.inspect_query("DROP TABLE organizations", role=Role.ANALYST)
    assert res_bad.is_safe is False
    assert res_bad.violation_category == "FORBIDDEN_STATEMENT_TYPE"
    assert res_bad.violation_reason is not None

    res_good = validator.inspect_query("SELECT org_name FROM organizations", role=Role.ANALYST)
    assert res_good.is_safe is True
    assert res_good.sanitized_sql is not None
    assert res_good.limit_applied == 100
