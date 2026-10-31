"""Comprehensive tests for standalone PR example (examples/secure_db_server_example.py)."""

import json
import pytest
from examples.secure_db_server_example import (
    CallerPrincipal,
    Role,
    engine as example_engine,
    server as example_server,
    set_current_principal,
    QueryTimeoutError,
)


@pytest.mark.asyncio
async def test_example_server_whoami() -> None:
    set_current_principal(CallerPrincipal(subject="usr_test", role=Role.ANALYST))
    result = await example_server.call_tool("whoami", {})
    text = result[0][0].text if isinstance(result, tuple) else result.content[0].text
    data = json.loads(text)
    assert data["role"] == "analyst"
    assert data["subject"] == "usr_test"


@pytest.mark.asyncio
async def test_example_server_list_tables() -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    result = await example_server.call_tool("list_tables", {})
    if isinstance(result, tuple):
        tables = result[1]["result"]
    else:
        tables = [json.loads(c.text) for c in result.content]
    assert len(tables) == 4
    names = {t["table_name"] for t in tables}
    assert names == {"organizations", "mcp_servers", "tool_invocations", "subscriptions"}


@pytest.mark.asyncio
async def test_example_server_describe_table() -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    result = await example_server.call_tool("describe_table", {"table_name": "organizations"})
    text = result[0][0].text if isinstance(result, tuple) else result.content[0].text
    data = json.loads(text)
    assert data["table_name"] == "organizations"
    assert data["caller_role"] == "analyst"
    assert data["select_star_allowed"] is False
    cols = {c["column_name"] for c in data["columns"]}
    assert "org_name" in cols
    assert "billing_email" in cols


@pytest.mark.asyncio
async def test_example_server_verify_query_safety() -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    # Safe query with comment-like string literal
    res_safe = await example_server.call_tool(
        "verify_query_safety",
        {"sql": "SELECT org_name FROM organizations WHERE org_name = 'foo--bar'"},
    )
    text_safe = res_safe[0][0].text if isinstance(res_safe, tuple) else res_safe.content[0].text
    data_safe = json.loads(text_safe)
    assert data_safe["is_safe"] is True

    # Mutating query
    res_unsafe = await example_server.call_tool(
        "verify_query_safety",
        {"sql": "DROP TABLE organizations"},
    )
    text_unsafe = res_unsafe[0][0].text if isinstance(res_unsafe, tuple) else res_unsafe.content[0].text
    data_unsafe = json.loads(text_unsafe)
    assert data_unsafe["is_safe"] is False


@pytest.mark.asyncio
async def test_example_server_execute_sql() -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    res = await example_server.call_tool(
        "execute_analytical_sql",
        {"sql": "SELECT org_name, mrr_usd FROM organizations WHERE mrr_usd > 2000"},
    )
    text = res[0][0].text if isinstance(res, tuple) else res.content[0].text
    data = json.loads(text)
    assert data["status"] == "success"
    assert data["row_count"] > 0
    assert "org_name" in data["columns"]

    # Blocked for public viewer
    set_current_principal(CallerPrincipal(role=Role.PUBLIC_VIEWER))
    with pytest.raises(Exception, match="Role 'public_viewer' cannot execute queries"):
        await example_server.call_tool(
            "execute_analytical_sql",
            {"sql": "SELECT org_name FROM organizations"},
        )


@pytest.mark.asyncio
async def test_example_server_get_security_audit_log() -> None:
    set_current_principal(CallerPrincipal(role=Role.ADMIN))
    res = await example_server.call_tool("get_security_audit_log", {"limit": 10})
    if isinstance(res, tuple):
        events = res[1]["result"]
    else:
        events = [json.loads(c.text) for c in res.content]
    assert isinstance(events, list)

    # Blocked for analyst
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    with pytest.raises(Exception, match="Admin role required"):
        await example_server.call_tool("get_security_audit_log", {})


@pytest.mark.asyncio
async def test_example_server_resources() -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    # Catalog
    catalog_res = await example_server.read_resource("schema://catalog")
    assert len(catalog_res) > 0
    catalog = json.loads(catalog_res[0].content)
    assert len(catalog) == 4

    # Table Schema
    schema_res = await example_server.read_resource("schema://tables/mcp_servers")
    assert len(schema_res) > 0
    schema = json.loads(schema_res[0].content)
    assert schema["table_name"] == "mcp_servers"

    # Security Rules
    rules_res = await example_server.read_resource("policy://security-rules")
    assert len(rules_res) > 0
    assert "4-Layer Defense-in-Depth Policy" in rules_res[0].content


@pytest.mark.asyncio
async def test_example_server_resource_read_honors_rbac_on_request(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp.types as types

    handler = example_server._mcp_server.request_handlers[types.ReadResourceRequest]
    req = types.ReadResourceRequest(
        method="resources/read",
        params=types.ReadResourceRequestParams(uri="schema://catalog"),
    )

    monkeypatch.setenv("MCP_DEFAULT_TOKEN", "token-admin-demo")
    res_admin = await handler(req)
    tables_admin = json.loads(res_admin.root.contents[0].text)
    assert len(tables_admin) == 6

    monkeypatch.setenv("MCP_DEFAULT_TOKEN", "token-analyst-demo")
    res_analyst = await handler(req)
    tables_analyst = json.loads(res_analyst.root.contents[0].text)
    assert len(tables_analyst) == 4


@pytest.mark.asyncio
async def test_example_server_prompts() -> None:
    # executive_analytics
    p1 = await example_server.get_prompt("executive_analytics", {"focus": "mrr_growth"})
    assert p1 is not None
    assert "mrr_growth" in p1.messages[0].content.text

    # red_team_security_audit
    p2 = await example_server.get_prompt("red_team_security_audit", {"target_vector": "cartesian_dos"})
    assert p2 is not None
    assert "cartesian_dos" in p2.messages[0].content.text


def test_example_engine_watchdog_timeout() -> None:
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
    with pytest.raises(QueryTimeoutError, match="Query aborted after"):
        example_engine.query(heavy_sql, role=Role.ADMIN, timeout=0.001)
