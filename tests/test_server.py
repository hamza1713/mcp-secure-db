"""Integration tests for MCPServer instance, tools, resources, and prompts."""

import json
import pytest
from mcp_secure_db.security.rbac import (
    CallerPrincipal,
    Role,
    set_current_principal,
)
from mcp_secure_db.server import create_server


@pytest.fixture
def mcp_server():
    return create_server()


# -----------------------------------------------------------------------------
# Tool Execution Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_whoami(mcp_server) -> None:
    set_current_principal(
        CallerPrincipal(
            subject="usr_test_analyst",
            email="analyst@test.com",
            role=Role.ANALYST,
            scopes=["schema:read", "sql:execute_bounded"],
            authenticated_via="test_fixture",
        )
    )
    result = await mcp_server.call_tool("whoami", {})
    # FastMCP returns tuple or CallToolResult
    # Let's extract structured content or parse JSON text
    text_content = result[0][0].text if isinstance(result, tuple) else result.content[0].text
    data = json.loads(text_content)
    assert data["role"] == "analyst"
    assert data["subject"] == "usr_test_analyst"
    assert "execute_analytical_sql" in data["allowed_tools"]
    assert "api_keys" not in data["accessible_tables"]


@pytest.mark.asyncio
async def test_tool_list_tables(mcp_server) -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    result = await mcp_server.call_tool("list_tables", {})
    if isinstance(result, tuple):
        tables = result[1]["result"]
    else:
        tables = [json.loads(c.text) for c in result.content]
    assert len(tables) == 4
    table_names = {t["table_name"] for t in tables}
    assert table_names == {"organizations", "mcp_servers", "tool_invocations", "subscriptions"}


@pytest.mark.asyncio
async def test_tool_describe_table(mcp_server) -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    result = await mcp_server.call_tool("describe_table", {"table_name": "organizations"})
    text = result[0][0].text if isinstance(result, tuple) else result.content[0].text
    data = json.loads(text)
    assert data["table_name"] == "organizations"
    assert data["select_star_allowed_for_caller"] is False
    cols = {c["column_name"] for c in data["columns"]}
    assert "billing_email" in cols
    assert "org_name" in cols


@pytest.mark.asyncio
async def test_tool_verify_query_safety(mcp_server) -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    # Safe query
    res_safe = await mcp_server.call_tool(
        "verify_query_safety",
        {"sql": "SELECT org_name, mrr_usd FROM organizations", "requested_limit": 50},
    )
    text_safe = res_safe[0][0].text if isinstance(res_safe, tuple) else res_safe.content[0].text
    data_safe = json.loads(text_safe)
    assert data_safe["is_safe"] is True
    assert data_safe["limit_applied"] == 50

    # Unsafe query
    res_unsafe = await mcp_server.call_tool(
        "verify_query_safety",
        {"sql": "DROP TABLE organizations"},
    )
    text_unsafe = res_unsafe[0][0].text if isinstance(res_unsafe, tuple) else res_unsafe.content[0].text
    data_unsafe = json.loads(text_unsafe)
    assert data_unsafe["is_safe"] is False
    assert data_unsafe["violation_category"] == "FORBIDDEN_STATEMENT_TYPE"


@pytest.mark.asyncio
async def test_tool_execute_analytical_sql_analyst(mcp_server) -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    res = await mcp_server.call_tool(
        "execute_analytical_sql",
        {"sql": "SELECT org_name, plan_tier, mrr_usd FROM organizations WHERE mrr_usd > 2000", "limit": 10},
    )
    text = res[0][0].text if isinstance(res, tuple) else res.content[0].text
    data = json.loads(text)
    assert data["status"] == "success"
    assert data["row_count"] > 0
    assert len(data["rows"]) == data["row_count"]
    assert "org_name" in data["columns"]


@pytest.mark.asyncio
async def test_tool_execute_analytical_sql_blocked_for_public_viewer(mcp_server) -> None:
    set_current_principal(CallerPrincipal(role=Role.PUBLIC_VIEWER))
    with pytest.raises(Exception, match="Role 'public_viewer' is restricted"):
        await mcp_server.call_tool(
            "execute_analytical_sql",
            {"sql": "SELECT org_name FROM organizations"},
        )


@pytest.mark.asyncio
async def test_tool_get_security_audit_log_admin_vs_analyst(mcp_server) -> None:
    # Admin accesses log
    set_current_principal(CallerPrincipal(role=Role.ADMIN))
    res_admin = await mcp_server.call_tool("get_security_audit_log", {"limit": 10})
    text = res_admin[0][0].text if isinstance(res_admin, tuple) else res_admin.content[0].text
    data = json.loads(text)
    assert data["caller_role"] == "admin"
    assert "summary_stats" in data
    assert "recent_events" in data

    # Analyst blocked
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    with pytest.raises(Exception, match="is not authorized to inspect security audit logs"):
        await mcp_server.call_tool("get_security_audit_log", {})


# -----------------------------------------------------------------------------
# Resource Reading Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_resource_catalog(mcp_server) -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    contents = await mcp_server.read_resource("schema://catalog")
    assert len(contents) > 0
    data = json.loads(contents[0].content)
    assert data["catalog_name"] == "manufact_cloud_telemetry"
    assert data["tables_count"] == 4


@pytest.mark.asyncio
async def test_read_resource_table_schema(mcp_server) -> None:
    set_current_principal(CallerPrincipal(role=Role.ANALYST))
    contents = await mcp_server.read_resource("schema://tables/mcp_servers")
    assert len(contents) > 0
    data = json.loads(contents[0].content)
    assert data["table_name"] == "mcp_servers"
    assert len(data["columns"]) > 0


@pytest.mark.asyncio
async def test_read_resource_security_rules(mcp_server) -> None:
    contents = await mcp_server.read_resource("policy://security-rules")
    assert len(contents) > 0
    text = contents[0].content
    assert "# MCP Secure DB Defense-in-Depth Policy" in text
    assert "Layer 1" in text
    assert "Layer 2" in text
    assert "Layer 3" in text
    assert "Layer 4" in text


# -----------------------------------------------------------------------------
# Prompt Generation Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_prompt_executive_analytics(mcp_server) -> None:
    prompt = await mcp_server.get_prompt("executive_analytics", {"focus_area": "token_efficiency"})
    assert prompt is not None
    prompt_text = prompt.messages[0].content.text
    assert "Chief AI Systems Analyst at Manufact Cloud" in prompt_text
    assert "token_efficiency" in prompt_text
    assert "Pietro and Luigi" in prompt_text


@pytest.mark.asyncio
async def test_prompt_red_team_security_audit(mcp_server) -> None:
    prompt = await mcp_server.get_prompt("red_team_security_audit", {"target_vector": "external_file_ssrf"})
    assert prompt is not None
    prompt_text = prompt.messages[0].content.text
    assert "Adversarial Security Red-Team Engineer" in prompt_text
    assert "read_csv_auto('/etc/passwd')" in prompt_text


# -----------------------------------------------------------------------------
# Middleware on_request & Hybrid HTTP Auth Regression Tests
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resource_read_honors_rbac_middleware_on_request(mcp_server, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify resources/read goes through RBACMiddleware.on_request so admin sees all 6 tables."""
    import mcp.types as types

    handler = mcp_server._mcp_server.request_handlers[types.ReadResourceRequest]

    # 1. Admin via MCP_DEFAULT_TOKEN -> sees 6 tables
    monkeypatch.setenv("MCP_DEFAULT_TOKEN", "token-admin-demo")
    req = types.ReadResourceRequest(
        method="resources/read",
        params=types.ReadResourceRequestParams(uri="schema://catalog"),
    )
    res_admin = await handler(req)
    payload_admin = json.loads(res_admin.root.contents[0].text)
    assert payload_admin["viewer_role"] == "admin"
    assert payload_admin["tables_count"] == 6

    # 2. Analyst via MCP_DEFAULT_TOKEN -> sees 4 tables
    monkeypatch.setenv("MCP_DEFAULT_TOKEN", "token-analyst-demo")
    res_analyst = await handler(req)
    payload_analyst = json.loads(res_analyst.root.contents[0].text)
    assert payload_analyst["viewer_role"] == "analyst"
    assert payload_analyst["tables_count"] == 4


@pytest.mark.asyncio
async def test_hybrid_http_auth_middleware() -> None:
    """Verify HybridHTTPAuthMiddleware handles unauthenticated, Bearer, x-api-key, and strict modes."""
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from httpx import AsyncClient, ASGITransport
    from mcp_use.server.auth import get_access_token
    from mcp_secure_db.security.rbac import HybridHTTPAuthMiddleware, SecureDBBearerAuthProvider

    async def mcp_endpoint(request):
        tok = get_access_token()
        return JSONResponse({
            "authenticated": tok is not None,
            "role": tok.claims.get("role") if tok else "public_viewer",
        })

    app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST", "GET"])])
    app.add_middleware(
        HybridHTTPAuthMiddleware,
        auth_provider=SecureDBBearerAuthProvider(),
        strict_auth=False,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Unauthenticated in Hybrid mode -> 200 OK, public_viewer
        r_unauth = await client.post("/mcp")
        assert r_unauth.status_code == 200
        assert r_unauth.json() == {"authenticated": False, "role": "public_viewer"}

        # 2. Valid Bearer token -> 200 OK, analyst
        r_bearer = await client.post("/mcp", headers={"Authorization": "Bearer token-analyst-demo"})
        assert r_bearer.status_code == 200
        assert r_bearer.json() == {"authenticated": True, "role": "analyst"}

        # 3. Valid x-api-key header -> 200 OK, admin
        r_apikey = await client.post("/mcp", headers={"x-api-key": "token-admin-demo"})
        assert r_apikey.status_code == 200
        assert r_apikey.json() == {"authenticated": True, "role": "admin"}

        # 4. Invalid Bearer token -> 401 Unauthorized
        r_invalid = await client.post("/mcp", headers={"Authorization": "Bearer bad-token"})
        assert r_invalid.status_code == 401
        assert r_invalid.json()["error"] == "invalid_token"

    # 5. Strict mode rejects unauthenticated /mcp requests with 401
    strict_app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])
    strict_app.add_middleware(
        HybridHTTPAuthMiddleware,
        auth_provider=SecureDBBearerAuthProvider(),
        strict_auth=True,
    )
    async with AsyncClient(transport=ASGITransport(app=strict_app), base_url="http://testserver") as strict_client:
        r_strict = await strict_client.post("/mcp")
        assert r_strict.status_code == 401
        assert r_strict.json()["error"] == "unauthorized"

