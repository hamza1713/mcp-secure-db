"""Tests for Layer 1: RBAC Middleware, BearerAuth Provider, and Token Resolution."""

from datetime import datetime, UTC
import pytest
from mcp.types import CallToolRequestParams, PaginatedRequestParams, ServerResult, ListToolsResult, Tool
from mcp_use.server.middleware import ServerMiddlewareContext
from mcp_secure_db.security.rbac import (
    ROLE_ALLOWED_TOOLS,
    CallerPrincipal,
    RBACMiddleware,
    Role,
    SecureDBBearerAuthProvider,
    get_current_principal,
    resolve_principal_from_token,
    set_current_principal,
)


# -----------------------------------------------------------------------------
# Token Resolution & BearerAuthProvider
# -----------------------------------------------------------------------------


def test_resolve_principal_tokens() -> None:
    viewer = resolve_principal_from_token("token-viewer-demo")
    assert viewer is not None
    assert viewer.role == Role.PUBLIC_VIEWER
    assert viewer.subject == "usr_viewer_01"

    analyst = resolve_principal_from_token("Bearer token-analyst-demo")
    assert analyst is not None
    assert analyst.role == Role.ANALYST
    assert analyst.subject == "usr_analyst_01"

    admin = resolve_principal_from_token("token-admin-demo")
    assert admin is not None
    assert admin.role == Role.ADMIN
    assert admin.subject == "usr_admin_01"

    invalid = resolve_principal_from_token("unknown-token")
    assert invalid is None


@pytest.mark.asyncio
async def test_bearer_auth_provider() -> None:
    provider = SecureDBBearerAuthProvider()

    token_obj = await provider.verify_token("token-analyst-demo")
    assert token_obj is not None
    assert token_obj.claims["role"] == "analyst"
    assert "sql:execute_bounded" in token_obj.scopes

    invalid_obj = await provider.verify_token("token-garbage")
    assert invalid_obj is None


# -----------------------------------------------------------------------------
# RBACMiddleware Resolution
# -----------------------------------------------------------------------------


def _make_context(
    method: str,
    headers: dict[str, str] | None = None,
    message: any = None,
) -> ServerMiddlewareContext[any]:
    return ServerMiddlewareContext(
        message=message,
        method=method,
        timestamp=datetime.now(UTC),
        transport="streamable-http",
        headers=headers,
    )


def test_rbac_middleware_resolves_bearer_header() -> None:
    middleware = RBACMiddleware()
    ctx = _make_context("tools/call", headers={"authorization": "Bearer token-admin-demo"})
    principal = middleware._resolve_caller(ctx)
    assert principal.role == Role.ADMIN
    assert principal.subject == "usr_admin_01"


def test_rbac_middleware_resolves_api_key_header() -> None:
    middleware = RBACMiddleware()
    ctx = _make_context("tools/call", headers={"x-api-key": "token-analyst-demo"})
    principal = middleware._resolve_caller(ctx)
    assert principal.role == Role.ANALYST
    assert principal.subject == "usr_analyst_01"


def test_rbac_middleware_invalid_token_header_raises() -> None:
    middleware = RBACMiddleware()
    ctx = _make_context("tools/call", headers={"authorization": "Bearer bogus"})
    with pytest.raises(PermissionError, match="Invalid authentication token"):
        middleware._resolve_caller(ctx)


def test_rbac_middleware_fallback_to_public_viewer() -> None:
    middleware = RBACMiddleware(strict_auth=False)
    ctx = _make_context("tools/call", headers={})
    principal = middleware._resolve_caller(ctx)
    assert principal.role == Role.PUBLIC_VIEWER
    assert principal.authenticated_via == "hybrid_default_fallback"


def test_rbac_middleware_strict_auth_blocks_missing_token() -> None:
    middleware = RBACMiddleware(strict_auth=True)
    ctx = _make_context("tools/call", headers={})
    with pytest.raises(PermissionError, match="Authentication required"):
        middleware._resolve_caller(ctx)


# -----------------------------------------------------------------------------
# Tool Call Enforcement (on_call_tool)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_call_tool_allows_permitted_and_blocks_unauthorized() -> None:
    middleware = RBACMiddleware()
    called = []

    async def mock_call_next(ctx: ServerMiddlewareContext[CallToolRequestParams]) -> str:
        called.append(ctx.message.name)
        return "ok"

    # 1. Public viewer calls permitted tool
    ctx_whoami = _make_context(
        "tools/call",
        headers={"authorization": "Bearer token-viewer-demo"},
        message=CallToolRequestParams(name="whoami", arguments={}),
    )
    res = await middleware.on_call_tool(ctx_whoami, mock_call_next)
    assert res == "ok"
    assert "whoami" in called

    # 2. Public viewer calls blocked tool (execute_analytical_sql)
    ctx_sql = _make_context(
        "tools/call",
        headers={"authorization": "Bearer token-viewer-demo"},
        message=CallToolRequestParams(name="execute_analytical_sql", arguments={"sql": "SELECT 1"}),
    )
    with pytest.raises(PermissionError, match="role 'public_viewer' is not authorized to invoke tool 'execute_analytical_sql'"):
        await middleware.on_call_tool(ctx_sql, mock_call_next)

    # 3. Analyst calls execute_analytical_sql (permitted)
    ctx_analyst_sql = _make_context(
        "tools/call",
        headers={"authorization": "Bearer token-analyst-demo"},
        message=CallToolRequestParams(name="execute_analytical_sql", arguments={"sql": "SELECT 1"}),
    )
    res_analyst = await middleware.on_call_tool(ctx_analyst_sql, mock_call_next)
    assert res_analyst == "ok"

    # 4. Analyst calls get_security_audit_log (blocked, requires admin)
    ctx_analyst_audit = _make_context(
        "tools/call",
        headers={"authorization": "Bearer token-analyst-demo"},
        message=CallToolRequestParams(name="get_security_audit_log", arguments={}),
    )
    with pytest.raises(PermissionError, match="role 'analyst' is not authorized to invoke tool 'get_security_audit_log'"):
        await middleware.on_call_tool(ctx_analyst_audit, mock_call_next)

    # 5. Admin calls get_security_audit_log (permitted)
    ctx_admin_audit = _make_context(
        "tools/call",
        headers={"authorization": "Bearer token-admin-demo"},
        message=CallToolRequestParams(name="get_security_audit_log", arguments={}),
    )
    res_admin = await middleware.on_call_tool(ctx_admin_audit, mock_call_next)
    assert res_admin == "ok"


# -----------------------------------------------------------------------------
# Dynamic Tool Listing Filter (on_list_tools)
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_list_tools_filters_per_role() -> None:
    middleware = RBACMiddleware()
    all_tools = [
        Tool(name="whoami", inputSchema={}),
        Tool(name="list_tables", inputSchema={}),
        Tool(name="describe_table", inputSchema={}),
        Tool(name="verify_query_safety", inputSchema={}),
        Tool(name="execute_analytical_sql", inputSchema={}),
        Tool(name="get_security_audit_log", inputSchema={}),
    ]

    async def mock_call_next(_: ServerMiddlewareContext[PaginatedRequestParams | None]) -> ServerResult:
        return ServerResult(root=ListToolsResult(tools=list(all_tools)))

    # Public viewer sees 4 tools
    ctx_viewer = _make_context("tools/list", headers={"authorization": "Bearer token-viewer-demo"})
    res_viewer = await middleware.on_list_tools(ctx_viewer, mock_call_next)
    viewer_names = [t.name for t in res_viewer.root.tools]
    assert viewer_names == ["whoami", "list_tables", "describe_table", "verify_query_safety"]

    # Analyst sees 5 tools
    ctx_analyst = _make_context("tools/list", headers={"authorization": "Bearer token-analyst-demo"})
    res_analyst = await middleware.on_list_tools(ctx_analyst, mock_call_next)
    analyst_names = [t.name for t in res_analyst.root.tools]
    assert analyst_names == [
        "whoami",
        "list_tables",
        "describe_table",
        "verify_query_safety",
        "execute_analytical_sql",
    ]

    # Admin sees all 6 tools
    ctx_admin = _make_context("tools/list", headers={"authorization": "Bearer token-admin-demo"})
    res_admin = await middleware.on_list_tools(ctx_admin, mock_call_next)
    admin_names = [t.name for t in res_admin.root.tools]
    assert len(admin_names) == 6
