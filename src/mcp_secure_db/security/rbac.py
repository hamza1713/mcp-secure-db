"""Layer 1: Role-Based Access Control (RBAC) via mcp-use BearerAuthProvider & Middleware."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextvars import ContextVar
from enum import StrEnum
from typing import Any

from mcp.types import CallToolRequestParams, PaginatedRequestParams
from mcp_use.server.auth import AccessToken, BearerAuthProvider, get_access_token
from mcp_use.server.middleware import CallNext, Middleware, ServerMiddlewareContext
from pydantic import BaseModel, Field


class Role(StrEnum):
    """Caller privilege levels enforced across tools, tables, and columns."""

    PUBLIC_VIEWER = "public_viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


# Tools exposed and permitted per role
ROLE_ALLOWED_TOOLS: dict[Role, set[str]] = {
    Role.PUBLIC_VIEWER: {
        "whoami",
        "list_tables",
        "describe_table",
        "verify_query_safety",
    },
    Role.ANALYST: {
        "whoami",
        "list_tables",
        "describe_table",
        "verify_query_safety",
        "execute_analytical_sql",
    },
    Role.ADMIN: {
        "whoami",
        "list_tables",
        "describe_table",
        "verify_query_safety",
        "execute_analytical_sql",
        "get_security_audit_log",
    },
}

# Tables completely hidden/blocked from non-admin roles
ADMIN_ONLY_TABLES: frozenset[str] = frozenset({"api_keys", "security_incidents"})

# All known tables in the analytical warehouse
ALL_KNOWN_TABLES: frozenset[str] = frozenset(
    {
        "organizations",
        "mcp_servers",
        "tool_invocations",
        "subscriptions",
        "api_keys",
        "security_incidents",
    }
)

# Columns containing PII or secrets that require Role.ADMIN
PII_COLUMNS_BY_TABLE: dict[str, frozenset[str]] = {
    "organizations": frozenset({"billing_email", "stripe_customer_id"}),
    "mcp_servers": frozenset({"webhook_secret"}),
    "tool_invocations": frozenset({"client_ip"}),
    "subscriptions": frozenset({"stripe_customer_id"}),
    "api_keys": frozenset({"key_hash", "raw_token_prefix"}),
    "security_incidents": frozenset(),
}

# Safe (non-PII) columns per table for helpful LLM self-correction hints
SAFE_COLUMNS_BY_TABLE: dict[str, tuple[str, ...]] = {
    "organizations": ("org_id", "org_name", "plan_tier", "mrr_usd", "region", "created_at"),
    "mcp_servers": (
        "server_id",
        "org_id",
        "server_name",
        "runtime",
        "transport",
        "status",
        "memory_mb",
        "avg_cold_start_ms",
        "deployed_at",
    ),
    "tool_invocations": (
        "invocation_id",
        "server_id",
        "org_id",
        "tool_name",
        "status",
        "latency_ms",
        "tokens_saved",
        "invoked_at",
    ),
    "subscriptions": (
        "subscription_id",
        "org_id",
        "plan_tier",
        "monthly_quota_calls",
        "used_calls",
        "status",
        "renews_at",
    ),
    "api_keys": ("key_id", "org_id", "scope_role", "key_hash", "raw_token_prefix", "created_at", "last_used_at"),
    "security_incidents": ("incident_id", "org_id", "role", "attack_vector", "blocked_sql", "detected_at"),
}

RESTRICTED_PII_COLUMNS: frozenset[str] = frozenset().union(*PII_COLUMNS_BY_TABLE.values())


class CallerPrincipal(BaseModel):
    """Authenticated caller identity stored in request context."""

    subject: str = Field(default="anonymous-viewer", description="Caller identifier")
    email: str = Field(default="viewer@public.local", description="Caller email")
    role: Role = Field(default=Role.PUBLIC_VIEWER, description="Resolved RBAC role")
    scopes: list[str] = Field(default_factory=lambda: ["schema:read"])
    authenticated_via: str = Field(default="default_fallback", description="How caller was authenticated")


_current_principal: ContextVar[CallerPrincipal] = ContextVar(
    "mcp_secure_db_principal",
    default=CallerPrincipal(),
)


def get_current_principal() -> CallerPrincipal:
    """Return the active caller principal for the current request context."""
    return _current_principal.get()


def set_current_principal(principal: CallerPrincipal) -> None:
    """Bind the caller principal for the current request context."""
    _current_principal.set(principal)


def _build_token_registry() -> dict[str, CallerPrincipal]:
    """Build lookup dictionary of valid bearer/API tokens from defaults + environment."""
    viewer_token = os.environ.get("MCP_VIEWER_TOKEN", "token-viewer-demo")
    analyst_token = os.environ.get("MCP_ANALYST_TOKEN", "token-analyst-demo")
    admin_token = os.environ.get("MCP_ADMIN_TOKEN", "token-admin-demo")

    return {
        viewer_token: CallerPrincipal(
            subject="usr_viewer_01",
            email="viewer@manufact-demo.com",
            role=Role.PUBLIC_VIEWER,
            scopes=["schema:read"],
            authenticated_via="bearer_token",
        ),
        analyst_token: CallerPrincipal(
            subject="usr_analyst_01",
            email="analyst@manufact-demo.com",
            role=Role.ANALYST,
            scopes=["schema:read", "sql:execute_bounded"],
            authenticated_via="bearer_token",
        ),
        admin_token: CallerPrincipal(
            subject="usr_admin_01",
            email="admin@manufact-demo.com",
            role=Role.ADMIN,
            scopes=["schema:read", "sql:execute_bounded", "pii:read", "audit:read"],
            authenticated_via="bearer_token",
        ),
    }


def resolve_principal_from_token(raw_token: str | None) -> CallerPrincipal | None:
    """Resolve a bearer/API token string into a CallerPrincipal, or None if invalid."""
    if not raw_token:
        return None
    token_clean = raw_token.strip()
    if token_clean.lower().startswith("bearer "):
        token_clean = token_clean[7:].strip()
    registry = _build_token_registry()
    return registry.get(token_clean)


class SecureDBBearerAuthProvider(BearerAuthProvider):
    """Native mcp-use BearerAuthProvider implementation for strict HTTP Bearer setups."""

    async def verify_token(self, token: str) -> AccessToken | None:
        principal = resolve_principal_from_token(token)
        if principal is None:
            return None
        return AccessToken(
            token=token,
            claims={
                "sub": principal.subject,
                "email": principal.email,
                "role": str(principal.role),
            },
            scopes=principal.scopes,
        )


class RBACMiddleware(Middleware):
    """Hybrid RBAC Middleware for mcp-use servers.

    Features:
    1. Resolves caller identity from:
       - mcp-use `get_access_token()` (if BearerAuthProvider is attached)
       - HTTP headers (`Authorization: Bearer <token>` or `x-api-key: <token>`)
       - Environment fallback (`MCP_DEFAULT_TOKEN` or `MCP_DEFAULT_ROLE`), defaulting
         gracefully to `public_viewer` so MCP Inspector & stdio work out-of-the-box.
    2. Dynamically filters `tools/list` (`on_list_tools`) so unauthorized tools are
       invisible to lower-privileged agents.
    3. Enforces hard authorization on `tools/call` (`on_call_tool`) before execution.
    """

    def __init__(
        self,
        strict_auth: bool | None = None,
        audit_callback: Callable[[str, Role, str, str], None] | None = None,
    ) -> None:
        if strict_auth is None:
            strict_auth = os.environ.get("MCP_STRICT_AUTH", "false").lower() in {"1", "true", "yes"}
        self.strict_auth = strict_auth
        self.audit_callback = audit_callback

    def _resolve_caller(self, context: ServerMiddlewareContext[Any]) -> CallerPrincipal:
        """Resolve and validate the caller's role from headers, AccessToken, or fallback."""
        # 1. Check native mcp-use AccessToken context
        access_token = get_access_token()
        if access_token is not None:
            role_str = str(access_token.claims.get("role", Role.PUBLIC_VIEWER))
            try:
                role = Role(role_str)
            except ValueError:
                role = Role.PUBLIC_VIEWER
            return CallerPrincipal(
                subject=str(access_token.claims.get("sub", "token-user")),
                email=str(access_token.claims.get("email", "user@manufact-demo.com")),
                role=role,
                scopes=list(access_token.scopes),
                authenticated_via="mcp_use_access_token",
            )

        # 2. Check HTTP headers (case-insensitive)
        headers = {k.lower(): v for k, v in (context.headers or {}).items()}
        auth_header = headers.get("authorization")
        api_key_header = headers.get("x-api-key")

        explicit_token = auth_header or api_key_header
        if explicit_token:
            principal = resolve_principal_from_token(explicit_token)
            if principal is None:
                if self.audit_callback:
                    self.audit_callback(
                        context.method,
                        Role.PUBLIC_VIEWER,
                        "BLOCKED_RBAC",
                        "Invalid Bearer or x-api-key token supplied in HTTP headers",
                    )
                raise PermissionError(
                    "Invalid authentication token. For demo testing, use 'token-viewer-demo', "
                    "'token-analyst-demo', or 'token-admin-demo'."
                )
            return principal

        # 3. Check environment default token or role (useful for local stdio clients)
        env_token = os.environ.get("MCP_DEFAULT_TOKEN")
        if env_token:
            principal = resolve_principal_from_token(env_token)
            if principal is not None:
                return principal.model_copy(update={"authenticated_via": "env_default_token"})

        if self.strict_auth:
            if self.audit_callback:
                self.audit_callback(
                    context.method,
                    Role.PUBLIC_VIEWER,
                    "BLOCKED_RBAC",
                    "Missing authentication token in strict_auth mode",
                )
            raise PermissionError(
                "Authentication required: supply 'Authorization: Bearer <token>' or 'x-api-key' header."
            )

        env_role_str = os.environ.get("MCP_DEFAULT_ROLE", "public_viewer").lower().strip()
        try:
            fallback_role = Role(env_role_str)
        except ValueError:
            fallback_role = Role.PUBLIC_VIEWER

        scopes_by_role = {
            Role.PUBLIC_VIEWER: ["schema:read"],
            Role.ANALYST: ["schema:read", "sql:execute_bounded"],
            Role.ADMIN: ["schema:read", "sql:execute_bounded", "pii:read", "audit:read"],
        }
        return CallerPrincipal(
            subject=f"default-{fallback_role.value}",
            email=f"{fallback_role.value}@local.inspector",
            role=fallback_role,
            scopes=scopes_by_role[fallback_role],
            authenticated_via="hybrid_default_fallback",
        )

    async def on_list_tools(
        self,
        context: ServerMiddlewareContext[PaginatedRequestParams | None],
        call_next: CallNext[PaginatedRequestParams | None, Any],
    ) -> Any:
        """Filter tools/list dynamically based on the caller's RBAC role."""
        principal = self._resolve_caller(context)
        set_current_principal(principal)
        allowed = ROLE_ALLOWED_TOOLS[principal.role]

        response = await call_next(context)
        if hasattr(response, "root") and hasattr(response.root, "tools") and isinstance(response.root.tools, list):
            response.root.tools = [tool for tool in response.root.tools if getattr(tool, "name", None) in allowed]
            return response
        if isinstance(response, list):
            return [tool for tool in response if getattr(tool, "name", None) in allowed]
        if hasattr(response, "tools") and isinstance(response.tools, list):
            response.tools = [tool for tool in response.tools if getattr(tool, "name", None) in allowed]
        return response

    async def on_call_tool(
        self,
        context: ServerMiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, Any],
    ) -> Any:
        """Enforce hard RBAC tool authorization before invoking any tool handler."""
        principal = self._resolve_caller(context)
        set_current_principal(principal)

        tool_name = context.message.name
        allowed = ROLE_ALLOWED_TOOLS[principal.role]
        if tool_name not in allowed:
            reason = (
                f"Access denied: role '{principal.role.value}' is not authorized to invoke tool "
                f"'{tool_name}'. Allowed tools for '{principal.role.value}': {sorted(allowed)}."
            )
            if self.audit_callback:
                self.audit_callback(tool_name, principal.role, "BLOCKED_RBAC", reason)
            raise PermissionError(reason)

        return await call_next(context)
