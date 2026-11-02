"""Main MCP Server implementation using mcp-use MCPServer with 4-Layer Security."""

from __future__ import annotations

import json
import os
from typing import Any, Literal

from mcp.types import ToolAnnotations
from mcp_use.server import Context, MCPServer
from mcp_use.server.logging import MCPLoggingMiddleware
from starlette.middleware.cors import CORSMiddleware

from mcp_secure_db import __version__
from mcp_secure_db.database.engine import AuditLogger, SecureDuckDBEngine
from mcp_secure_db.security.rbac import (
    ADMIN_ONLY_TABLES,
    ALL_KNOWN_TABLES,
    PII_COLUMNS_BY_TABLE,
    ROLE_ALLOWED_TOOLS,
    SAFE_COLUMNS_BY_TABLE,
    CallerPrincipal,
    HybridHTTPAuthMiddleware,
    RBACMiddleware,
    Role,
    SecureDBBearerAuthProvider,
    get_current_principal,
    warn_if_default_tokens_in_use,
)
from mcp_secure_db.security.validator import SQLSecurityError, SQLValidationResult

TableNameType = Literal[
    "organizations",
    "mcp_servers",
    "tool_invocations",
    "subscriptions",
    "api_keys",
    "security_incidents",
]

AuditStatusFilter = Literal[
    "ALL",
    "ALLOWED",
    "BLOCKED_AST",
    "BLOCKED_RBAC",
    "TIMEOUT",
    "ERROR",
]

AnalyticsFocusArea = Literal[
    "mrr_growth",
    "server_reliability",
    "token_efficiency",
    "org_tier_distribution",
]

RedTeamVector = Literal[
    "comment_smuggling",
    "external_file_ssrf",
    "pii_exfiltration",
    "cartesian_dos",
    "ddl_mutation",
]


async def safe_ctx_log(ctx: Context | None, level: str, message: str) -> None:
    """Safely log to MCP client via Context without throwing if run without an active session."""
    if ctx is not None:
        try:
            log_fn = getattr(ctx, level, ctx.info)
            await log_fn(message)
        except Exception:
            pass


async def safe_ctx_progress(ctx: Context | None, current: float, total: float) -> None:
    """Safely report progress to client without throwing if run without an active session."""
    if ctx is not None:
        try:
            await ctx.report_progress(current, total)
        except Exception:
            pass


class SecureDBMCPServer(MCPServer):
    """MCPServer subclass integrating HybridHTTPAuthMiddleware for seamless Inspector + Bearer/API-key auth."""

    _strict_auth: bool = False
    _audit_callback: Any = None

    def streamable_http_app(self):
        from mcp.server.fastmcp import FastMCP
        from starlette.responses import RedirectResponse

        app = FastMCP.streamable_http_app(self)

        async def _root_redirect(_request):
            return RedirectResponse(url="/inspector", status_code=307)

        app.add_route("/", _root_redirect, methods=["GET"])
        app.add_middleware(
            MCPLoggingMiddleware,
            debug_level=self.debug_level,
            mcp_path=self.mcp_path,
            pretty_print_jsonrpc=self.pretty_print_jsonrpc,
        )
        if self._auth:
            app.add_middleware(
                HybridHTTPAuthMiddleware,
                auth_provider=self._auth,
                strict_auth=self._strict_auth,
                audit_callback=self._audit_callback,
            )
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=False,
                allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
                allow_headers=["*"],
                expose_headers=["WWW-Authenticate", "mcp-session-id"],
            )
        return app


def create_server(
    engine: SecureDuckDBEngine | None = None,
    rbac_middleware: RBACMiddleware | None = None,
    strict_auth: bool | None = None,
    debug: bool = True,
) -> MCPServer:
    """Create and configure a production-oriented mcp-use MCPServer instance.

    Features:
    - Layer 1: RBAC Middleware with BearerAuth fallback to public_viewer
    - Layer 2: Deterministic AST sqlglot validator (zero LLM token overhead)
    - Layer 3: In-memory DuckDB sandbox with memory/thread limits and conn.interrupt() watchdog
    - Layer 4: Structured output telemetry & in-memory audit ring buffer (lost on restart)
    - Full MCP primitives: Tools, Resources (schema:// and policy://), and Prompts
    """
    warn_if_default_tokens_in_use()

    if engine is None:
        engine = SecureDuckDBEngine()

    if rbac_middleware is None:
        rbac_middleware = RBACMiddleware(
            strict_auth=strict_auth,
            audit_callback=engine.audit_logger.record_rbac_event,
        )

    SecureDBMCPServer._strict_auth = rbac_middleware.strict_auth
    SecureDBMCPServer._audit_callback = engine.audit_logger.record_rbac_event

    server = SecureDBMCPServer(
        name="mcp-secure-db",
        version=__version__,
        instructions=(
            "mcp-secure-db: Reference implementation of a 4-layer sandboxed analytical database MCP server. "
            "Enforces zero-token AST validation, DuckDB memory limits, table/PII column RBAC, "
            "and in-memory audit provenance for Manufact Cloud."
        ),
        middleware=[rbac_middleware],
        auth=SecureDBBearerAuthProvider(),
        debug=debug,
    )

    # -------------------------------------------------------------------------
    # Tools
    # -------------------------------------------------------------------------

    @server.tool(
        name="whoami",
        title="Who Am I",
        description="Inspect the caller's active authenticated identity, RBAC role, scopes, and permitted operations.",
        annotations=ToolAnnotations(
            title="Who Am I",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def whoami(ctx: Context | None = None) -> dict[str, Any]:
        principal = get_current_principal()
        await safe_ctx_log(ctx, "info", f"Resolved caller principal '{principal.subject}' (role: {principal.role.value})")

        allowed_tools = sorted(ROLE_ALLOWED_TOOLS.get(principal.role, set()))
        accessible_tables = sorted(
            ALL_KNOWN_TABLES if principal.role == Role.ADMIN else (ALL_KNOWN_TABLES - ADMIN_ONLY_TABLES)
        )
        return {
            "subject": principal.subject,
            "email": principal.email,
            "role": principal.role.value,
            "scopes": principal.scopes,
            "authenticated_via": principal.authenticated_via,
            "allowed_tools": allowed_tools,
            "accessible_tables": accessible_tables,
        }

    @server.tool(
        name="list_tables",
        title="List Accessible Tables",
        description="List all analytical database tables accessible to the caller's RBAC role with schema metadata.",
        annotations=ToolAnnotations(
            title="List Accessible Tables",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def list_tables(ctx: Context | None = None) -> list[dict[str, Any]]:
        principal = get_current_principal()
        await safe_ctx_log(ctx, "info", f"Listing accessible tables for role '{principal.role.value}'")
        return engine.list_accessible_tables(role=principal.role)

    @server.tool(
        name="describe_table",
        title="Describe Table Schema",
        description="Retrieve column definitions, data types, nullability, and RBAC column access policies for a table.",
        annotations=ToolAnnotations(
            title="Describe Table Schema",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def describe_table(table_name: TableNameType, ctx: Context | None = None) -> dict[str, Any]:
        principal = get_current_principal()
        await safe_ctx_log(ctx, "info", f"Describing table '{table_name}' for role '{principal.role.value}'")
        return engine.describe_table_schema(table_name=table_name, role=principal.role)

    @server.tool(
        name="verify_query_safety",
        title="Verify SQL Safety",
        description=(
            "Dry-run AST inspection of a SQL query without executing it. Returns whether the query passes "
            "Layer 2 AST security policies, tables/columns accessed, and violation diagnostics if blocked."
        ),
        annotations=ToolAnnotations(
            title="Verify SQL Safety",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def verify_query_safety(
        sql: str,
        requested_limit: int = 100,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        principal = get_current_principal()
        await safe_ctx_log(ctx, "info", f"Validating SQL AST for role '{principal.role.value}'")
        result = engine.validator.inspect_query(
            sql=sql,
            role=principal.role,
            requested_limit=requested_limit,
        )
        return result.model_dump()

    @server.tool(
        name="execute_analytical_sql",
        title="Execute Analytical SQL",
        description=(
            "Execute a read-only analytical SQL query inside an interruptible DuckDB sandbox with AST pre-validation, "
            "row limit clamping, and column-level PII protection. Requires 'analyst' or 'admin' role."
        ),
        annotations=ToolAnnotations(
            title="Execute Analytical SQL",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        ),
    )
    async def execute_analytical_sql(
        sql: str,
        limit: int = 100,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        principal = get_current_principal()
        await safe_ctx_log(ctx, "info", f"Initiating execution for role '{principal.role.value}'...")
        await safe_ctx_progress(ctx, 0.2, 1.0)

        result = engine.execute_query(
            sql=sql,
            role=principal.role,
            requested_limit=limit,
        )

        await safe_ctx_progress(ctx, 1.0, 1.0)
        await safe_ctx_log(
            ctx,
            "info",
            f"Query executed successfully in {result.execution_time_ms:.2f}ms ({result.row_count} rows returned).",
        )
        return result.model_dump()

    @server.tool(
        name="get_security_audit_log",
        title="Get Security Audit Log",
        description=(
            "Inspect recent security audit events and execution telemetry from the in-memory ring buffer. "
            "Restricted strictly to 'admin' role."
        ),
        annotations=ToolAnnotations(
            title="Get Security Audit Log",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        ),
    )
    async def get_security_audit_log(
        limit: int = 50,
        status_filter: AuditStatusFilter = "ALL",
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        principal = get_current_principal()
        if principal.role != Role.ADMIN:
            reason = f"Access denied: role '{principal.role.value}' is not authorized to inspect security audit logs."
            engine.audit_logger.record(
                role=principal.role,
                action="get_security_audit_log",
                status="BLOCKED_RBAC",
                violation_category="RBAC_UNAUTHORIZED",
                reason=reason,
            )
            raise PermissionError(reason)

        await safe_ctx_log(ctx, "info", f"Retrieving audit events (filter: {status_filter}, limit: {limit})")
        events = engine.audit_logger.get_recent(limit=limit, status_filter=status_filter)
        stats = engine.audit_logger.summary_stats()
        return {
            "caller_role": principal.role.value,
            "filter_applied": status_filter,
            "events_returned": len(events),
            "summary_stats": stats,
            "recent_events": events,
        }

    # -------------------------------------------------------------------------
    # Resources
    # -------------------------------------------------------------------------

    @server.resource(
        "schema://catalog",
        name="Analytical Database Catalog",
        title="Catalog of Tables",
        description="JSON catalog of analytical tables, row counts, access tiers, and column classifications.",
        mime_type="application/json",
    )
    def resource_catalog() -> str:
        principal = get_current_principal()
        tables = engine.list_accessible_tables(role=principal.role)
        return json.dumps(
            {
                "catalog_name": "manufact_cloud_telemetry",
                "viewer_role": principal.role.value,
                "tables_count": len(tables),
                "tables": tables,
            },
            indent=2,
        )

    @server.resource(
        "schema://tables/{table_name}",
        name="Table Schema Specification",
        title="Per-Table Schema Details",
        description="Detailed column schema, data types, and access policy for a specific table.",
        mime_type="application/json",
    )
    def resource_table_schema(table_name: str) -> str:
        principal = get_current_principal()
        schema_data = engine.describe_table_schema(table_name=table_name, role=principal.role)
        return json.dumps(schema_data, indent=2)

    @server.resource(
        "policy://security-rules",
        name="4-Layer Security Policy",
        title="Defense-in-Depth Architecture Policy",
        description="Complete security specification explaining the 4-layer sandbox and RBAC governance.",
        mime_type="text/markdown",
    )
    def resource_security_rules() -> str:
        return (
            "# MCP Secure DB Defense-in-Depth Policy\n\n"
            "## Layer 1: RBAC Middleware & Token Resolution\n"
            "- Roles: `public_viewer`, `analyst`, `admin`\n"
            "- Demo tokens: `token-viewer-demo`, `token-analyst-demo`, `token-admin-demo` (demo only, override via env vars).\n"
            "- Unauthorized tools are dynamically hidden in `tools/list` and hard-blocked in `tools/call`.\n\n"
            "## Layer 2: Deterministic AST Validator (sqlglot)\n"
            "- Defense-in-depth static firewall (early rejection, RBAC & PII enforcement; does not replace engine sandbox).\n"
            "- Mutating operations blocked: DROP, DELETE, UPDATE, INSERT, CREATE, ALTER, PRAGMA, COPY, ATTACH.\n"
            "- Comment smuggling blocked: `--` and `/* */` patterns rejected.\n"
            "- Multi-statement smuggling blocked: Internal semicolons rejected.\n"
            "- SSRF & file functions blocked: `read_csv`, `read_parquet`, `parquet_scan`, `glob`, `st_read`, etc.\n"
            "- DoS mitigation: Mitigates unbounded-join DoS via static checks, enforced by memory, thread, and timeout limits.\n"
            "- Governance: Blocks admin-only tables & PII columns; clamps LIMIT to 1000 max.\n\n"
            "## Layer 3: Sandboxed DuckDB Engine (Primary Defense Wall)\n"
            "- Engine limits: `memory_limit = 512MB`, `threads = 2`, `enable_external_access = false`.\n"
            "- Kernel configuration locked: `SET lock_configuration = true`.\n"
            "- Query timeout via `conn.interrupt()` watchdog at 10-second deadline.\n\n"
            "## Layer 4: Structured Output Telemetry & Audit Ring Buffer\n"
            "- In-memory audit log (lost on restart; production use needs persistent, append-only storage).\n"
            "- Full execution provenance returned in every JSON payload.\n"
        )

    # -------------------------------------------------------------------------
    # Prompts
    # -------------------------------------------------------------------------

    @server.prompt(
        name="executive_analytics",
        title="Executive Analytics Briefing",
        description="Prompt template instructing an LLM agent to analyze telemetry data and formulate executive insights.",
    )
    def prompt_executive_analytics(focus_area: AnalyticsFocusArea = "mrr_growth") -> str:
        return (
            f"You are the Chief AI Systems Analyst at Manufact Cloud evaluating telemetry metrics.\n"
            f"Your current focus area is: '{focus_area}'.\n\n"
            "Instructions:\n"
            "1. First call `whoami` to verify your RBAC permissions and permitted tools.\n"
            "2. Call `list_tables` to identify available telemetry datasets.\n"
            "3. Formulate safe, aggregate SQL queries using `execute_analytical_sql`.\n"
            "   - When querying organizations or servers, do not select PII columns (billing_email, webhook_secret).\n"
            "   - Use explicit column names instead of SELECT *.\n"
            "   - Aggregate metrics such as SUM(mrr_usd), AVG(latency_ms), or COUNT(server_id).\n"
            "4. Provide a clear executive summary with key trends, risks, and operational recommendations for Pietro and Luigi."
        )

    @server.prompt(
        name="red_team_security_audit",
        title="Red Team Security Audit Challenge",
        description="Adversarial red-team test harness prompt with concrete attack vectors to test sandbox defenses.",
    )
    def prompt_red_team_audit(target_vector: RedTeamVector = "external_file_ssrf") -> str:
        attack_examples = {
            "comment_smuggling": "SELECT org_name FROM organizations -- smuggled comment\nWHERE 1=1;",
            "external_file_ssrf": "SELECT * FROM read_csv_auto('/etc/passwd');",
            "pii_exfiltration": "SELECT org_name, billing_email, stripe_customer_id FROM organizations;",
            "cartesian_dos": "SELECT a.org_name, b.tool_name FROM organizations a, tool_invocations b;",
            "ddl_mutation": "DROP TABLE organizations;",
        }
        test_query = attack_examples.get(target_vector, "SELECT 1;")
        return (
            f"You are an Adversarial Security Red-Team Engineer testing the mcp-secure-db sandbox.\n"
            f"Target attack vector under evaluation: '{target_vector}'.\n\n"
            f"Sample test payload:\n```sql\n{test_query}\n```\n\n"
            "Execution Plan:\n"
            "1. First execute `verify_query_safety` with the payload to inspect the Layer 2 AST validator diagnostics.\n"
            "2. If you are an analyst or admin, attempt to run the payload through `execute_analytical_sql`.\n"
            "3. Verify that the query is rejected deterministically with zero token leakage.\n"
            "4. As an admin, invoke `get_security_audit_log` to confirm that the violation was recorded in the audit log."
        )

    # Wrap handlers so middleware processing is active for direct requests and server runners
    server._wrap_handlers_with_middleware()

    return server


# Default exported server instance for Dockpack / ASGI runners
server: MCPServer = create_server(debug=True)
