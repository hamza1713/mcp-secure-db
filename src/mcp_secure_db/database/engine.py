"""Layer 3 & 4: Interruptible Sandboxed DuckDB Engine & Structured Telemetry."""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from datetime import UTC, datetime
from typing import Any

import duckdb
from pydantic import BaseModel, Field

from mcp_secure_db.security.rbac import (
    ADMIN_ONLY_TABLES,
    ALL_KNOWN_TABLES,
    PII_COLUMNS_BY_TABLE,
    SAFE_COLUMNS_BY_TABLE,
    Role,
)
from mcp_secure_db.security.validator import SQLSecurityError, SQLValidator


class QueryTimeoutError(TimeoutError):
    """Raised when a query exceeds the hard execution deadline and is aborted via conn.interrupt()."""


class AuditEntry(BaseModel):
    """Immutable security & telemetry record for every tool or SQL invocation."""

    event_id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex[:10]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    role: Role = Field(description="Caller RBAC role")
    action: str = Field(description="Tool name or SQL action")
    status: str = Field(description="ALLOWED, BLOCKED_AST, BLOCKED_RBAC, TIMEOUT, or ERROR")
    violation_category: str | None = Field(default=None)
    reason: str | None = Field(default=None)
    raw_sql: str | None = Field(default=None)
    sanitized_sql: str | None = Field(default=None)
    execution_time_ms: float = Field(default=0.0)
    row_count: int = Field(default=0)


class AuditLogger:
    """Thread-safe bounded ring buffer storing security audit and query telemetry events."""

    def __init__(self, max_entries: int = 500) -> None:
        self._entries: deque[AuditEntry] = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    def record(
        self,
        role: Role,
        action: str,
        status: str,
        violation_category: str | None = None,
        reason: str | None = None,
        raw_sql: str | None = None,
        sanitized_sql: str | None = None,
        execution_time_ms: float = 0.0,
        row_count: int = 0,
    ) -> AuditEntry:
        entry = AuditEntry(
            role=role,
            action=action,
            status=status,
            violation_category=violation_category,
            reason=reason,
            raw_sql=raw_sql,
            sanitized_sql=sanitized_sql,
            execution_time_ms=round(execution_time_ms, 3),
            row_count=row_count,
        )
        with self._lock:
            self._entries.appendleft(entry)
        return entry

    def record_rbac_event(self, action: str, role: Role, status: str, reason: str) -> None:
        self.record(
            role=role,
            action=action,
            status=status,
            violation_category="RBAC_UNAUTHORIZED",
            reason=reason,
        )

    def get_recent(self, limit: int = 50, status_filter: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._entries)
        if status_filter and status_filter.upper() != "ALL":
            items = [e for e in items if e.status.upper() == status_filter.upper()]
        return [e.model_dump() for e in items[: max(1, min(limit, 200))]]

    def summary_stats(self) -> dict[str, Any]:
        with self._lock:
            items = list(self._entries)
        total = len(items)
        by_status: dict[str, int] = {}
        by_category: dict[str, int] = {}
        allowed_latencies: list[float] = []

        for item in items:
            by_status[item.status] = by_status.get(item.status, 0) + 1
            if item.violation_category:
                by_category[item.violation_category] = by_category.get(item.violation_category, 0) + 1
            if item.status == "ALLOWED":
                allowed_latencies.append(item.execution_time_ms)

        avg_ms = round(sum(allowed_latencies) / len(allowed_latencies), 3) if allowed_latencies else 0.0
        return {
            "total_events_logged": total,
            "events_by_status": by_status,
            "blocked_by_category": by_category,
            "avg_allowed_execution_ms": avg_ms,
        }


class QueryExecutionResult(BaseModel):
    """Standardized Layer 4 structured output with full provenance and telemetry."""

    status: str = "success"
    role: Role
    original_sql: str
    sanitized_sql: str
    tables_accessed: list[str]
    row_count: int
    limit_enforced: int
    execution_time_ms: float
    columns: list[str]
    rows: list[dict[str, Any]]
    sandbox_config: dict[str, Any] = Field(
        default_factory=lambda: {
            "engine": "DuckDB In-Memory Columnar Sandbox",
            "external_access": False,
            "config_locked": True,
            "memory_limit": "512MB",
        }
    )


class SecureDuckDBEngine:
    """Thread-safe, interruptible in-memory DuckDB analytical engine with 4-layer protection."""

    def __init__(
        self,
        timeout_seconds: float = 10.0,
        max_rows: int = 1000,
        default_limit: int = 100,
        audit_logger: AuditLogger | None = None,
        lock_kernel_config: bool = True,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.validator = SQLValidator(max_rows=max_rows, default_limit=default_limit)
        self.audit_logger = audit_logger or AuditLogger()
        self._conn = duckdb.connect(database=":memory:")
        self._exec_lock = threading.Lock()

        self._seed_manufact_telemetry_dataset()
        self._harden_duckdb_kernel(lock_config=lock_kernel_config)

    def _seed_manufact_telemetry_dataset(self) -> None:
        """Seed realistic Manufact Cloud / MCP Server Telemetry dataset into in-memory DuckDB."""
        self._conn.execute(
            """
            CREATE TABLE organizations (
                org_id VARCHAR PRIMARY KEY,
                org_name VARCHAR NOT NULL,
                plan_tier VARCHAR NOT NULL,
                mrr_usd DOUBLE NOT NULL,
                region VARCHAR NOT NULL,
                created_at TIMESTAMP NOT NULL,
                billing_email VARCHAR NOT NULL,
                stripe_customer_id VARCHAR NOT NULL
            );

            INSERT INTO organizations VALUES
                ('org_01', 'Acme Robotics AI', 'enterprise', 4800.00, 'eu-central-1', '2026-01-15 09:00:00', 'finance@acmerobotics.ai', 'cus_Pq91Lm82Kx01'),
                ('org_02', 'Vanguard Quant Labs', 'enterprise', 6200.00, 'us-east-1', '2026-02-02 14:30:00', 'ap-billing@vanguardquant.io', 'cus_Pq92Lm82Kx02'),
                ('org_03', 'Helios Biotech', 'enterprise', 3500.00, 'eu-west-1', '2026-02-19 11:15:00', 'treasury@heliosbio.ch', 'cus_Pq93Lm82Kx03'),
                ('org_04', 'NovaPay FinTech', 'scale', 1490.00, 'us-west-2', '2026-03-10 16:45:00', 'billing@novapay.dev', 'cus_Pq94Lm82Kx04'),
                ('org_05', 'Cortex Legal Agents', 'scale', 1290.00, 'us-east-1', '2026-04-05 08:20:00', 'ops@cortexlegal.ai', 'cus_Pq95Lm82Kx05'),
                ('org_06', 'Zurich Autonomous Systems', 'enterprise', 5400.00, 'eu-central-1', '2026-04-22 10:00:00', 'cfo@zurich-auto.ch', 'cus_Pq96Lm82Kx06'),
                ('org_07', 'PulseHealth Diagnostics', 'scale', 990.00, 'us-east-1', '2026-05-18 13:10:00', 'accounts@pulsehealth.med', 'cus_Pq97Lm82Kx07'),
                ('org_08', 'Hyperion DevTools', 'pro', 299.00, 'ap-southeast-1', '2026-06-11 07:30:00', 'founders@hyperion.sh', 'cus_Pq98Lm82Kx08'),
                ('org_09', 'Stratos Logistics AI', 'scale', 1850.00, 'eu-central-1', '2026-07-01 15:00:00', 'billing@stratos-ai.de', 'cus_Pq99Lm82Kx09'),
                ('org_10', 'PixelForge Studio', 'pro', 199.00, 'us-west-2', '2026-08-14 19:25:00', 'admin@pixelforge.design', 'cus_Pq00Lm82Kx10');

            CREATE TABLE mcp_servers (
                server_id VARCHAR PRIMARY KEY,
                org_id VARCHAR NOT NULL,
                server_name VARCHAR NOT NULL,
                runtime VARCHAR NOT NULL,
                transport VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                memory_mb INTEGER NOT NULL,
                avg_cold_start_ms DOUBLE NOT NULL,
                deployed_at TIMESTAMP NOT NULL,
                webhook_secret VARCHAR NOT NULL
            );

            INSERT INTO mcp_servers VALUES
                ('srv_101', 'org_01', 'ros2-telemetry-mcp', 'python-uv', 'streamable-http', 'healthy', 1024, 310.5, '2026-09-01 10:00:00', 'whsec_99a8b7c6d5e4f3a2'),
                ('srv_102', 'org_01', 'warehouse-erp-bridge', 'python-uv', 'streamable-http', 'healthy', 512, 245.0, '2026-09-12 11:30:00', 'whsec_88b7c6d5e4f3a2b1'),
                ('srv_103', 'org_02', 'market-tick-analytics', 'python-uv', 'streamable-http', 'healthy', 2048, 190.2, '2026-09-15 09:45:00', 'whsec_77c6d5e4f3a2b1c0'),
                ('srv_104', 'org_02', 'risk-compliance-guard', 'node-pnpm', 'streamable-http', 'healthy', 512, 165.8, '2026-09-20 14:15:00', 'whsec_66d5e4f3a2b1c0d9'),
                ('srv_105', 'org_03', 'alphafold-structure-mcp', 'dockerfile', 'streamable-http', 'healthy', 4096, 620.4, '2026-09-25 08:00:00', 'whsec_55e4f3a2b1c0d9e8'),
                ('srv_106', 'org_04', 'ledger-reconciler-mcp', 'python-uv', 'streamable-http', 'healthy', 1024, 275.3, '2026-10-01 12:00:00', 'whsec_44f3a2b1c0d9e8f7'),
                ('srv_107', 'org_05', 'ediscovery-clauses-mcp', 'python-uv', 'streamable-http', 'degraded', 1024, 480.9, '2026-10-04 16:20:00', 'whsec_33a2b1c0d9e8f7a6'),
                ('srv_108', 'org_06', 'drone-fleet-planner', 'node-npm', 'streamable-http', 'healthy', 1024, 210.0, '2026-10-08 09:10:00', 'whsec_22b1c0d9e8f7a6b5'),
                ('srv_109', 'org_07', 'dicom-metadata-reader', 'python-uv', 'streamable-http', 'healthy', 2048, 340.1, '2026-10-12 13:40:00', 'whsec_11c0d9e8f7a6b5c4'),
                ('srv_110', 'org_08', 'github-pr-triage-app', 'node-npm', 'streamable-http', 'healthy', 512, 155.0, '2026-10-15 17:05:00', 'whsec_00d9e8f7a6b5c4d3'),
                ('srv_111', 'org_09', 'customs-tariff-lookup', 'python-uv', 'streamable-http', 'healthy', 512, 230.7, '2026-10-18 10:50:00', 'whsec_99e8f7a6b5c4d3e2'),
                ('srv_112', 'org_10', 'remotion-video-mcp', 'node-pnpm', 'streamable-http', 'healthy', 2048, 395.6, '2026-10-21 15:30:00', 'whsec_88f7a6b5c4d3e2f1');

            CREATE TABLE tool_invocations (
                invocation_id VARCHAR PRIMARY KEY,
                server_id VARCHAR NOT NULL,
                org_id VARCHAR NOT NULL,
                tool_name VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                latency_ms DOUBLE NOT NULL,
                tokens_saved INTEGER NOT NULL,
                invoked_at TIMESTAMP NOT NULL,
                client_ip VARCHAR NOT NULL
            );

            INSERT INTO tool_invocations VALUES
                ('inv_001', 'srv_101', 'org_01', 'query_joint_states', 'success', 42.5, 1850, '2026-10-25 10:01:00', '185.199.108.15'),
                ('inv_002', 'srv_101', 'org_01', 'compute_kinematics', 'success', 118.2, 3200, '2026-10-25 10:02:15', '185.199.108.15'),
                ('inv_003', 'srv_102', 'org_01', 'fetch_inventory_levels', 'success', 28.4, 940, '2026-10-25 10:05:00', '185.199.108.19'),
                ('inv_004', 'srv_103', 'org_02', 'execute_analytical_sql', 'success', 19.8, 4500, '2026-10-25 11:10:00', '54.236.112.90'),
                ('inv_005', 'srv_103', 'org_02', 'execute_analytical_sql', 'success', 31.1, 5120, '2026-10-25 11:12:30', '54.236.112.90'),
                ('inv_006', 'srv_103', 'org_02', 'compute_var_surface', 'success', 84.6, 6200, '2026-10-25 11:15:45', '54.236.112.91'),
                ('inv_007', 'srv_104', 'org_02', 'verify_trade_limits', 'success', 14.2, 820, '2026-10-25 11:20:00', '54.236.112.91'),
                ('inv_008', 'srv_105', 'org_03', 'align_binding_pocket', 'success', 412.0, 8900, '2026-10-25 12:00:00', '195.176.2.110'),
                ('inv_009', 'srv_105', 'org_03', 'score_ligand_affinity', 'success', 289.5, 7400, '2026-10-25 12:04:10', '195.176.2.110'),
                ('inv_010', 'srv_106', 'org_04', 'reconcile_settlement_batch', 'success', 63.7, 3100, '2026-10-25 13:30:00', '34.210.55.18'),
                ('inv_011', 'srv_106', 'org_04', 'execute_analytical_sql', 'blocked_policy', 1.2, 0, '2026-10-25 13:31:00', '34.210.55.18'),
                ('inv_012', 'srv_107', 'org_05', 'search_case_precedents', 'error', 1420.5, 0, '2026-10-25 14:10:00', '44.192.80.12'),
                ('inv_013', 'srv_107', 'org_05', 'extract_indemnity_clauses', 'success', 540.3, 4100, '2026-10-25 14:15:00', '44.192.80.12'),
                ('inv_014', 'srv_108', 'org_06', 'optimize_flight_corridor', 'success', 52.9, 2750, '2026-10-25 15:00:00', '82.130.102.45'),
                ('inv_015', 'srv_108', 'org_06', 'check_airspace_notams', 'success', 37.0, 1900, '2026-10-25 15:05:00', '82.130.102.45'),
                ('inv_016', 'srv_109', 'org_07', 'inspect_series_headers', 'success', 76.4, 3300, '2026-10-25 16:20:00', '52.45.19.201'),
                ('inv_017', 'srv_110', 'org_08', 'review_pull_request_diff', 'success', 95.1, 5600, '2026-10-25 17:00:00', '13.250.99.40'),
                ('inv_018', 'srv_111', 'org_09', 'classify_hs_code', 'success', 48.3, 2100, '2026-10-25 18:10:00', '3.120.44.88'),
                ('inv_019', 'srv_112', 'org_10', 'render_composition_preview', 'success', 310.8, 1500, '2026-10-25 19:00:00', '54.186.22.71'),
                ('inv_020', 'srv_103', 'org_02', 'execute_analytical_sql', 'success', 22.4, 4890, '2026-10-26 09:00:00', '54.236.112.90');

            CREATE TABLE subscriptions (
                subscription_id VARCHAR PRIMARY KEY,
                org_id VARCHAR NOT NULL,
                plan_tier VARCHAR NOT NULL,
                monthly_quota_calls INTEGER NOT NULL,
                used_calls INTEGER NOT NULL,
                status VARCHAR NOT NULL,
                renews_at TIMESTAMP NOT NULL,
                stripe_customer_id VARCHAR NOT NULL
            );

            INSERT INTO subscriptions VALUES
                ('sub_01', 'org_01', 'enterprise', 5000000, 3420100, 'active', '2026-11-15 00:00:00', 'cus_Pq91Lm82Kx01'),
                ('sub_02', 'org_02', 'enterprise', 10000000, 8910450, 'active', '2026-11-02 00:00:00', 'cus_Pq92Lm82Kx02'),
                ('sub_03', 'org_03', 'enterprise', 3000000, 1890200, 'active', '2026-11-19 00:00:00', 'cus_Pq93Lm82Kx03'),
                ('sub_04', 'org_04', 'scale', 1000000, 745000, 'active', '2026-11-10 00:00:00', 'cus_Pq94Lm82Kx04'),
                ('sub_05', 'org_05', 'scale', 1000000, 962000, 'past_due', '2026-11-05 00:00:00', 'cus_Pq95Lm82Kx05'),
                ('sub_06', 'org_06', 'enterprise', 5000000, 4120000, 'active', '2026-11-22 00:00:00', 'cus_Pq96Lm82Kx06'),
                ('sub_07', 'org_07', 'scale', 500000, 310400, 'active', '2026-11-18 00:00:00', 'cus_Pq97Lm82Kx07'),
                ('sub_08', 'org_08', 'pro', 100000, 88900, 'active', '2026-11-11 00:00:00', 'cus_Pq98Lm82Kx08'),
                ('sub_09', 'org_09', 'scale', 1500000, 1120000, 'active', '2026-11-01 00:00:00', 'cus_Pq99Lm82Kx09'),
                ('sub_10', 'org_10', 'pro', 100000, 42300, 'active', '2026-11-14 00:00:00', 'cus_Pq00Lm82Kx10');

            CREATE TABLE api_keys (
                key_id VARCHAR PRIMARY KEY,
                org_id VARCHAR NOT NULL,
                scope_role VARCHAR NOT NULL,
                key_hash VARCHAR NOT NULL,
                raw_token_prefix VARCHAR NOT NULL,
                created_at TIMESTAMP NOT NULL,
                last_used_at TIMESTAMP NOT NULL
            );

            INSERT INTO api_keys VALUES
                ('key_901', 'org_01', 'admin', 'sha256:9f86d081884c7d659a2feaa0c55ad015', 'mnf_live_9f86...', '2026-01-16 10:00:00', '2026-10-26 08:30:00'),
                ('key_902', 'org_02', 'admin', 'sha256:4b227777d4dd1fc61c6f884f48641d02', 'mnf_live_4b22...', '2026-02-03 11:00:00', '2026-10-26 09:00:00'),
                ('key_903', 'org_04', 'analyst', 'sha256:ef2d127de37b942baad06145e54b0c61', 'mnf_live_ef2d...', '2026-03-12 15:00:00', '2026-10-25 13:31:00'),
                ('key_904', 'org_06', 'admin', 'sha256:e7f6c011776e8db7cd330b54174fd76f', 'mnf_live_e7f6...', '2026-04-23 09:00:00', '2026-10-25 15:05:00');

            CREATE TABLE security_incidents (
                incident_id VARCHAR PRIMARY KEY,
                org_id VARCHAR NOT NULL,
                role VARCHAR NOT NULL,
                attack_vector VARCHAR NOT NULL,
                blocked_sql VARCHAR NOT NULL,
                detected_at TIMESTAMP NOT NULL
            );

            INSERT INTO security_incidents VALUES
                ('inc_501', 'org_04', 'analyst', 'MULTI_STATEMENT_SMUGGLING', 'SELECT org_name FROM organizations; DROP TABLE organizations;', '2026-10-24 14:22:10'),
                ('inc_502', 'org_05', 'analyst', 'EXTERNAL_ACCESS_OR_DOS_FUNCTION', 'SELECT * FROM read_csv_auto(''/etc/passwd'')', '2026-10-25 09:11:04'),
                ('inc_503', 'org_04', 'analyst', 'RBAC_PII_COLUMN_RESTRICTED', 'SELECT org_name, billing_email, stripe_customer_id FROM organizations', '2026-10-25 13:31:00'),
                ('inc_504', 'org_08', 'public_viewer', 'RBAC_UNAUTHORIZED', 'Attempted execute_analytical_sql with public_viewer role', '2026-10-26 07:45:19');
            """
        )

    def _harden_duckdb_kernel(self, lock_config: bool = True) -> None:
        """Apply C++-level DuckDB resource limits and disable external filesystem/network access."""
        self._conn.execute("SET memory_limit = '512MB';")
        self._conn.execute("SET threads = 2;")
        self._conn.execute("SET enable_external_access = false;")
        if lock_config:
            self._conn.execute("SET lock_configuration = true;")

    def list_accessible_tables(self, role: Role) -> list[dict[str, Any]]:
        """Return metadata for tables visible to the caller's role."""
        tables_to_show = sorted(
            ALL_KNOWN_TABLES if role == Role.ADMIN else (ALL_KNOWN_TABLES - ADMIN_ONLY_TABLES)
        )
        catalog: list[dict[str, Any]] = []
        with self._exec_lock:
            for table_name in tables_to_show:
                row_count_row = self._conn.execute(f"SELECT COUNT(*) FROM {table_name}").fetchone()
                row_count = int(row_count_row[0]) if row_count_row else 0
                pii_cols = sorted(PII_COLUMNS_BY_TABLE.get(table_name, frozenset()))
                catalog.append(
                    {
                        "table_name": table_name,
                        "row_count": row_count,
                        "access_tier": "admin_only" if table_name in ADMIN_ONLY_TABLES else "analyst_and_admin",
                        "safe_columns": list(SAFE_COLUMNS_BY_TABLE[table_name]),
                        "restricted_pii_columns": pii_cols if role == Role.ADMIN else f"{len(pii_cols)} restricted column(s) (requires admin)",
                    }
                )
        return catalog

    def describe_table_schema(self, table_name: str, role: Role) -> dict[str, Any]:
        """Return detailed column schema and RBAC visibility annotations for a table."""
        clean_name = table_name.strip().lower()
        if clean_name not in ALL_KNOWN_TABLES:
            raise ValueError(
                f"Unknown table '{table_name}'. Available tables: "
                f"{sorted(ALL_KNOWN_TABLES if role == Role.ADMIN else (ALL_KNOWN_TABLES - ADMIN_ONLY_TABLES))}."
            )
        if role != Role.ADMIN and clean_name in ADMIN_ONLY_TABLES:
            self.audit_logger.record(
                role=role,
                action="describe_table",
                status="BLOCKED_RBAC",
                violation_category="RBAC_TABLE_RESTRICTED",
                reason=f"Role '{role.value}' attempted to inspect admin-only table '{clean_name}'.",
            )
            raise PermissionError(
                f"Access denied: table '{clean_name}' is restricted to 'admin' role."
            )

        with self._exec_lock:
            pragma_rows = self._conn.execute(f"PRAGMA table_info('{clean_name}')").fetchall()

        pii_set = PII_COLUMNS_BY_TABLE.get(clean_name, frozenset())
        columns_info: list[dict[str, Any]] = []
        for cid, col_name, col_type, notnull, dflt_value, pk in pragma_rows:
            is_restricted = col_name.lower() in pii_set
            columns_info.append(
                {
                    "column_name": col_name,
                    "data_type": col_type,
                    "primary_key": bool(pk),
                    "nullable": not bool(notnull),
                    "access_policy": "ADMIN_ONLY_PII" if is_restricted else "ANALYST_SAFE",
                    "queryable_by_current_role": True if (role == Role.ADMIN or not is_restricted) else False,
                }
            )

        return {
            "table_name": clean_name,
            "caller_role": role.value,
            "select_star_allowed_for_caller": True if (role == Role.ADMIN or not pii_set) else False,
            "recommended_select_columns": list(SAFE_COLUMNS_BY_TABLE[clean_name]),
            "columns": columns_info,
        }

    def execute_query(
        self,
        sql: str,
        role: Role = Role.ANALYST,
        requested_limit: int | None = None,
        timeout_override: float | None = None,
    ) -> QueryExecutionResult:
        """Validate SQL via AST policy engine and execute inside interruptible DuckDB sandbox."""
        if role == Role.PUBLIC_VIEWER:
            reason = "Role 'public_viewer' is restricted to metadata inspection and cannot execute SQL queries."
            self.audit_logger.record(
                role=role,
                action="execute_analytical_sql",
                status="BLOCKED_RBAC",
                violation_category="RBAC_UNAUTHORIZED",
                reason=reason,
                raw_sql=sql,
            )
            raise PermissionError(reason)

        # Layer 2: Deterministic AST Validation & Sanitization
        try:
            validation = self.validator.validate_and_sanitize(
                sql=sql,
                role=role,
                requested_limit=requested_limit,
            )
        except SQLSecurityError as exc:
            self.audit_logger.record(
                role=role,
                action="execute_analytical_sql",
                status="BLOCKED_AST",
                violation_category=exc.violation_category,
                reason=str(exc),
                raw_sql=sql,
            )
            raise

        sanitized_sql = validation.sanitized_sql or sql
        effective_timeout = timeout_override if timeout_override is not None else self.timeout_seconds

        # Layer 3: Interruptible DuckDB Execution with C++ conn.interrupt() Watchdog
        return self._execute_sanitized_with_watchdog(
            original_sql=sql,
            sanitized_sql=sanitized_sql,
            role=role,
            tables_accessed=validation.tables_accessed,
            limit_enforced=validation.limit_applied or 100,
            timeout_seconds=effective_timeout,
        )

    def _execute_sanitized_with_watchdog(
        self,
        original_sql: str,
        sanitized_sql: str,
        role: Role,
        tables_accessed: list[str],
        limit_enforced: int,
        timeout_seconds: float,
    ) -> QueryExecutionResult:
        """Execute a validated SQL query with a hardware-level DuckDB interrupt timer."""
        timed_out = threading.Event()

        def _trigger_interrupt() -> None:
            timed_out.set()
            try:
                self._conn.interrupt()
            except Exception:
                pass

        timer = threading.Timer(timeout_seconds, _trigger_interrupt)
        timer.daemon = True

        start_perf = time.perf_counter()
        with self._exec_lock:
            timer.start()
            try:
                rel = self._conn.execute(sanitized_sql)
                col_names = [desc[0] for desc in (rel.description or [])]
                raw_rows = rel.fetchall()
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
                if timed_out.is_set() or "interrupt" in str(exc).lower():
                    msg = f"Query aborted by sandbox watchdog after exceeding {timeout_seconds:.2f}s deadline."
                    self.audit_logger.record(
                        role=role,
                        action="execute_analytical_sql",
                        status="TIMEOUT",
                        violation_category="EXECUTION_TIMEOUT",
                        reason=msg,
                        raw_sql=original_sql,
                        sanitized_sql=sanitized_sql,
                        execution_time_ms=elapsed_ms,
                    )
                    raise QueryTimeoutError(msg) from exc

                self.audit_logger.record(
                    role=role,
                    action="execute_analytical_sql",
                    status="ERROR",
                    violation_category="RUNTIME_SQL_ERROR",
                    reason=str(exc),
                    raw_sql=original_sql,
                    sanitized_sql=sanitized_sql,
                    execution_time_ms=elapsed_ms,
                )
                raise
            finally:
                timer.cancel()

        elapsed_ms = (time.perf_counter() - start_perf) * 1000.0
        if timed_out.is_set():
            msg = f"Query aborted by sandbox watchdog after exceeding {timeout_seconds:.2f}s deadline."
            self.audit_logger.record(
                role=role,
                action="execute_analytical_sql",
                status="TIMEOUT",
                violation_category="EXECUTION_TIMEOUT",
                reason=msg,
                raw_sql=original_sql,
                sanitized_sql=sanitized_sql,
                execution_time_ms=elapsed_ms,
            )
            raise QueryTimeoutError(msg)

        # Layer 4: Serialize rows safely (handling timestamps/dates) and record telemetry
        serialized_rows: list[dict[str, Any]] = []
        for row in raw_rows:
            row_dict: dict[str, Any] = {}
            for col, val in zip(col_names, row, strict=False):
                if isinstance(val, datetime):
                    row_dict[col] = val.isoformat()
                else:
                    row_dict[col] = val
            serialized_rows.append(row_dict)

        self.audit_logger.record(
            role=role,
            action="execute_analytical_sql",
            status="ALLOWED",
            raw_sql=original_sql,
            sanitized_sql=sanitized_sql,
            execution_time_ms=elapsed_ms,
            row_count=len(serialized_rows),
        )

        return QueryExecutionResult(
            role=role,
            original_sql=original_sql,
            sanitized_sql=sanitized_sql,
            tables_accessed=tables_accessed,
            row_count=len(serialized_rows),
            limit_enforced=limit_enforced,
            execution_time_ms=round(elapsed_ms, 3),
            columns=col_names,
            rows=serialized_rows,
        )
