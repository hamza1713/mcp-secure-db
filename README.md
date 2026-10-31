# mcp-secure-db

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![mcp-use 1.7+](https://img.shields.io/badge/mcp--use-1.7.1-orange.svg)](https://github.com/mcp-use/mcp-use)
[![DuckDB](https://img.shields.io/badge/DuckDB-In--Memory%20Columnar-yellow.svg)](https://duckdb.org/)
[![Security Test Coverage](https://img.shields.io/badge/Security%20Coverage-32%20adversarial%20cases-brightgreen.svg)](tests/test_adversarial.py)
[![Dockpack](https://img.shields.io/badge/Dockpack-Ready-success.svg)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**Reference implementation of a 4-layer sandboxed analytical database MCP server built on `mcp-use` for Manufact Cloud.**

---

## Executive Summary

Connecting autonomous LLM agents to analytical databases introduces serious operational and security risks:
1. **Prompt Injection & Destructive Mutation**: Injected `DROP TABLE`, `TRUNCATE`, or `DELETE` statements.
2. **Server-Side Request Forgery (SSRF) & File Exfiltration**: Reading local files (`/etc/passwd`) or cloud metadata via DuckDB functions like `read_csv` or `parquet_scan`.
3. **Comment Smuggling**: Payloads hidden inside `--` line comments or `/* */` block comments.
4. **Denial of Service (DoS)**: Unconstrained Cartesian `CROSS JOIN` operations and synthetic unbounded row generators exhausting server memory.
5. **PII & Credential Leaks**: Unauthorized access to API keys, webhook secrets, billing emails, and Stripe customer IDs.

`mcp-secure-db` addresses these challenges through a **layered defense-in-depth architecture** that combines zero-token static AST validation with engine sandboxing, resource constraints, and structured telemetry.

---

## 4-Layer Defense-in-Depth Architecture

```
                                  [ MCP Client / Agent ]
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: Hybrid RBAC Middleware & Token Resolution (mcp-use Middleware)               │
│ • Bearer token authentication (configurable via MCP_VIEWER_TOKEN, etc.)               │
│ • Demo tokens provided for local testing (token-viewer-demo, token-analyst-demo, etc.) │
│ • Graceful fallback to public_viewer for zero-friction MCP Inspector debugging         │
│ • Dynamic tool masking: unpermitted tools are hidden from tools/list                   │
│ • Hard call-time rejection in on_call_tool before execution                            │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: Deterministic AST SQL Validator & Policy Engine (sqlglot DuckDB Dialect)      │
│ • Defense in depth: early static rejection; does not replace the engine sandbox        │
│ • Strict read-only: blocks DROP, DELETE, UPDATE, INSERT, ALTER, PRAGMA, COPY, ATTACH   │
│ • Anti-smuggling: strips comments (-- and /* */) and rejects multi-statements (;)      │
│ • SSRF & Exfiltration ban: blocks read_csv, read_parquet, parquet_scan, glob, st_read │
│ • DoS mitigation: mitigates unbounded joins via static checks; max 4 joins per query   │
│ • Governance: blocks admin-only tables & PII columns; bans SELECT * on PII tables      │
│ • Automatic LIMIT injection & clamping (default 100, max 1000 rows across subqueries)  │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: Sandboxed In-Memory DuckDB Engine (Primary Defense Wall)                      │
│ • Engine limits: SET enable_external_access = false; SET memory_limit = '512MB';       │
│ • Engine limits: SET threads = 2; (enforced before any user query runs)                │
│ • Kernel lock: SET lock_configuration = true; (prevents runtime configuration changes) │
│ • Watchdog timer: 10-second deadline aborts runaway queries via conn.interrupt()       │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: Structured Output Telemetry & In-Memory Audit Buffer                          │
│ • Standardized JSON response with full execution provenance, latency, and row counts   │
│ • In-memory thread-safe ring buffer recording all queries, timeouts, and blocks       │
│ • Note: In-memory only (lost on process restart; production requires persistent storage)│
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Model & Limitations

### Threat Model

* **What it protects against:**
  * Prompt-injected SQL generated by autonomous LLM agents (attempting mutations, comment smuggling, multi-statements, file reads).
  * Accidental unbounded queries (clamped limits, max 4 joins, literal tautologies).
  * Direct PII column reads or wildcard exfiltration on tables marked with PII for non-admin roles.
  * Container-level file extraction attempts via DuckDB's native file functions.
  * Runaway query loops or CPU-intensive recursive CTEs exceeding the 10-second watchdog deadline.
  * Unauthenticated access to analytical execution tools when strict auth is enabled.

* **What it does NOT protect against (Out of Scope):**
  * Compromised container host or root access to the server operating system.
  * Malicious administrators who possess legitimate `admin` tokens (admins have access to PII and audit logs by design).
  * Timing attacks or statistical side channels (e.g. inferring whether a row exists by measuring query latency).
  * Derived or semantic PII inference (e.g. if non-PII fields like `region` or `mrr_usd` correlate with specific individuals).
  * Memory exhaustion that occurs below the 512MB threshold or within the 10-second window.

### Layer Enforcement Matrix

| Layer | What It Enforces | What It Cannot Catch |
| :--- | :--- | :--- |
| **Layer 1: RBAC Middleware** | Resolves caller tokens to roles (`public_viewer`, `analyst`, `admin`), filters `tools/list`, blocks unpermitted `tools/call`. | Cannot inspect the contents of SQL queries passed to permitted tools. |
| **Layer 2: sqlglot AST Firewall** | Fast static rejection of DDL/DML, comments, multi-statements, SSRF functions, literal join tautologies, PII columns, and clamps `LIMIT <= 1000`. | Cannot statically resolve complex semantic joins; does not replace engine-level sandbox. |
| **Layer 3: DuckDB Engine Sandbox** | Engine-level `enable_external_access=false`, `lock_configuration=true`, `memory_limit='512MB'`, `threads=2`, and 10s `conn.interrupt()` watchdog. | In-memory only; does not provide persistent database security controls (e.g. Postgres RLS, network egress firewalls) for external production databases. |
| **Layer 4: Telemetry & Audit Buffer** | In-memory ring buffer capturing query text, caller role, execution latency, and violation category. | Stored in process memory and lost on container restart. Production deployments require persistent, write-once append-only storage. |

### Known Limitations

1. **Static Join Checks Are Bypassable:** Static AST analysis cannot detect all query plans that produce large cross products. Layer 2 mitigates obvious tautologies (`ON 1=1`, `ON x=x`, `CROSS JOIN`), but engine resource limits (512MB RAM, 2 threads, 10s watchdog) serve as the backstop.
2. **In-Memory Audit Log:** The audit ring buffer is maintained in volatile Python memory. Restarting or redeploying the server clears the audit history. Production use requires shipping logs to an external, append-only service.
3. **Demo Tokens:** Hardcoded tokens (`token-viewer-demo`, `token-analyst-demo`, `token-admin-demo`) are provided strictly for demonstration and testing. They can be overridden via `MCP_VIEWER_TOKEN`, `MCP_ANALYST_TOKEN`, and `MCP_ADMIN_TOKEN` and must never be exposed in production.
4. **In-Memory Demonstration Database:** The pre-seeded DuckDB database is an in-memory test fixture. Real-world enterprise deployments should front external databases (Postgres, Snowflake, BigQuery) with read-only database credentials and database-native Row-Level Security (RLS).
5. **Column-Based PII Redaction:** PII protection is based on column names. It does not perform semantic data loss prevention (DLP) or detect inferred PII from unredacted attributes.

---

## Adversarial Test Results

The table below summarizes verified test outcomes across attack vectors in [`tests/test_adversarial.py`](tests/test_adversarial.py):

| Attack Class | Tested Payload / Scenario | Result | Enforcement Layer |
| :--- | :--- | :--- | :--- |
| **Comment Smuggling** | `SELECT org_name FROM organizations -- comment` | **Blocked by AST** (`COMMENT_SMUGGLING`) | Layer 2 |
| **Block Comment Smuggling** | `SELECT * FROM (SELECT org_name FROM organizations /* comment */)` | **Blocked by AST** (`COMMENT_SMUGGLING`) | Layer 2 |
| **Multi-Statement Chaining** | `SELECT org_name FROM organizations; DROP TABLE organizations;` | **Blocked by AST** (`MULTI_STATEMENT_SMUGGLING`) | Layer 2 |
| **Mutating DDL / DML** | `DROP TABLE organizations`, `DELETE FROM organizations` | **Blocked by AST** (`FORBIDDEN_STATEMENT_TYPE`) | Layer 2 |
| **File Read SSRF (AST)** | `SELECT * FROM read_csv_auto('/etc/passwd')`, `read_parquet('...')` | **Blocked by AST** (`EXTERNAL_ACCESS_OR_DOS_FUNCTION`) | Layer 2 |
| **File Read SSRF (Engine Direct)** | Direct `read_csv('...')`, `glob('*')` bypassing AST | **Blocked by Engine** (`duckdb.PermissionException`) | Layer 3 (Primary Wall) |
| **Engine Config Tampering** | `SET enable_external_access = true`, `SET memory_limit = '10GB'` | **Blocked by Engine** (`configuration has been locked`) | Layer 3 (Primary Wall) |
| **Join Tautology (Literal)** | `JOIN ... ON 2 > 1`, `JOIN ... ON 'a'='a'`, `JOIN ... ON TRUE` | **Blocked by AST** (`CARTESIAN_JOIN_DOS`) | Layer 2 |
| **Join Tautology (Self-Ref)**| `JOIN ... ON a.org_id = a.org_id` (x=x) | **Blocked by AST** (`CARTESIAN_JOIN_DOS`) | Layer 2 |
| **Synthetic Generators** | `SELECT generate_series(1, 10000000)`, `range(...)` | **Blocked by AST** (`EXTERNAL_ACCESS_OR_DOS_FUNCTION`) | Layer 2 |
| **Row Explosion (`unnest`)** | `SELECT unnest([1, 2, 3]) FROM organizations` | **Allowed & Clamped** to `LIMIT <= 1000` | Layer 2 & 3 |
| **Unbounded Recursive CTE** | `WITH RECURSIVE nums(x) AS (...) SELECT ...` | **Allowed by AST, Aborted by Watchdog** (`QueryTimeoutError`) | Layer 3 (`conn.interrupt()`) |
| **Excessive Joins (> 4)** | 5-way join query | **Blocked by AST** (`DOS_COMPLEXITY_EXCEEDED`) | Layer 2 |
| **Low-Cardinality Self-Join**| `SELECT * FROM organizations a JOIN organizations b ON a.plan_tier = b.plan_tier` | **Allowed & Clamped** to `LIMIT <= 1000` | Layer 2 & 3 |
| **PII Column Access** | `SELECT billing_email FROM organizations` (as analyst) | **Blocked by AST** (`RBAC_PII_COLUMN_RESTRICTED`) | Layer 2 |
| **PII Aliasing / Wrapping** | `SELECT e FROM (SELECT billing_email AS e FROM organizations)` | **Blocked by AST** (`RBAC_PII_COLUMN_RESTRICTED`) | Layer 2 |
| **PII CTE / Expression** | `SELECT concat(billing_email, '') FROM organizations` | **Blocked by AST** (`RBAC_PII_COLUMN_RESTRICTED`) | Layer 2 |
| **Wildcard on PII Table** | `SELECT * FROM organizations` (as analyst) | **Blocked by AST** (`RBAC_WILDCARD_ON_PII_TABLE`) | Layer 2 |
| **Huge LIMIT Request** | `LIMIT 999999999` (root or subquery) | **Clamped by AST** to `LIMIT 1000` | Layer 2 |
| **OFFSET Abuse** | `SELECT org_name FROM organizations LIMIT 10 OFFSET 1000000` | **Allowed & Bounded** (scans memory, returns 0 rows safely) | Layer 3 |
| **Forged Bearer Token** | `Authorization: Bearer forged-token-xyz` | **Rejected with HTTP 401** (`invalid_token`) | Layer 1 |
| **Public Viewer Calling Tool**| `public_viewer` directly calling `execute_analytical_sql` | **Blocked by RBAC** (`PermissionError` in middleware & engine) | Layer 1 & 3 |

---

## Pre-seeded Manufact Cloud Telemetry Dataset

The in-memory DuckDB database is pre-seeded with realistic relational telemetry:

| Table | Records | Access Tier | Description | Restricted PII Columns |
| :--- | :---: | :---: | :--- | :--- |
| `organizations` | 10 | Analyst / Admin | AI startups and scaleups on Manufact Cloud | `billing_email`, `stripe_customer_id` |
| `mcp_servers` | 12 | Analyst / Admin | Deployed MCP servers, runtimes, status, cold starts | `webhook_secret` |
| `tool_invocations` | 20 | Analyst / Admin | Telemetry logs: tool calls, latencies, tokens saved | `client_ip` |
| `subscriptions` | 10 | Analyst / Admin | Monthly quotas, used calls, renewal timestamps | `stripe_customer_id` |
| `api_keys` | 4 | **Admin Only** | Hashed API tokens and scope delegations | `key_hash`, `raw_token_prefix` |
| `security_incidents` | 4 | **Admin Only** | Historical attacks blocked by the security sandbox | *None (All admin-only)* |

---

## Protocol Showcase (`mcp-use` Primitives)

### 1. Tools

All tools are registered with modern MCP `ToolAnnotations` and stream live diagnostics using `Context`:

* `whoami()`: Returns caller identity, RBAC role, scopes, allowed tools, and accessible tables.
* `list_tables()`: Returns schema metadata, row counts, and column classifications for accessible tables.
* `describe_table(table_name)`: Returns column types, nullability, primary keys, and current-role queryability. Uses Python `Literal` to render an interactive dropdown in MCP clients.
* `verify_query_safety(sql, requested_limit)`: Dry-run AST inspection testing Layer 2 safety without executing SQL.
* `execute_analytical_sql(sql, limit)`: Validates and executes analytical queries inside DuckDB sandbox. Requires `analyst` or `admin`.
* `get_security_audit_log(limit, status_filter)`: Retrieves recent security events and telemetry summary stats. Requires `admin`.

### 2. Resources

* `schema://catalog`: Complete JSON catalog of accessible warehouse tables, schemas, and classifications.
* `schema://tables/{table_name}`: Dynamic per-table JSON schema specification with column types and PII flags.
* `policy://security-rules`: Markdown policy detailing the 4-layer security architecture and governance rules.

### 3. Prompts

* `executive_analytics(focus_area)`: Prompt instructing LLM agents to compute MRR growth, token efficiency, or server reliability.
* `red_team_security_audit(target_vector)`: Adversarial testing harness with concrete attack payloads testing each security barrier.

---

## RBAC Role Matrix

| Capability / Tool | `public_viewer` | `analyst` | `admin` |
| :--- | :---: | :---: | :---: |
| `whoami` |  Allowed |  Allowed |  Allowed |
| `list_tables` |  Allowed |  Allowed |  Allowed |
| `describe_table` |  Allowed |  Allowed |  Allowed |
| `verify_query_safety` |  Allowed |  Allowed |  Allowed |
| `execute_analytical_sql` |  *Hidden / Blocked* |  Allowed |  Allowed |
| `get_security_audit_log` |  *Hidden / Blocked* |  *Hidden / Blocked* |  Allowed |
| Read Safe Tables |  Allowed |  Allowed |  Allowed |
| Read `api_keys` / `security_incidents` |  Blocked |  Blocked |  Allowed |
| Read PII (`billing_email`, etc.) |  Blocked |  Blocked |  Allowed |
| `SELECT *` on PII Tables |  Blocked |  Blocked |  Allowed |
| Demo Token (DEV ONLY) | `token-viewer-demo` | `token-analyst-demo` | `token-admin-demo` |

---

## Quickstart

### Prerequisites
* Python 3.11+
* [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Installation & Setup

```bash
# 1. Clone repository
git clone https://github.com/hamza-ali/mcp-secure-db.git
cd mcp-secure-db

# 2. Sync dependencies with uv
uv sync

# 3. Start the server (streamable-http on port 8000)
uv run python server.py
```

### Inspecting with MCP Inspector

Test interactively in your browser:

```bash
npx @modelcontextprotocol/inspector http://localhost:8000/mcp
```

To authenticate as an Analyst or Admin in the Inspector, provide HTTP headers:
```
Authorization: Bearer token-analyst-demo
```
or
```
Authorization: Bearer token-admin-demo
```

*(Note: In production, configure tokens via `MCP_VIEWER_TOKEN`, `MCP_ANALYST_TOKEN`, and `MCP_ADMIN_TOKEN`.)*

---

## Running the Verification Suite

Run the full pytest suite:

```bash
uv run pytest
```

Test coverage by category:
- `tests/test_adversarial.py` (22 tests): Dedicated red-team harness testing join tautologies, row-explosion functions, recursive CTE timeouts, comment and whitespace evasion, unicode lookalikes, multi-statement breakouts, PII wrapping/aliasing, LIMIT/OFFSET clamping, RBAC bypasses, and direct C++ engine blocks.
- `tests/test_validator.py` (54 tests): DDL/DML rejection, tokenized comment smuggling, SSRF functions, Cartesian joins & tautologies, PII columns, LIMIT clamping, string literals with `--` and `;`.
- `tests/test_engine.py` (13 tests): DuckDB C++ kernel locking, direct file reader blocking without AST, table counts, schema introspection, interrupt watchdog timeout, telemetry ring buffer.
- `tests/test_rbac.py` (9 tests): Token resolution, BearerAuthProvider, RBACMiddleware header extraction, fallback mechanism, dynamic `on_list_tools` filtering.
- `tests/test_server.py` (14 tests): MCPServer end-to-end integration, all 6 tools, 3 resources, 2 prompts, on_request resource RBAC, and Hybrid HTTP auth.
- `tests/test_example_server.py` (10 tests): Standalone PR example validation, tool permissions, schema resources, prompts, and watchdog interrupt.

---

## Dockpack & Manufact Cloud Deployment

`mcp-secure-db` is built to be 100% compliant with Manufact Cloud's **Dockpack** container packaging:

1. **Standard `Dockerfile`**: Multi-stage Python 3.12-slim build with non-root security (`appuser:1001`).
2. **Standard Entrypoint**: Root `server.py` honoring standard environment variables:
   - `HOST`: Binds to `0.0.0.0` in container, `127.0.0.1` locally.
   - `PORT`: Binds to `8000`.
   - `MCP_TRANSPORT`: Defaults to `streamable-http`.
3. **Zero Configuration**: No proprietary config files (Dockpack autodetects standard Dockerfiles and Python environments).

### Building and Running Docker Image Locally

```bash
# Build image
docker build -t mcp-secure-db:latest .

# Run container
docker run -p 8000:8000 mcp-secure-db:latest
```

---

## Standalone Example for `mcp-use` PR

Under `examples/secure_db_server_example.py`, a single-file, self-contained version of this architecture is provided. It is ready for direct submission to the upstream `mcp-use/mcp-use` repository under `libraries/python/examples/server/secure_db_server_example.py`.

```bash
# Run standalone example
uv run python examples/secure_db_server_example.py
```

---

## Authors & Acknowledgments

* **Built by**: Hamza Ali
* **Built for**: Manufact (`manufact.com`, founders Pietro Zullo & Luigi Pederzani)
* **Framework**: `mcp-use` (The open-source Model Context Protocol SDK)
