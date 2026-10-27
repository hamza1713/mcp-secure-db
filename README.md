# mcp-secure-db

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![mcp-use 1.7+](https://img.shields.io/badge/mcp--use-1.7.1-orange.svg)](https://github.com/mcp-use/mcp-use)
[![DuckDB](https://img.shields.io/badge/DuckDB-In--Memory%20Columnar-yellow.svg)](https://duckdb.org/)
[![Tests](https://img.shields.io/badge/pytest-96%20passing-brightgreen.svg)](tests/)
[![Dockpack](https://img.shields.io/badge/Dockpack-Ready-success.svg)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

**Enterprise-grade, 4-layer sandboxed analytical database MCP server built natively on `mcp-use` for Manufact Cloud.**

---

## Executive Summary

Connecting autonomous LLM agents to production or analytical databases introduces severe security risks:
1. **Prompt Injection & Destructive Mutation**: Smuggled `DROP TABLE`, `TRUNCATE`, or `DELETE` statements.
2. **Server-Side Request Forgery (SSRF) & File Exfiltration**: Reading `/etc/passwd` or cloud metadata (`http://169.254.169.254/`) via DuckDB functions like `read_csv` or `parquet_scan`.
3. **Comment Smuggling & Prompt Poisoning**: Injection hidden inside `--` line comments or `/* */` block comments.
4. **Denial of Service (DoS)**: Unconstrained Cartesian `CROSS JOIN` operations and synthetic unbounded row generators exhausting server memory.
5. **PII & Credential Leaks**: Unauthorized access to API keys, webhook secrets, billing emails, and Stripe IDs.

`mcp-secure-db` solves these challenges through a **deterministic 4-layer defense-in-depth architecture** that guarantees safety with **zero LLM token consumption overhead**.

---

## 4-Layer Defense-in-Depth Architecture

```
                                  [ MCP Client / Agent ]
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: Hybrid RBAC Middleware & Token Resolution (mcp-use Middleware)               │
│ • Bearer token authentication (token-viewer-demo, token-analyst-demo, token-admin-demo)│
│ • Graceful fallback to public_viewer for zero-friction MCP Inspector & stdio debugging │
│ • Dynamic tool masking: unpermitted tools are hidden from tools/list                   │
│ • Hard call-time rejection in on_call_tool before execution                            │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: Deterministic AST SQL Validator & Policy Engine (sqlglot DuckDB Dialect)      │
│ • Strict read-only: blocks DROP, DELETE, UPDATE, INSERT, ALTER, PRAGMA, COPY, ATTACH   │
│ • Anti-smuggling: strips comments (-- and /* */) and rejects multi-statements (;)      │
│ • SSRF & Exfiltration ban: blocks read_csv, read_parquet, parquet_scan, glob, st_read │
│ • DoS prevention: blocks Cartesian CROSS JOINs; enforces max 4 joins per query         │
│ • Governance: blocks admin-only tables & PII columns; bans SELECT * on PII tables      │
│ • Automatic LIMIT injection & clamping (default 100, max 1000 rows)                    │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: Interruptible In-Memory DuckDB C++ Kernel Sandbox                             │
│ • C++ hardening: SET enable_external_access = false; SET memory_limit = '512MB';       │
│ • Kernel lock: SET lock_configuration = true; (prevents pragma overrides)              │
│ • Active watchdog: 10-second hard deadline with native C++ conn.interrupt() abort      │
└───────────────────────────────────────────┬────────────────────────────────────────────┘
                                            │
                                            ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: Structured Output Telemetry & Audit Ring Buffer                               │
│ • Standardized JSON response with full execution provenance, latency, and row counts   │
│ • In-memory thread-safe ring buffer recording all queries, timeouts, and blocks       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Pre-seeded Manufact Cloud Telemetry Dataset

The in-memory DuckDB database is pre-seeded with realistic, relational cloud and MCP infrastructure telemetry:

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

* `executive_analytics(focus_area)`: Expert prompt instructing LLM agents to compute MRR growth, token efficiency, or server reliability.
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
| Demo Token | `token-viewer-demo` | `token-analyst-demo` | `token-admin-demo` |

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

---

## Red Team Attack Matrix & Defense Verification

| Attack Vector | Example Payload | Layer | Enforcement Mechanism |
| :--- | :--- | :---: | :--- |
| **Comment Smuggling** | `SELECT org_name FROM organizations -- smuggled` | Layer 2 | Token-level scan & AST reject `--` and `/* */` comments while allowing string literals |
| **Multi-Statement** | `SELECT org_name FROM organizations; DROP TABLE organizations;` | Layer 2 | Token-level semicolon detection blocks chained statements |
| **Destructive DDL** | `DROP TABLE organizations` | Layer 2 | AST parser blocks `exp.Drop` and all mutating statements |
| **DuckDB SSRF** | `SELECT * FROM read_csv_auto('http://169.254.169.254/')` | Layer 2 & 3 | AST blocks `read_csv*`; C++ `enable_external_access = false` |
| **File Exfiltration** | `SELECT * FROM read_csv('/etc/passwd')` | Layer 2 & 3 | AST blocks file functions; table path regex rejects file names |
| **Cartesian Join DoS**| `SELECT * FROM organizations a JOIN tool_invocations b ON 1=1` | Layer 2 | Validator forbids CROSS JOIN, comma joins, and degenerate literal tautologies (`ON 1=1`) |
| **PII Data Leakage** | `SELECT org_name, billing_email FROM organizations` | Layer 2 | Rejects PII columns unless caller role is `admin` |
| **Wildcard PII Leak** | `SELECT * FROM organizations` | Layer 2 | Blocks `SELECT *` on PII tables unless caller role is `admin` |
| **Compute Exhaustion** | Heavy recursive CTE without row bounds | Layer 3 | Hardware watchdog fires `conn.interrupt()` at 10s deadline |

---

## Running the Verification Suite

Run the full pytest suite (96 comprehensive security tests):

```bash
uv run pytest
```

Output:
```
================= 96 passed in 10.94s ==================
```

Test coverage includes:
- `tests/test_validator.py` (54 tests): DDL/DML rejection, tokenized comment smuggling, SSRF functions, Cartesian joins & tautologies, PII columns, LIMIT clamping, string literals with `--` and `;`.
- `tests/test_engine.py` (12 tests): DuckDB C++ kernel locking, table counts, schema introspection, interrupt watchdog timeout, telemetry ring buffer.
- `tests/test_rbac.py` (9 tests): Token resolution, BearerAuthProvider, RBACMiddleware header extraction, fallback mechanism, dynamic `on_list_tools` filtering.
- `tests/test_server.py` (12 tests): MCPServer end-to-end integration, all 6 tools, 3 resources, and 2 prompts.
- `tests/test_example_server.py` (9 tests): Standalone PR example validation, tool permissions, schema resources, prompts, and watchdog interrupt.

---

## Dockpack & Manufact Cloud Deployment

`mcp-secure-db` is built to be 100% compliant with Manufact Cloud's **Dockpack** container packaging:

1. **Standard `Dockerfile`**: Multi-stage Python 3.12-slim build with non-root security (`appuser:1001`).
2. **Standard Entrypoint**: Root `server.py` honoring standard environment variables:
   - `HOST`: Binds to `0.0.0.0`.
   - `PORT`: Binds to `8000`.
   - `MCP_TRANSPORT`: Defaults to `streamable-http`.
3. **Zero Configuration**: No proprietary config files (`manufact.yaml` does not exist in Manufact's spec; Dockpack autodetects standard Dockerfiles and Python environments).

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
