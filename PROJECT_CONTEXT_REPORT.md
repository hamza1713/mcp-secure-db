# PROJECT CONTEXT & VERIFICATION REPORT: mcp-secure-db

**Target Startup**: Manufact (`manufact.com`)  
**Founders**: Pietro Zullo & Luigi Pederzani  
**Product**: Manufact Cloud & `mcp-use` SDK  
**Author**: Hamza Ali  
**Date**: October 2026  
**Status**: Production Ready & Fully Verified (96/96 pytest tests passing)

---

## 1. Executive Context & Objective

The Model Context Protocol (MCP) connects LLMs to external systems and tools. However, exposing analytical databases directly to AI agents without strict guardrails creates severe security vulnerabilities:
* Prompt injection leading to destructive schema alterations (`DROP`, `ALTER`, `TRUNCATE`).
* SSRF and server exfiltration (`read_csv_auto('/etc/passwd')` or metadata service scraping).
* Compute exhaustion via unconstrained Cartesian joins (`CROSS JOIN`).
* Unauthorized exfiltration of PII (billing emails, Stripe customer IDs, API keys, webhook secrets).

This project implements **`mcp-secure-db`**, a reference architecture that demonstrates how to securely sandbox analytical database access using `mcp-use`. It provides:
1. **Dual-Track Delivery**:
   * **Track A**: Full standalone enterprise repository with Dockpack compliance, comprehensive tests, and modular architecture.
   * **Track B**: A single-file, self-contained example (`examples/secure_db_server_example.py`) prepared for direct pull request submission to `mcp-use/mcp-use` under `libraries/python/examples/server/`.
2. **Zero-Token Overhead**: Rather than relying on expensive, nondeterministic LLM-based query checking, all AST validation and policy enforcement is handled deterministically via `sqlglot` at C++ speeds.

---

## 2. Fact-Checking & Technical Corrections (No Hallucinations)

During the architectural review, key corrections were made to eliminate inaccuracies:

1. **No `manufact.yaml` File**:
   * Earlier preliminary concepts suggested creating a proprietary `manufact.yaml` configuration file.
   * **Fact**: Manufact Cloud does not use or recognize `manufact.yaml`. Manufact uses **Dockpack**, an automated build system that natively ingests standard `Dockerfile`, `pyproject.toml`, or `requirements.txt`.
   * **Resolution**: The project provides a clean, standard, multi-stage `Dockerfile` (Python 3.12-slim, non-root user `appuser:1001`, port 8000) and standard `server.py` entrypoint.

2. **Transport Standard**:
   * Manufact Cloud's primary transport protocol is `streamable-http`.
   * **Resolution**: Root `server.py` defaults to `transport="streamable-http"`, binding to `HOST` (0.0.0.0) and `PORT` (8000).

3. **Hybrid RBAC with Graceful Fallback**:
   * Requiring strict authentication headers in all environments breaks out-of-the-box local testing with tools like MCP Inspector and Claude Desktop (stdio).
   * **Resolution**: Implemented hybrid resolution: if Bearer or API Key headers are present, authenticate against the role registry (`token-viewer-demo`, `token-analyst-demo`, `token-admin-demo`); if absent, gracefully fall back to `public_viewer` (unless `strict_auth=True` is explicitly toggled).

---

## 3. Four-Layer Defense-in-Depth Specification

### Layer 1: RBAC Middleware & Dynamic Tool Masking
* **Component**: `mcp_secure_db.security.rbac.RBACMiddleware`
* **Features**:
  * Extends `mcp_use.server.middleware.Middleware`.
  * Integrates with `mcp_use.server.auth.BearerAuthProvider` via `SecureDBBearerAuthProvider`.
  * Dynamic `on_list_tools`: lower-privilege roles cannot even discover prohibited tools (e.g., `execute_analytical_sql` is hidden from `public_viewer`; `get_security_audit_log` is hidden from both `public_viewer` and `analyst`).
  * Hard enforcement in `on_call_tool`: raises `PermissionError` if an unauthorized tool call is attempted.

### Layer 2: Deterministic Zero-Token AST Validator (sqlglot)
* **Component**: `mcp_secure_db.security.validator.SQLValidator`
* **Features**:
  * Operates on DuckDB SQL dialect AST.
  * Token-level comment scanning: blocks SQL comments (`--` and `/* */`) to neutralize comment-smuggled payloads, while accurately permitting string literals containing `--` or `/*` (e.g., `WHERE col = 'foo--bar'`).
  * Token-level multi-statement prevention: blocks chained statements with internal semicolons (`;`) while allowing semicolons inside quoted literals.
  * Rejects all mutating AST nodes: `exp.Drop`, `exp.Delete`, `exp.Update`, `exp.Insert`, `exp.Create`, `exp.Alter`, `exp.Pragma`, `exp.Copy`, `exp.Attach`, `exp.Detach`, etc.
  * Blocks SSRF & file access functions: `read_csv`, `read_csv_auto`, `read_parquet`, `parquet_scan`, `glob`, `st_read`, `repeat`, `sleep`.
  * Forbids file path or URL table references (e.g., `FROM '/etc/passwd'`).
  * Blocks Cartesian joins: rejects `CROSS JOIN`, unconstrained comma joins, and degenerate literal tautologies (`ON 1=1`, `ON true`, `ON 'a'='a'`).
  * Clamps query `LIMIT` to `max_rows` (1000) and injects `default_limit` (100) if omitted.
  * Governs table and column visibility: blocks access to `api_keys` and `security_incidents` for non-admins; blocks columns containing PII (`billing_email`, `stripe_customer_id`, `webhook_secret`, `client_ip`) unless caller is `admin`; blocks `SELECT *` on PII tables for non-admins.

### Layer 3: Interruptible DuckDB Kernel Sandbox
* **Component**: `mcp_secure_db.database.engine.SecureDuckDBEngine`
* **Features**:
  * In-memory DuckDB database (`:memory:`).
  * Hardware hardening: `SET enable_external_access = false;`, `SET memory_limit = '512MB';`, `SET threads = 2;`.
  * Kernel lockdown: `SET lock_configuration = true;` (prevents malicious SQL from altering security pragmas).
  * Active Hardware Watchdog: 10-second hard deadline. If query execution exceeds the deadline, a background thread issues `conn.interrupt()` directly into the DuckDB C++ kernel, immediately aborting execution and raising `QueryTimeoutError`.

### Layer 4: Structured Output Telemetry & Provenance
* **Component**: `mcp_secure_db.database.engine.AuditLogger`
* **Features**:
  * Standardized `QueryExecutionResult` response schema returning execution time, row count, limit applied, columns, rows, and sandbox configuration.
  * Thread-safe ring buffer (`AuditLogger`) tracking all query executions, RBAC blocks, AST blocks, and timeouts.

---

## 4. MCP Primitives Implemented

| Category | Identifier | Description | Role Required |
| :--- | :--- | :--- | :--- |
| **Tool** | `whoami` | Inspect active principal, role, scopes, and allowed tools | Any (`public_viewer`+) |
| **Tool** | `list_tables` | List accessible tables with row count and safe column lists | Any (`public_viewer`+) |
| **Tool** | `describe_table` | Schema metadata with `Literal` table dropdown and PII flags | Any (`public_viewer`+) |
| **Tool** | `verify_query_safety` | Dry-run AST inspection without query execution | Any (`public_viewer`+) |
| **Tool** | `execute_analytical_sql` | Execute bounded analytical SQL in DuckDB sandbox | `analyst`, `admin` |
| **Tool** | `get_security_audit_log` | Inspect telemetry ring buffer and violation statistics | `admin` |
| **Resource** | `schema://catalog` | JSON catalog of accessible warehouse tables | Any (`public_viewer`+) |
| **Resource** | `schema://tables/{table_name}` | Per-table schema details, data types, and PII policy | Any (`public_viewer`+) |
| **Resource** | `policy://security-rules` | Markdown policy specification of the 4-layer architecture | Any (`public_viewer`+) |
| **Prompt** | `executive_analytics` | Executive briefing template for AI cloud metrics | Any (`public_viewer`+) |
| **Prompt** | `red_team_security_audit` | Adversarial test harness with concrete attack payloads | Any (`public_viewer`+) |

---

## 5. Automated Verification Results

All tests were executed using `pytest` via `uv run pytest`.

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1
rootdir: C:\Users\Hamza Ali\Desktop\MCP Secure DB
configfile: pyproject.toml
testpaths: tests
plugins: anyio-4.12.1, asyncio-0.23.8
collected 96 items

tests/test_engine.py ............                                        [ 12%]
tests/test_example_server.py .........                                   [ 21%]
tests/test_rbac.py .........                                             [ 31%]
tests/test_server.py ............                                        [ 43%]
tests/test_validator.py ...................................................... [100%]

============================== 96 passed in 10.94s ==============================
```

### Coverage Highlights:
* **AST Validator (54 test cases)**: Tested tokenized comments (`--`, `/* */`), string literals with `--` and `;`, comment-only inputs, multiple statements, mutating statements (`DROP`, `DELETE`, `UPDATE`, `INSERT`, `CREATE`, `ALTER`, `TRUNCATE`, `COPY`, `PRAGMA`, `ATTACH`, `DETACH`), functions (`read_csv`, `read_parquet`, `glob`, `st_read`, `repeat`, `sleep`), Cartesian joins and degenerate literal tautologies (`ON 1=1`, `ON true`), table name smuggling, admin-only table blocking, PII column blocking, wildcard `SELECT *` blocking, and LIMIT injection/clamping.
* **DuckDB Sandbox & Watchdog (12 test cases)**: Verified pre-seeded data counts, C++ configuration locking, table access filtering, schema inspection, query execution, hardware watchdog timeout triggering `conn.interrupt()`, and telemetry aggregation.
* **RBAC & Auth (9 test cases)**: Verified token resolution, `BearerAuthProvider`, header resolution, fallback mechanism, dynamic `on_list_tools` filtering, and call-time authorization.
* **Server Primitives (12 test cases)**: Verified all 6 tools, 3 resources, and 2 prompts end-to-end on `MCPServer`.
* **Standalone Example (9 test cases)**: Verified `examples/secure_db_server_example.py` single-file PR example, all 6 tools, schema/policy resources, prompts, and watchdog interrupt timeout.

---

## 6. Founder Outreach Playbook (Pietro Zullo & Luigi Pederzani)

### Step 1: Open Upstream PR to `mcp-use/mcp-use`
* **File to Submit**: `examples/secure_db_server_example.py`
* **Target Path**: `libraries/python/examples/server/secure_db_server_example.py`
* **PR Title**: `feat(examples): add secure sandboxed analytical database MCP server example`
* **PR Description Summary**:
  > "Hi Pietro and Luigi — We built a production-grade analytical database MCP server example showcasing `mcp-use`'s native primitives (`MCPServer`, `BearerAuthProvider`, `Middleware`, `Context` streaming, `ToolAnnotations`, Resources, and Prompts).
  >
  > It demonstrates how enterprise developers can safely expose DuckDB to LLMs with a 4-layer defense: RBAC middleware, zero-token AST validation via sqlglot, interruptible DuckDB C++ execution, and structured telemetry. Tested and self-contained in a single file."

### Step 2: Deploy to Manufact Cloud via Dockpack
* Push the repository to GitHub.
* Deploy directly to Manufact Cloud using Dockpack (automatically builds from `Dockerfile` and runs `server.py` on port 8000).
* Share live deployment endpoint with Pietro and Luigi for interactive testing via MCP Inspector.

### Step 3: High-Conversion Cold Email & DM

**Subject:** Production Secure DuckDB template for mcp-use (Dockpack & MCP Inspector ready)  
**To:** `pietro@manufact.com`, `luigi@manufact.com`  

> Hi Pietro and Luigi,
> 
> Really impressed by how **mcp-use** is standardizing the MCP developer experience and how **Manufact** is solving managed deployment with Dockpack.
> 
> A common hurdle for enterprise developers connecting AI agents to internal analytics is **execution safety and authorization**—preventing LLMs from hallucinating destructive DDL/DML, exfiltrating data via DuckDB file functions (`read_csv_auto`), or bypassing role boundaries.
> 
> To test the framework and provide a showcase template for Manufact Cloud, I built a production-ready starter:
> 
> **`mcp-secure-db`** (Built natively on `mcp-use` 1.7.1):
> * **Layer 1 (RBAC Middleware & BearerAuth):** Dynamic `on_list_tools` filtering so unauthorized tools are invisible to callers, plus role-based permissions (`public_viewer`, `analyst`, `admin`).
> * **Layer 2 (Deterministic AST Validation):** Zero-token-cost `sqlglot` validation blocking multi-statements, comments, DDL/DML, DuckDB file/network functions, Cartesian join DoS (`ON 1=1`), and enforcing column-level PII protection.
> * **Layer 3 (Sandboxed DuckDB & Watchdog):** In-memory DuckDB locked with `enable_external_access=false` + `lock_configuration=true`, with hardware-level `conn.interrupt()` aborting runaway queries after 10s.
> * **Layer 4 (Telemetry & Audit Ring Buffer):** In-memory audit logger tracking every allowed/blocked attempt with latency ms and row counts.
> * **Dockpack & Inspector Ready:** Includes Dockerfile, pre-seeded MCP Cloud Telemetry dataset, and 1-click Inspector prompts (`red_team_security_audit`, `executive_analytics`).
> * **Test Suite:** 96 passing pytest tests covering security vectors, RBAC, and engine interrupts.
> 
> I also submitted a self-contained PR adding this under `libraries/python/examples/server/secure_db_server_example.py` to fill the Python server examples gap.
> 
> * **GitHub Repository:** [Your GitHub Link]
> * **Pull Request:** [Your PR Link]
> * **45-Second Demo (Live in Inspector via Manufact Cloud):** [Loom Link]
> 
> If you have an engineering backlog around Python SDK improvements or enterprise security adapters, I'd love to help as a remote intern or contractor.
> 
> Best regards,  
> **Hamza Ali**  
> AI Systems Engineer | Lahore, Pakistan | [GitHub] | [LinkedIn]

**Short X / LinkedIn DM:**
> "Hey Pietro / Luigi — loved what you're doing with Manufact and mcp-use! I noticed `libraries/python/examples/server` only had 3 basic examples, so I built `mcp-secure-db`: a 4-layer sandboxed DuckDB template (RBAC middleware, sqlglot AST protection, DuckDB C++ lock, and 10s interrupt watchdog). Backed by 96 passing tests and Dockpack-ready. Just opened a PR with a self-contained example! [PR Link]"

---

## 7. Project File Structure

```
MCP Secure DB/
├── Dockerfile                             # Multi-stage Dockpack build (Python 3.12-slim, non-root)
├── pyproject.toml                         # Project metadata, dependencies, and pytest configuration
├── requirements.txt                       # Locked dependencies for Dockpack uv pip install
├── README.md                              # Public documentation with architecture diagrams & quickstart
├── PROJECT_CONTEXT_REPORT.md              # Architectural audit, fact-check, and founder playbook
├── server.py                              # Dockpack entrypoint (streamable-http on port 8000)
├── src/
│   └── mcp_secure_db/
│       ├── __init__.py                    # Version declaration (1.0.0)
│       ├── server.py                      # MCPServer factory wiring tools, resources, and prompts
│       ├── security/
│       │   ├── __init__.py
│       │   ├── rbac.py                    # Layer 1: RBACMiddleware, BearerAuth, tokens, roles
│       │   └── validator.py               # Layer 2: sqlglot AST validator, anti-smuggling, SSRF block
│       └── database/
│           ├── __init__.py
│           └── engine.py                  # Layers 3 & 4: Sandboxed DuckDB, watchdog, audit ring buffer
├── examples/
│   └── secure_db_server_example.py        # Self-contained single-file PR example for mcp-use
└── tests/
    ├── test_validator.py                  # 54 AST security & policy test cases
    ├── test_engine.py                     # 12 DuckDB engine, sandbox, timeout, telemetry tests
    ├── test_rbac.py                       # 9 RBAC middleware & token resolution tests
    ├── test_server.py                     # 12 MCPServer tools, resources, and prompt tests
    └── test_example_server.py             # 9 standalone PR example tests
```
