# mcp-secure-db (TypeScript)

> **Zero-Token Deterministic Secure Analytical Database Sandbox MCP Server**  
> Built with the official **`mcp-use`** TypeScript SDK, `node-sql-parser`, and in-memory WebAssembly SQLite. Fully compliant with **Manufact Cloud (Dockpack)** standards.

[![Tests](https://img.shields.io/badge/Tests-49%2F49%20Passing-brightgreen)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue)]()
[![SDK](https://img.shields.io/badge/SDK-mcp--use%20v2.12.2-purple)]()
[![Security](https://img.shields.io/badge/Security-Deterministic%20AST%20(Zero%20Tokens)-orange)]()

---

## 1. Overview & Threat Model

Exposing databases directly to AI agents via the **Model Context Protocol (MCP)** introduces severe security vulnerabilities:
1. **Prompt Injection / Destructive DDL & DML**: Malicious or hallucinated queries executing `DROP TABLE`, `ALTER`, `TRUNCATE`, `DELETE`, or `UPDATE`.
2. **SSRF & Filesystem Exfiltration**: Query functions accessing server files (`read_csv('/etc/passwd')`) or local networks.
3. **Compute Exhaustion & DoS**: Unconstrained Cartesian `CROSS JOIN` queries or queries without row bounds crashing server memory.
4. **PII Exfiltration**: Models inadvertently exfiltrating Stripe customer IDs, webhook secrets, or billing emails.

**`mcp-secure-db`** implements a **4-layer defense-in-depth architecture** that mitigates all four threat vectors with **zero token cost** by leveraging deterministic AST validation in TypeScript before any query touches the database engine.

---

## 2. Four-Layer Defense-in-Depth Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: RBAC Middleware & Dynamic Tool Masking                       │
│  - Hides sensitive tools based on Bearer token / role (viewer/analyst/admin)
│  - Blocks unauthorized tool invocation before execution                │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 2: Zero-Token Deterministic AST Validator (node-sql-parser)     │
│  - Pre-execution validation in <1ms without calling an LLM            │
│  - Blocks SQL comments, chained semicolons, mutating DDL/DML, SSRF     │
│  - Rejects Cartesian joins & tautologies (`ON 1=1`)                    │
│  - Clamps/injects LIMIT clauses; enforces table & column-level PII masks
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 3: In-Memory Kernel Sandbox (sql.js / WebAssembly SQLite)       │
│  - In-memory database with zero filesystem or network bindings         │
│  - 512MB memory boundary & 10-second hard execution watchdog           │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 4: Structured Output Telemetry & Audit Ring Buffer              │
│  - Standardized JSON responses with row bounds, columns, timing        │
│  - In-memory thread-safe ring buffer recording all queries and blocks  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. MCP Primitives Implemented

### Tools

| Tool | Description | Role Required |
| :--- | :--- | :--- |
| `whoami` | Inspect active principal, role, scopes, and allowed tools | Any (`public_viewer`+) |
| `list_tables` | List accessible warehouse tables with row counts and visible columns | Any (`public_viewer`+) |
| `describe_table` | Schema metadata with PII flags (PII columns masked for non-admins) | Any (`public_viewer`+) |
| `verify_query_safety` | Dry-run AST inspection without executing query (0 token cost) | Any (`public_viewer`+) |
| `execute_analytical_sql` | Execute bounded analytical SELECT queries in the WASM sandbox | `analyst`, `admin` |
| `get_security_audit_log` | Inspect telemetry ring buffer and security violation statistics | `admin` |

### Resources

* `schema://catalog`: Full JSON catalog of all analytical warehouse tables.
* `policy://security-rules`: Markdown policy specification of the 4-layer defense.

### Prompts

* `executive_analytics`: Executive briefing template for SaaS compute and revenue metrics.
* `red_team_security_audit`: Adversarial penetration testing harness to verify defense boundaries.

---

## 4. Role Hierarchy & Authentication Tokens

| Token | Role | Scopes | Allowed Tools |
| :--- | :--- | :--- | :--- |
| *(None / Missing)* | `public_viewer` | `db:read:metadata` | `whoami`, `list_tables`, `describe_table`, `verify_query_safety` |
| `token-analyst-demo` | `analyst` | `db:read:metadata`, `db:execute:analytics` | Viewer tools + `execute_analytical_sql` |
| `token-admin-demo` | `admin` | All scopes + `db:audit:read`, `db:pii:access` | All tools + `get_security_audit_log` |

---

## 5. Quick Start & Verification

### Prerequisites
* Node.js `>= 22.0.0`
* `pnpm` (install with `npm install -g pnpm`)

### Installation & Test Suite

```bash
# 1. Install dependencies
pnpm install

# 2. Run typecheck
pnpm typecheck

# 3. Run all 49 Vitest unit & integration tests
pnpm test

# 4. Build the server
pnpm build

# 5. Start development server with MCP Inspector
pnpm dev
```

---

## 6. Docker & Manufact Cloud Deployment

This repository includes a multi-stage `Dockerfile` tested for **Manufact Cloud (Dockpack)** standards:

```bash
docker build -t mcp-secure-db .
docker run -p 8000:8000 mcp-secure-db
```

---

## 7. License

MIT
