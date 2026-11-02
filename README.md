# mcp-secure-db (TypeScript)

> **Reference implementation and proof of concept for layered SQL query guardrails over MCP**  
> Built with the `mcp-use` TypeScript SDK (`2.12.2` [E:CLAIM-001]), `node-sql-parser` (`5.4.0` [E:CLAIM-002]), and an in-process SQLite sandbox (`sql.js` `1.15.2` [E:CLAIM-002]).

---

## 1. Overview and Scope

Exposing analytical databases to AI agents over the **Model Context Protocol (MCP)** creates concrete risks:
1. **Destructive or mutating SQL**: Prompt-injected or malformed agent calls attempting `DROP`, `ALTER`, `DELETE`, `UPDATE`, or `INSERT`.
2. **Dangerous engine functions and extension loading**: Queries invoking extension loaders or unexpected SQL functions.
3. **Expensive joins and unbounded result sets**: Cartesian joins or queries returning excessive rows.
4. **Over-broad table and sensitive-column access**: Agents reading tables or columns outside the caller's role scope.

`mcp-secure-db` is an open-source **reference implementation and proof of concept** demonstrating how an MCP server can combine role checks, local JavaScript AST validation (requiring zero LLM API calls [E:CLAIM-003]), an isolated SQLite demo dataset, and an audit log, paired with an automated claims linter (`scripts/claims-lint.ts` [E:CLAIM-037]) that blocks unverified security or performance claims in documentation.

---

## 2. Current Layered Architecture (Baseline Proof of Concept)

```
┌────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: Role-Based Authorization                                     │
│  - Resolves caller role from token (public_viewer, analyst, admin)     │
│  - Enforces handler-level role checks on SQL execution and audit tools │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 2: Local JavaScript AST Validator (node-sql-parser)             │
│  - Validates SQL locally without calling an external LLM               │
│  - Blocks SQL comments, semicolon-chained statements, and top-level    │
│    non-SELECT statements in regression tests                           │
│  - Injects default LIMIT 100 and clamps top-level LIMIT to 1000        │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 3: In-Process WebAssembly SQLite Engine (sql.js)                │
│  - Runs against seeded in-memory demo tables with no filesystem or     │
│    network handles exposed to the WASM SQLite instance                 │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 4: In-Memory Recent-Events Buffer                               │
│  - Retains recent query executions and blocked requests in memory      │
│    (not durable across restarts)                                       │
└────────────────────────────────────────────────────────────────────────┘
```

> **Active Engineering Remediation Note:** Known baseline gaps in CTE/subquery AST traversal, default-deny authentication, worker-thread query deadlines, function allowlisting, and persistent audit logging are cataloged in `docs/FINDINGS.md` and `docs/CLAIMS.md`.

---

## 3. MCP Primitives Implemented

The server registers 6 MCP tools, 2 resources, and 2 prompts [E:CLAIM-008]:

### Tools

| Tool | Description | Role Required |
| :--- | :--- | :--- |
| `whoami` | Inspect active principal, role, scopes, and allowed tools | `public_viewer`, `analyst`, `admin` |
| `list_tables` | List accessible demo tables with row counts and visible columns | `public_viewer`, `analyst`, `admin` |
| `describe_table` | Inspect column metadata and PII flags for an authorized table | `public_viewer`, `analyst`, `admin` |
| `verify_query_safety` | Dry-run local JavaScript AST validation without executing the query | `public_viewer`, `analyst`, `admin` |
| `execute_analytical_sql` | Execute validated `SELECT` queries against the seeded SQLite dataset [E:CLAIM-010] | `analyst`, `admin` |
| `get_security_audit_log` | Inspect the in-memory recent-events audit buffer [E:CLAIM-010] | `admin` |

### Resources

* `schema://catalog`: JSON catalog of demo warehouse tables (`customers`, `api_usage`, `security_incidents`, `api_keys` [E:CLAIM-009]).
* `policy://security-rules`: Markdown summary of active server policy layers.

### Prompts

* `executive_analytics`: Guided prompt template for SaaS usage analysis.
* `red_team_security_audit`: Prompt template for testing query validation rules.

---

## 4. Quick Start and Verification

### Prerequisites
* Node.js `>= 22.0.0`
* `pnpm`

### Commands

```bash
# 1. Install dependencies from lockfile
pnpm install --frozen-lockfile

# 2. Run TypeScript type checks
pnpm run typecheck

# 3. Run Vitest suite and claims-lint
pnpm test

# 4. Build the server bundle
pnpm run build

# 5. Start local development server
pnpm run dev
```

---

## 5. Container Build

The repository includes a multi-stage `Dockerfile` running as non-root `appuser` (UID `1001`) on port `8000` [E:CLAIM-011]:

```bash
docker build -t mcp-secure-db .
docker run -p 8000:8000 mcp-secure-db
```

---

## 6. Limitations and Non-Goals

- **Does not prevent prompt injection:** SQL validation and read-only execution restrict what SQL operations an agent can run; they do not stop a prompt-injected agent from querying data its assigned role is permitted to read.
- **Baseline limitations documented in `docs/FINDINGS.md`:** Prior to Phase 2–4 hardening, column-name checks, denylist function checks, synchronous `sql.js` execution, fallback viewer access, and non-durable in-memory audit buffering have documented limitations (`CLAIM-017` through `CLAIM-021`, `CLAIM-027`).
- **Demo dataset scope:** Default execution runs against seeded in-memory SQLite data [E:CLAIM-009] and does not represent production telemetry against external data warehouses.
- **Not a formal proof:** Deterministic parser and engine checks reduce risk for tested patterns; they are not formal verification.
- **No regulatory compliance claim:** No claim of GDPR, HIPAA, SOC 2, or PCI compliance is made, and the recent-events buffer is not designed for regulatory compliance auditing.
- **Independent review pending:** All tests in this repository were authored alongside the implementation; independent human security review is recommended before any production use.

---

## 7. License

MIT
