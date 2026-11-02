# mcp-secure-db (TypeScript)

> **Reference implementation and proof of concept for layered SQL query guardrails over MCP**  
> Built with the `mcp-use` TypeScript SDK (`2.12.2` [E:CLAIM-001]), `node-sql-parser` (`5.4.0` [E:CLAIM-002]), and a worker-isolated `node:sqlite` sandbox [E:CLAIM-025] [E:CLAIM-026].

---

## 1. Overview and Scope

Exposing analytical databases to AI agents over the **Model Context Protocol (MCP)** introduces concrete security and operational risks:
1. **Mutating or administrative SQL**: Prompt-injected or malformed agent calls attempting `DROP`, `ALTER`, `DELETE`, `UPDATE`, `INSERT`, `PRAGMA`, or `ATTACH`.
2. **Non-allowlisted functions and extension loading**: Queries invoking `load_extension` or unexpected SQLite functions.
3. **Expensive joins and runaway recursive queries**: Unconstrained Cartesian joins or CPU-heavy recursive CTEs blocking the server process.
4. **Over-broad table and sensitive-column access**: Agents reading restricted tables or sensitive columns via aliases, CTEs, subqueries, expressions, views, or wildcards.

`mcp-secure-db` is an open-source **reference implementation and proof of concept** demonstrating layered controls for read-only analytical SQL over MCP, paired with an automated claims linter (`scripts/claims-lint.ts` [E:CLAIM-037]) and dependency pinning verifier (`scripts/verify-deps.ts` [E:CLAIM-038]).

---

## 2. Four-Layer Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│  LAYER 1: Default-Deny RBAC & MCP Wire Middleware                      │
│  - Default-deny: missing or invalid credentials get only `whoami`      │
│  - `mcp:tools/list` hides unauthorized tools per caller role           │
│  - `mcp:tools/call` and `schema://catalog` enforce role permissions    │
│  - Resolves verified `mcp-use` OAuth scopes before static demo tokens  │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 2: Local JavaScript AST Validator (node-sql-parser, SQLite)     │
│  - Validates SQL locally without calling an external LLM               │
│  - Recursive traversal of WITH CTEs, subqueries, and UNION branches    │
│  - Explicit SQLite function and per-role table allowlists              │
│  - Blocks implicit comma joins, CROSS/NATURAL JOIN, and ON tautologies │
│  - Clamps/injects terminal LIMIT (default 100, maximum 1000)           │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 3: Worker-Isolated SQLite Sandbox (node:worker_threads)         │
│  - Runs `node:sqlite` inside an OS worker thread terminated on timeout │
│  - Enables defensive mode, disables extension loading, sets query_only │
│  - Enforces V8 worker heap limits and SQLite max_page_count cap        │
│  - Compile-time `setAuthorizer` independently checks actions, tables,  │
│    base columns (including through SQL views), and allowlisted funcs   │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 4: Fail-Closed Result Policy & Recent-Events Audit Buffer       │
│  - Scans output columns and cell values for restricted PII patterns    │
│  - Records allowed and blocked calls in an in-memory buffer            │
│    (explicitly non-durable across restarts)                            │
└────────────────────────────────────────────────────────────────────────┘
```

### Engine Trade-Off and Stability Caveat (`node:sqlite` vs `sql.js` vs `better-sqlite3`)

- **`sql.js` (previous engine):** Runs synchronously in WebAssembly on the calling thread and does not expose SQLite's `sqlite3_set_authorizer` or `SQLITE_DBCONFIG_DEFENSIVE` APIs in its standard JavaScript wrapper.
- **`better-sqlite3`:** Mature native addon, but requires native C++ prebuilts or `node-gyp` toolchains across platforms and Node ABI versions.
- **`node:sqlite` in `node:worker_threads` (selected):** Ships built into Node `>= 22.13.0` / Node `24` with zero native compilation steps and exposes `enableDefensive(true)`, `enableLoadExtension(false)`, and `setAuthorizer(...)` [E:CLAIM-026].
- **Stability caveat:** Node.js marks `node:sqlite` as an experimental / release-candidate API (`ExperimentalWarning`), and upstream issues note reentrancy hazards if `DatabaseSync` methods are invoked inside `setAuthorizer`. To mitigate this, the worker's `setAuthorizer` callback performs pure in-memory `Set` and counter checks with zero reentrant database calls [E:CLAIM-026].

---

## 3. Authentication and Role Model

Authentication enforces **default-deny** [E:CLAIM-017]:
- Verified OAuth access tokens (`ctx.auth` in `mcp-use` `2.12.2` [E:CLAIM-013]) are checked first (`db:read:metadata`, `db:execute:analytics`, `db:audit:read`, `db:pii:access`).
- For standalone local testing without an external OAuth identity provider, static Bearer tokens (`Authorization: Bearer <token>`) are supported:

| Credentials | Resolved Role | Allowed Tools |
| :--- | :--- | :--- |
| *(Missing or Invalid)* | `unauthenticated` | `whoami` only (all data/catalog calls denied and logged) [E:CLAIM-017] |
| `token-viewer-demo` | `public_viewer` | `whoami`, `list_tables`, `describe_table`, `verify_query_safety` |
| `token-analyst-demo` | `analyst` | Viewer tools + `execute_analytical_sql` (non-admin tables, PII blocked) [E:CLAIM-010] |
| `token-admin-demo` | `admin` | All 6 tools including `get_security_audit_log` and admin tables [E:CLAIM-008] [E:CLAIM-010] |

> **Insecure Demo Flag Warning:** Setting `MCP_SECURE_DB_INSECURE_DEMO=true` allows requests *without* credentials to fall back to `public_viewer` for local inspector demos [E:CLAIM-017]. This flag weakens default-deny metadata protection and must **never** be enabled in shared or untrusted environments. Invalid tokens still fail closed even when this flag is set [E:CLAIM-017].

---

## 4. Quick Start and Verification

### Prerequisites
* Node.js `>= 22.13.0` (Node `24` recommended and used in CI/Docker [E:CLAIM-011])
* `pnpm`

### Commands

```bash
# 1. Install pinned dependencies from lockfile
pnpm install --frozen-lockfile

# 2. Verify exact dependency pinning and npm advisories
pnpm run deps:verify
pnpm audit --audit-level=high

# 3. Run TypeScript type checks
pnpm run typecheck

# 4. Run Vitest suite, claims-lint, and verify-deps
pnpm test

# 5. Build the server bundle
pnpm run build
```

---

## 5. Limitations and Non-Goals

- **Does not prevent prompt injection:** The validator, SQLite authorizer, and worker sandbox limit what SQL operations an injected instruction can execute; they do **not** stop a prompt-injected agent from reading data its authenticated role is permitted to access.
- **Inference and aggregation on permitted columns:** Statistical or multi-query inference over non-PII columns that a role is allowed to query remains possible.
- **`node:sqlite` experimental status:** Built-in `node:sqlite` emits an `ExperimentalWarning` in Node.js and may evolve across Node releases.
- **Demo dataset scope:** Default execution runs against 4 seeded in-memory SQLite tables [E:CLAIM-009] and is not evidence of production behavior against external cloud data warehouses.
- **In-memory audit buffer durability:** The 100-entry ring buffer is an in-memory debugging cache and is not durable across process restarts [E:CLAIM-027].
- **Not a formal proof:** Parser, authorizer, and result-level checks reduce risk for tested patterns; they do not constitute formal verification.
- **No regulatory compliance claim:** No claim of GDPR, HIPAA, SOC 2, or PCI compliance is made, and this software is out of scope for regulatory compliance certification.
- **Independent review pending:** All tests in this repository were written alongside the code; independent human security review is recommended before any production deployment.

---

## 6. License

MIT
