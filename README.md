# mcp-secure-db (TypeScript)

> **Hardened reference implementation and proof of concept for layered SQL query guardrails over MCP**  
> Built with the `mcp-use` TypeScript SDK (`2.12.2` [E:CLAIM-001]), `node-sql-parser` (`5.4.0` [E:CLAIM-002]), and a worker-isolated `node:sqlite` sandbox [E:CLAIM-025] [E:CLAIM-026].

---

## 1. Overview and Scope

Exposing analytical databases to AI agents over the **Model Context Protocol (MCP)** introduces concrete security and operational risks:
1. **Mutating or administrative SQL**: Prompt-injected or malformed agent calls attempting `DROP`, `ALTER`, `DELETE`, `UPDATE`, `INSERT`, `PRAGMA`, or `ATTACH` [E:CLAIM-004].
2. **Non-allowlisted functions and extension loading**: Queries invoking `load_extension` or unexpected SQLite functions [E:CLAIM-018].
3. **Expensive joins and runaway recursive queries**: Unconstrained Cartesian joins or CPU-heavy recursive CTEs blocking the server process [E:CLAIM-019], [E:CLAIM-025].
4. **Over-broad table and sensitive-column access**: Agents reading restricted tables or sensitive columns via aliases, CTEs, subqueries, expressions, views, or wildcards [E:CLAIM-020].
5. **Prompt injection via database records (Lethal Trifecta)**: Downstream models following prompt injections stored in database text fields [E:CLAIM-046].

`mcp-secure-db` is an open-source **hardened reference implementation and proof of concept** demonstrating six layered controls for read-only analytical SQL over MCP, paired with an automated claims linter (`scripts/claims-lint.ts` [E:CLAIM-037]) and dependency pinning verifier (`scripts/verify-deps.ts` [E:CLAIM-038]).

---

## 2. Six-Layer Architecture

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
│  LAYER 4: Worker Thread Sandbox & Hard Deadline                        │
│  - Enforces strict execution deadline (default 5000ms, test 800ms)     │
│  - Hard worker termination via `worker.terminate()` on slow queries    │
│  - Automatic clean worker respawn after termination                    │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 5: Result-Level PII Policy & Untrusted Data Tagging             │
│  - Scans output columns and cell values for restricted PII patterns    │
│  - Annotates responses with `untrustedData: true` and safety notices   │
├────────────────────────────────────────────────────────────────────────┤
│  LAYER 6: Rate Limiting & Persistent Redacted Audit Logging            │
│  - Per-principal query rate limits and cumulative row egress budgets   │
│  - Dual-tier logging: in-memory ring buffer plus append-only redacted  │
│    JSONL file on disk (`data/audit.jsonl`)                             │
└────────────────────────────────────────────────────────────────────────┘
```

### Engine Trade-Off and Stability Caveat (`node:sqlite` vs `sql.js` vs `better-sqlite3`)

- **`sql.js` (previous engine):** Runs synchronously in WebAssembly on the calling thread and does not expose SQLite's `sqlite3_set_authorizer` or `SQLITE_DBCONFIG_DEFENSIVE` APIs in its standard JavaScript wrapper.
- **`better-sqlite3`:** Mature native addon, but requires native C++ prebuilts or `node-gyp` toolchains across platforms and Node ABI versions.
- **`node:sqlite` in `node:worker_threads` (selected):** Ships built into Node `>= 22.13.0` / Node `24` with zero native compilation steps and exposes `enableDefensive(true)`, `enableLoadExtension(false)`, and `setAuthorizer(...)` [E:CLAIM-026].
- **Stability caveat:** Node.js marks `node:sqlite` as an experimental / release-candidate API (`ExperimentalWarning`), and upstream issues note reentrancy hazards if `DatabaseSync` methods are invoked inside `setAuthorizer`. To mitigate this, the worker's `setAuthorizer` callback performs pure in-memory `Set` and counter checks with zero reentrant database calls [E:CLAIM-026].

---

## 3. Measured Performance Benchmarks

Pre-execution AST validation latencies were measured using `bench/validator.bench.ts` under Node v24.12.0 x64 (1,000 warm-up iterations + 10,000 timed iterations per query) [E:CLAIM-022]:

| Query Type | p50 Latency | p90 Latency | p95 Latency | p99 Latency | Throughput | Evidence Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Simple Projection** (`SELECT id, name, plan FROM customers`) | **0.334 ms** | 0.667 ms | 1.102 ms | 3.344 ms | 1668 ops/sec | [E:CLAIM-022] (`bench/results.json`) |
| **Relational Join** (`customers` JOIN `api_usage`) | **0.395 ms** | 0.832 ms | 1.030 ms | 1.904 ms | 1848 ops/sec | [E:CLAIM-022] (`bench/results.json`) |
| **Aggregate with Grouping** (`COUNT(*)`, `SUM()`, `GROUP BY`) | **0.725 ms** | 2.059 ms | 3.509 ms | 11.280 ms | 751 ops/sec | [E:CLAIM-022] (`bench/results.json`) |

Run the benchmark suite locally with:
```bash
pnpm run bench
```

---

## 4. Authentication and Role Model

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

## 5. Verification and Test Suite

The test suite includes 199 automated tests across 16 test files [E:CLAIM-048]:

- **Bypass Corpus (`tests/bypass-corpus/`)**: 32 structured adversarial vectors covering comment tricks, unicode, quoting, function I/O exploits, CTE mutations, and Cartesian joins [E:CLAIM-039].
- **Differential Testing (`tests/differential.test.ts`)**: 93 queries compared across AST validator and real SQLite authorizer to confirm zero security divergences [E:CLAIM-040].
- **Grammar & Mutation Fuzzing (`tests/fuzz.test.ts`)**: 300 queries generated by PRNG, validating engine safety invariants [E:CLAIM-041].
- **Self Red-Team Pass (`tests/red-team-self.test.ts`)**: 32 adversarial test cases verifying all fail closed [E:CLAIM-042].
- **Worker Timeout & Pragmas (`tests/sqlite-controls.test.ts`)**: Verifies hard worker-thread deadline termination on slow recursive CTEs [E:CLAIM-025].
- **Result PII Protection (`tests/pii-bypass.test.ts`)**: 25 tests proving fail-closed blocking across views, CTEs, subqueries, aliases, and cell values [E:CLAIM-020].
- **Company Schema & Live Gemini CLI (`tests/company-db.test.ts`)**: 15 tests verifying 5-table corporate SQLite seeding, PII guardrails (`ssn`, `salary_usd`, `personal_email`), and interactive Gemini CLI role/macro flows [E:CLAIM-051].
- **PostgreSQL Query Engine (`tests/postgres-adapter.test.ts`, `tests/integration/`)**: Validates connection pool lifecycle, `BEGIN READ ONLY` transactions, `SET LOCAL ROLE` (`mcp_viewer`, `mcp_analyst`, `mcp_admin`), `statement_timeout`, schema allowlists, and dialect parsing [E:CLAIM-043], [E:CLAIM-049], [E:CLAIM-050].
- **Rate Limiting & Audit (`tests/rate-limiter.test.ts`, `tests/audit.test.ts`)**: Tests per-principal rate limits, row budgets, and sensitive literal redaction [E:CLAIM-044], [E:CLAIM-045].
- **Claims Linter (`tests/claims-lint.test.ts`)**: Enforces claims-evidence mapping in CI [E:CLAIM-037].

### Quickstart Commands

```bash
# 1. Install pinned dependencies from lockfile
pnpm install --frozen-lockfile

# 2. Verify exact dependency pinning and npm advisories
pnpm run deps:verify
pnpm audit --audit-level=high

# 3. Run TypeScript type checks
pnpm run typecheck

# 4. Run test suite, claims linter, and dependency verification
pnpm test

# 5. Run reproducible validator latency benchmark
pnpm run bench

# 6. Seed custom company SQLite database and launch interactive Gemini CLI tester
pnpm run seed:company
pnpm run test:gemini

# 7. Build the server bundle
pnpm run build

# 8. (Optional) Run live PostgreSQL integration tests (requires Docker or local Postgres)
pnpm run pg:up
pnpm run test:integration
pnpm run pg:down
```

---

## 6. Limitations and Non-Goals

- **Does not stop downstream prompt injection:** The validator, SQLite authorizer, and worker sandbox limit what SQL operations an injected instruction can execute; they do **not** stop a prompt-injected agent from reading data its authenticated role is permitted to access. Response data is tagged with `untrustedData: true` to assist calling models [E:CLAIM-046].
- **Inference and aggregation on permitted columns:** Statistical or multi-query inference over non-PII columns that a role is allowed to query remains possible.
- **`node:sqlite` experimental status:** Built-in `node:sqlite` emits an `ExperimentalWarning` in Node.js and may evolve across Node releases.
- **Demo dataset scope:** Default execution runs against 4 seeded in-memory SQLite tables [E:CLAIM-009] and is not evidence of production behavior against external cloud data warehouses.
- **In-memory audit buffer durability:** The 100-entry ring buffer is an in-memory debugging cache and is not durable across process restarts [E:CLAIM-027]. A persistent append-only log is written to `data/audit.jsonl` [E:CLAIM-045].
- **PostgreSQL cluster configuration**: The PostgreSQL engine (`src/database/postgres-adapter.ts` [E:CLAIM-043]) requires appropriate least-privilege roles (`mcp_viewer`, `mcp_analyst`, `mcp_admin`, `mcp_gateway`) and column grants provisioned on target databases (see `docker/postgres/init/02-roles.sql`).
- **Not a formal security proof:** Parser, authorizer, and result-level checks reduce risk for tested patterns; they do not constitute a formal proof of security.
- **No regulatory compliance claim:** No claim of GDPR, HIPAA, SOC 2, or PCI compliance is made, and this software is out of scope for regulatory compliance certification.
- **Independent review recommendation:** All tests in this repository were written alongside the code; independent human security review is recommended before any production deployment.

---

## 7. Documentation Index

- `docs/THREAT_MODEL.md`: Lethal-trifecta analysis, layer boundaries, and OWASP MCP / LLM Top 10 coverage matrix [E:CLAIM-047].
- `docs/TECHNICAL_REPORT.md`: Comprehensive engineering report and forensic audit findings.
- `docs/CONTRIBUTION_BRIEF.md`: Partner brief and upstream contribution proposals for Manufact / `mcp-use`.
- `docs/CLAIMS.md`: Complete claims ledger mapping every claim to verified evidence.
- `docs/FINDINGS.md`: Register of all 15 audit findings with root cause and remediation status.
- `docs/OPEN_QUESTIONS.md`: Register of unverified external facts and future research items.

---

## 8. License

MIT
