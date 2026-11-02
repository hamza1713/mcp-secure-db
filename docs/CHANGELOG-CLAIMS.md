# Claims Changelog

Tracks every claim added, softened, removed, or newly supported across remediation phases.

## Phase 0 — Baseline and Ledger

### Added to Ledger (`docs/CLAIMS.md`)
- Cataloged baseline claims `CLAIM-001` through `CLAIM-036` across `README.md`, `Dockerfile`, `package.json`, `docs/`, and `src/`.
- Baseline regression suite verified via `pnpm test` [E:CLAIM-014].
- Verified installed dependency versions from `pnpm-lock.yaml` [E:CLAIM-001] [E:CLAIM-002] and OAuth type exports in `mcp-use` [E:CLAIM-013].

### Identified as Unsupported, Partial, or Unverified (Queued for Phase 1–5 Remediation)
- Marked `CLAIM-015`, `CLAIM-016`, `CLAIM-022` through `CLAIM-026`, `CLAIM-028`, `CLAIM-029`, `CLAIM-031`, `CLAIM-032`, `CLAIM-034`, `CLAIM-036` as `UNSUPPORTED`.
- Marked `CLAIM-017` through `CLAIM-021` and `CLAIM-027` as `PARTIAL`.
- Marked `CLAIM-030`, `CLAIM-033`, `CLAIM-035` as `UNVERIFIED` and logged in `docs/OPEN_QUESTIONS.md`.
- Logged concrete code-level bypasses and missing controls `FINDING-001` through `FINDING-014` in `docs/FINDINGS.md`.

## Phase 1 — Claims Linter and Baseline Prose Cleanup

### Added and Newly Supported
- `CLAIM-037` (`SUPPORTED`): Added `scripts/claims-lint.ts`, unit tests in `tests/claims-lint.test.ts`, `pnpm test` enforcement, and `.github/workflows/ci.yml`.

### Softened or Corrected (Before -> After)
- `src/index.ts` (`FINDING-005` / `CLAIM-023`):
  - Before: `"0 Tokens (Deterministic AST C++ Evaluation)"`
  - After: `"0 Tokens (Local JavaScript AST Validation)"`
- `src/index.ts` and `README.md` (`CLAIM-024`):
  - Before: `"In-Memory Kernel Sandbox ... hardware watchdog timeouts"`
  - After: `"In-Process WebAssembly SQLite Engine (sql.js) ... no filesystem or network handles"`
- `README.md` (`CLAIM-027`):
  - Before: `"In-memory thread-safe ring buffer recording all queries and blocks"`
  - After: `"In-Memory Recent-Events Buffer ... retains recent query executions and blocked requests in memory (not durable across restarts)"`
- `Dockerfile` and `README.md` (`CLAIM-030`):
  - Before: `"Fully compliant with Manufact Cloud (Dockpack) runtime standards"`
  - After: `"Builds with Node 22 and runs as non-root user appuser (UID 1001)"`

### Removed
- Removed obsolete Python/DuckDB prototype reports (`docs/COMPREHENSIVE_FOUNDER_REPORT.md` and `docs/PROJECT_CONTEXT_REPORT.md`), closing stale text for `CLAIM-031`, `CLAIM-034`, and `CLAIM-036`.
- Removed unmeasured latency claim (`CLAIM-022`) from `README.md` pending Phase 3 benchmark measurement.
- Removed absolute `"mitigates all four threat vectors"` wording (`CLAIM-028`) from `README.md` and added explicit `Limitations and Non-Goals`.

### Still Open (Queued for Phase 2–4)
- `CLAIM-015` through `CLAIM-021`, `CLAIM-025`, `CLAIM-026`, `CLAIM-027` (`FINDING-001`..`FINDING-004`, `FINDING-006`..`FINDING-014`).

## Phase 2 — P0 Engineering Fixes (Making Core Claims True)

### Newly Supported Claims (`docs/CLAIMS.md`)
- `CLAIM-015` (`SUPPORTED`): Registered `server.use("mcp:tools/list", ...)` and `server.use("mcp:tools/call", ...)` on `MCPServer`; verified over JSON-RPC wire calls in `tests/server.test.ts` (`FINDING-001` fixed).
- `CLAIM-016` (`SUPPORTED`): Enforced default-deny authentication and role-based table/PII filtering on `schema://catalog` (`FINDING-002` fixed).
- `CLAIM-017` (`SUPPORTED`): Switched `RBACManager` to default-deny (`unauthenticated` role receives only `whoami`), added verified `mcp-use` OAuth scope resolution (`CLAIM-013`), and documented `MCP_SECURE_DB_INSECURE_DEMO=true` as insecure (`FINDING-013` fixed).
- `CLAIM-018` (`SUPPORTED`): Replaced DuckDB-era function denylist with explicit SQLite function and per-role table allowlists enforced in both `SQLValidator` and SQLite `setAuthorizer` (`FINDING-012`, `FINDING-014` fixed).
- `CLAIM-019` (`SUPPORTED`): Added implicit comma-join, `NATURAL JOIN`, and constant/`OR`-branch `ON` tautology rejection (`FINDING-011` fixed).
- `CLAIM-020` (`SUPPORTED`): Implemented three-layer fail-closed PII protection across recursive AST traversal (CTEs, subqueries, unions, expressions, predicates), SQLite `setAuthorizer` `SQLITE_READ` checks (including SQL views), and `enforceResultPolicy` value/pattern scanning (`FINDING-006`..`FINDING-010` fixed).
- `CLAIM-021`, `CLAIM-025`, `CLAIM-026` (`SUPPORTED`): Moved SQLite execution to `node:sqlite` inside `node:worker_threads` with hard `worker.terminate()` deadline recovery, V8 `resourceLimits`, `enableDefensive(true)`, `enableLoadExtension(false)`, `PRAGMA query_only = ON`, `PRAGMA trusted_schema = OFF`, `PRAGMA cell_size_check = ON`, `PRAGMA max_page_count = 4096`, and `maxAuthorizerOps` (`FINDING-003`, `FINDING-004` fixed).
- `CLAIM-027` (`SUPPORTED`): Explicitly labeled the 100-entry in-memory ring buffer as non-durable in code responses and docs.
- `CLAIM-038` (`SUPPORTED`): Pinned all dependencies to exact semver versions, removed unused `sql.js`, upgraded `vitest` to `5.0.5` to remediate transitive `tinypool`/`@vitest/mocker` advisories (`FINDING-015` fixed), and added `scripts/verify-deps.ts` + `pnpm audit` to CI.

### Honest Caveats Added
- Documented `node:sqlite` `ExperimentalWarning` and non-reentrant `setAuthorizer` design in `README.md` and `src/database/sqlite-worker-code.ts`.

## Phase 3 — Evidence (Differential Testing, Fuzzing, Bypass Corpus, Benchmark, Red-Team)

### Newly Supported Claims (`docs/CLAIMS.md`)
- `CLAIM-022` (`SUPPORTED`) [E:CLAIM-022]: Measured validator latency via reproducible benchmark suite in `bench/validator.bench.ts` (1,000 warmup iterations + 10,000 timed iterations per query on Node v24.12.0 x64); measured p50 of 0.334 ms (p95 1.102 ms, p99 3.344 ms) on simple projections and p50 of 0.395 ms (p95 1.030 ms, p99 1.904 ms) on joins (`bench/results.json`).
- `CLAIM-039` (`SUPPORTED`) [E:CLAIM-039]: Public bypass corpus at `tests/bypass-corpus/` with 32 structured attack vectors verified in `tests/bypass-corpus.test.ts`.
- `CLAIM-040` (`SUPPORTED`) [E:CLAIM-040]: Differential test harness in `tests/differential.test.ts` executing 93 queries across `SQLValidator` and real SQLite (`node:sqlite` with authorizer), proving zero security divergences.
- `CLAIM-041` (`SUPPORTED`) [E:CLAIM-041]: Seeded deterministic PRNG grammar and mutation fuzzer in `tests/fuzz.test.ts` executing 300 queries, asserting that every validator-allowed query executes safely in real SQLite.
- `CLAIM-042` (`SUPPORTED`) [E:CLAIM-042]: Dedicated self red-team pass in `tests/red-team-self.test.ts` evaluating 32 distinct adversarial attack vectors against all security layers, verifying all 32 fail closed.

## Phase 4 — Defense in Depth and Containment

### Newly Supported Claims (`docs/CLAIMS.md`)
- `CLAIM-043` (`SUPPORTED`) [E:CLAIM-043]: Added experimental PostgreSQL adapter in `src/database/postgres-adapter.ts` with read-only transaction parameters, `statement_timeout`, and schema/table allowlists, verified in `tests/postgres-adapter.test.ts`.
- `CLAIM-044` (`SUPPORTED`) [E:CLAIM-044]: Added per-principal sliding-window rate limiter and row-budget accounting in `src/security/rate-limiter.ts`, verified in `tests/rate-limiter.test.ts`.
- `CLAIM-045` (`SUPPORTED`) [E:CLAIM-045]: Implemented persistent append-only JSONL logging to `data/audit.jsonl` with sensitive literal scrubbing (emails, tokens, IPs) alongside an in-memory cache, verified in `tests/audit.test.ts`.
- `CLAIM-046` (`SUPPORTED`) [E:CLAIM-046]: Added explicit `untrustedData: true` and prompt safety notices to database query result sets to mitigate prompt injection risk, verified in `tests/server.test.ts`.
- `CLAIM-047` (`SUPPORTED`) [E:CLAIM-047]: Published comprehensive threat model in `docs/THREAT_MODEL.md` documenting the lethal-trifecta exposure, layer boundaries, and OWASP MCP / LLM Top 10 coverage.
