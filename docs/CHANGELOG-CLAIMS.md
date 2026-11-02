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
