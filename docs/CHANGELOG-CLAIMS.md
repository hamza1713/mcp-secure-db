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
