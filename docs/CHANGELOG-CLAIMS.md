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
