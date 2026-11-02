# Claims Ledger

Baseline recorded during Phase 0 prior to engineering remediation.
Every factual, security, performance, maturity, or external claim across `README.md`, `Dockerfile`, `package.json`, `docs/`, and `src/` is cataloged below and mapped to an honest status (`SUPPORTED`, `PARTIAL`, `UNSUPPORTED`, or `UNVERIFIED`).

## Baseline Test Run (Phase 0 Snapshot)

Executed command: `pnpm test` (`vitest run`) [E:CLAIM-014]
- `tests/validator.test.ts`: 24 passed [E:CLAIM-014]
- `tests/engine.test.ts`: 4 passed [E:CLAIM-014]
- `tests/server.test.ts`: 16 passed [E:CLAIM-014]
- `tests/rbac.test.ts`: 5 passed [E:CLAIM-014]
- Total at Phase 0 snapshot: 4 test files, 49 tests passed (regression coverage written by the project author, not independent security validation) [E:CLAIM-014].

## Ledger Table

| ID | Claim Text | Location | Evidence Type | Evidence Reference | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| CLAIM-001 | Server is built with the `mcp-use` TypeScript SDK version 2.12.2 | `package.json`, `pnpm-lock.yaml` | LOCKFILE | `pnpm-lock.yaml` | SUPPORTED |
| CLAIM-002 | Project uses TypeScript 5.9.3, `node-sql-parser` 5.4.0, `sql.js` 1.15.2, `zod` 4.6.7, and `vitest` 3.2.7 | `pnpm-lock.yaml` | LOCKFILE | `pnpm-lock.yaml` | SUPPORTED |
| CLAIM-003 | Validator runs locally in TypeScript without making an LLM API call (0 LLM tokens used by the validator itself) | `src/security/validator.ts` | TEST | `tests/validator.test.ts` | SUPPORTED |
| CLAIM-004 | Lexical scanner blocks `--` and `/*` SQL comments outside string literals while allowing `--` inside single-quoted literals in tested cases | `src/security/validator.ts` | TEST | `tests/validator.test.ts` | SUPPORTED |
| CLAIM-005 | Lexical scanner blocks semicolon-chained multi-statement strings outside quotes while allowing `;` inside single-quoted literals in tested cases | `src/security/validator.ts` | TEST | `tests/validator.test.ts` | SUPPORTED |
| CLAIM-006 | AST check rejects top-level `DROP`, `DELETE`, `UPDATE`, `INSERT`, and `ALTER` statements in regression tests | `src/security/validator.ts` | TEST | `tests/validator.test.ts` | SUPPORTED |
| CLAIM-007 | Validator injects default `LIMIT 100` when omitted and clamps top-level `LIMIT` values above `1000` down to `1000` | `src/security/validator.ts` | TEST | `tests/validator.test.ts` | SUPPORTED |
| CLAIM-008 | Server registers 6 MCP tools (`whoami`, `list_tables`, `describe_table`, `verify_query_safety`, `execute_analytical_sql`, `get_security_audit_log`), 2 resources (`schema://catalog`, `policy://security-rules`), and 2 prompts (`executive_analytics`, `red_team_security_audit`) | `src/index.ts` | TEST | `tests/server.test.ts` | SUPPORTED |
| CLAIM-009 | Seeded demo database initializes 4 tables (`customers` with 5 rows, `api_usage` with 10 rows, `security_incidents` with 3 rows, `api_keys` with 4 rows) | `src/database/seed.ts` | TEST | `tests/engine.test.ts` | SUPPORTED |
| CLAIM-010 | Direct calls to `execute_analytical_sql` reject `public_viewer` and direct calls to `get_security_audit_log` reject `public_viewer` and `analyst` | `src/index.ts` | TEST | `tests/server.test.ts` | SUPPORTED |
| CLAIM-011 | `Dockerfile` uses a multi-stage `node:22-slim` build and runs as non-root user `appuser` (UID 1001) on port 8000 | `Dockerfile` | CODE | `Dockerfile` | SUPPORTED |
| CLAIM-012 | Manufact was co-founded by Pietro Zullo and Luigi Pederzani, listed by Y Combinator in batch S25, with press reporting a February 2026 seed round led by Peak XV and CTO Enrico Toniato | `docs/mcp-secure-db-audit-and-remediation-report.md` | CITATION | `docs/mcp-secure-db-audit-and-remediation-report.md` | SUPPORTED |
| CLAIM-013 | Installed `mcp-use` package exports OAuth context types (`OAuthAuth`, `OAuthMode`, `OAuthUpstreamToken`) | `node_modules/mcp-use/dist/index.d.ts` | LOCKFILE | `pnpm-lock.yaml` | SUPPORTED |
| CLAIM-014 | Baseline Vitest regression suite executes 49 tests across 4 test files | `README.md`, `tests/` | TEST | `tests/validator.test.ts` | SUPPORTED |
| CLAIM-015 | Layer 1 RBAC middleware dynamically hides unauthorized tools on `tools/list` requests | `README.md`, `src/index.ts` | NONE | `src/index.ts` | UNSUPPORTED |
| CLAIM-016 | Resource `schema://catalog` enforces role-based table and PII masking | `README.md`, `src/index.ts` | NONE | `src/index.ts` | UNSUPPORTED |
| CLAIM-017 | Unauthenticated or unrecognized tokens safely fall back to `public_viewer` with metadata access by default | `README.md`, `src/security/rbac.ts` | TEST | `tests/rbac.test.ts` | PARTIAL |
| CLAIM-018 | Validator blocks SSRF and filesystem exfiltration via a denylist of `read_csv`, `read_csv_auto`, `read_parquet`, `parquet_scan`, `st_read`, `glob`, `load_extension`, `eval`, `sleep`, `repeat` | `README.md`, `src/security/validator.ts` | TEST | `tests/validator.test.ts` | PARTIAL |
| CLAIM-019 | Validator rejects Cartesian joins and tautological join conditions | `README.md`, `src/security/validator.ts` | TEST | `tests/validator.test.ts` | PARTIAL |
| CLAIM-020 | Validator enforces table and column-level PII protection for non-admin roles (`billing_email`, `stripe_customer_id`, `webhook_secret`, `client_ip`) | `README.md`, `src/security/validator.ts` | TEST | `tests/validator.test.ts` | PARTIAL |
| CLAIM-021 | `LIMIT` clamping prevents compute exhaustion, memory crashes, and cloud bill shock | `README.md`, `docs/` | NONE | `src/security/validator.ts` | PARTIAL |
| CLAIM-022 | Pre-execution AST validation runs in under 1 millisecond | `README.md`, `docs/` | NONE | `NONE` | UNSUPPORTED |
| CLAIM-023 | Validator performs deterministic AST C++ evaluation / runs at C++ AST speeds | `src/index.ts`, `docs/` | NONE | `NONE` | UNSUPPORTED |
| CLAIM-024 | Database runs in an in-memory kernel sandbox / hardware isolation with hardware watchdog timeouts | `README.md`, `src/index.ts`, `docs/` | NONE | `NONE` | UNSUPPORTED |
| CLAIM-025 | Engine enforces a 10-second hard execution timeout / watchdog | `README.md`, `src/database/engine.ts` | NONE | `src/database/engine.ts` | UNSUPPORTED |
| CLAIM-026 | Engine enforces a 512MB memory boundary | `README.md`, `src/database/engine.ts` | NONE | `src/database/engine.ts` | UNSUPPORTED |
| CLAIM-027 | Audit logger is a thread-safe ring buffer suitable for security auditing | `README.md`, `src/database/audit.ts` | TEST | `tests/engine.test.ts` | PARTIAL |
| CLAIM-028 | System mitigates all four threat vectors (prompt injection DDL/DML, SSRF, DoS, PII exfiltration) | `README.md` | NONE | `NONE` | UNSUPPORTED |
| CLAIM-029 | System provides mathematical, deterministic security guarantees | `docs/` | NONE | `NONE` | UNSUPPORTED |
| CLAIM-030 | Repository and Dockerfile are compliant with Manufact Cloud (Dockpack) standards | `README.md`, `Dockerfile`, `docs/` | NONE | `NONE` | UNVERIFIED |
| CLAIM-031 | Project is production ready / enterprise-grade | `docs/PROJECT_CONTEXT_REPORT.md`, `docs/COMPREHENSIVE_FOUNDER_REPORT.md` | NONE | `NONE` | UNSUPPORTED |
| CLAIM-032 | System addresses GDPR, HIPAA, or SOC 2 compliance barriers | `docs/` | NONE | `NONE` | UNSUPPORTED |
| CLAIM-033 | Enterprise CISOs are actively blocking AI database integrations | `docs/` | NONE | `NONE` | UNVERIFIED |
| CLAIM-034 | Manufact founders are YC W24/S24 alumni | `docs/` | CITATION | `docs/mcp-secure-db-audit-and-remediation-report.md` | UNSUPPORTED |
| CLAIM-035 | Upstream maintainer bot auto-closed a Python PR stating focus is on the TypeScript SDK | `docs/` | NONE | `NONE` | UNVERIFIED |
| CLAIM-036 | Legacy Python/DuckDB claims (`server.py`, `sqlglot`, DuckDB `conn.interrupt()`, 96 pytest tests) describe the current repository | `docs/PROJECT_CONTEXT_REPORT.md`, `docs/COMPREHENSIVE_FOUNDER_REPORT.md` | NONE | `NONE` | UNSUPPORTED |
