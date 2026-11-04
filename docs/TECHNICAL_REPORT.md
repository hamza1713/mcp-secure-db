# Technical Remediation and Credibility Audit Report: mcp-secure-db

> **Maturity Status**: Hardened reference implementation and proof of concept  
> **Framework**: `mcp-use` TypeScript SDK (`2.12.2` [E:CLAIM-001])  
> **Database Sandbox**: Worker-isolated `node:sqlite` (`Node >= 22.13.0` / Node `24` [E:CLAIM-011], [E:CLAIM-025], [E:CLAIM-026]) and PostgreSQL connection pool (`pg.Pool` [E:CLAIM-043])  
> **Test Coverage**: 184 automated tests across 15 test suites [E:CLAIM-048]

---

## 1. Executive Summary and Audit Context

This document details the complete forensic audit and engineering remediation of `mcp-secure-db`.

### 1.1 Remediation Mandate

Earlier iterations of the project contained severe discrepancies between documentation and engineering reality:
1. **Unsubstantiated Claims**: Claims of formal security proofs, impenetrable defense, hardware-level isolation, and regulatory certifications existed without supporting code or evidence.
2. **Obsolete Python/DuckDB Artifacts**: Documentation referenced DuckDB functions (`read_csv`, `read_parquet`) and pytest suites despite migrating to TypeScript and SQLite.
3. **Engine-Level Vulnerabilities**: The previous `sql.js` WebAssembly engine ran synchronously on the main thread, making timeout enforcement ineffective against runaway queries, and lacked compile-time authorizer support.
4. **Bypassable Security Filters**: AST validation alone was susceptible to aliasing, view bypasses, CTE mutations, and tautological joins.

### 1.2 Remediated Architecture

The repository has been restructured into a hardened reference implementation featuring:
- **Six Layered Defensive Boundaries**: Wire-level RBAC tool masking [E:CLAIM-006], recursive AST SQL validation [E:CLAIM-004], compile-time SQLite authorizers and pragmas [E:CLAIM-026], worker-thread execution with hard `worker.terminate()` deadline recovery [E:CLAIM-025], result-level PII scanning and untrusted data tagging [E:CLAIM-020], [E:CLAIM-046], and sliding-window rate limiting with persistent redacted audit logging [E:CLAIM-044], [E:CLAIM-045].
- **Automated Claims Enforcement**: A custom claims linter (`scripts/claims-lint.ts` [E:CLAIM-037]) runs in `pnpm test` and CI, requiring all claims to be tagged with evidence references resolving to `docs/CLAIMS.md`.
- **Reproducible Evidence**: 32 bypass corpus vectors [E:CLAIM-039], 93 differential queries [E:CLAIM-040], a 300-query fuzzer [E:CLAIM-041], a 32-vector red-team suite [E:CLAIM-042], and a reproducible benchmark suite [E:CLAIM-022].

---

## 2. Forensic Audit Findings Register

The audit identified 19 distinct vulnerabilities and architectural findings:

| Finding ID | Severity | Category | Description | Remediation Architecture & Evidence |
| :--- | :--- | :--- | :--- | :--- |
| **FINDING-001** | High | Integrity | Unbacked regulatory certification claims | Removed all regulatory certification claims; added explicit non-claims in Limitations sections. Enforced by automated linter [E:CLAIM-037]. |
| **FINDING-002** | High | Integrity | Inaccurate sandboxing and parser terminology | Replaced with accurate technical descriptions ("worker thread", "JavaScript AST"). Enforced by automated linter [E:CLAIM-037]. |
| **FINDING-003** | Critical | Sandbox | Ineffective query timeouts under synchronous `sql.js` WebAssembly execution | Migrated to `node:sqlite` inside `node:worker_threads`; enforced hard deadline via `worker.terminate()` [E:CLAIM-025]. |
| **FINDING-004** | High | Database | Missing SQLite engine-level hardening controls | Enabled `enableDefensive(true)`, `enableLoadExtension(false)`, `query_only = ON`, `trusted_schema = OFF`, `max_page_count = 4096`, and synchronous `setAuthorizer` [E:CLAIM-026]. |
| **FINDING-005** | Medium | Audit | Audit log was non-durable in-memory buffer while docs implied persistence | Labeled ring buffer as non-durable cache [E:CLAIM-027]; implemented persistent append-only JSONL log (`data/audit.jsonl`) [E:CLAIM-045]. |
| **FINDING-006** | Critical | Data Leak | PII filter bypass via SQL column aliases (`SELECT billing_email AS contact`) | AST validator recursively inspects underlying column expressions; authorizer independently blocks restricted base columns [E:CLAIM-020]. |
| **FINDING-007** | Critical | Data Leak | PII filter bypass via Common Table Expressions (`WITH cte AS (...) SELECT email FROM cte`) | AST validator tracks and recurses through all CTE definitions and body expressions [E:CLAIM-020]. |
| **FINDING-008** | Critical | Data Leak | PII filter bypass via subqueries (`SELECT * FROM (SELECT billing_email FROM customers)`) | AST validator recurses into derived tables; authorizer checks base column accesses [E:CLAIM-020]. |
| **FINDING-009** | Critical | Data Leak | PII filter bypass via SQL Views | Created views querying restricted columns are blocked by SQLite `setAuthorizer` at compile time [E:CLAIM-020]. |
| **FINDING-010** | High | Data Leak | PII filter bypass via `SELECT *` wildcard projection | Wildcards rejected for non-admin roles on sensitive tables in AST; result-level scanner enforces fail-closed checks [E:CLAIM-020]. |
| **FINDING-011** | High | Denial of Service | Expensive Cartesian joins via comma joins, CROSS JOIN, NATURAL JOIN, and ON tautologies | AST validator rejects implicit comma joins, CROSS/NATURAL joins, and constant/`OR`-branch `ON` conditions [E:CLAIM-019]. |
| **FINDING-012** | Medium | Defense | Denylist of functions inherited DuckDB names (`read_csv`, `read_parquet`) | Converted to explicit SQLite function allowlist (`ALLOWED_FUNCTIONS`) enforced at both AST and authorizer layers [E:CLAIM-018]. |
| **FINDING-013** | High | Access Control | Permissive fallback allowed unauthenticated tool calls | Enforced default-deny authentication; `unauthenticated` role receives only `whoami` [E:CLAIM-017]. Insecure demo flag documented [E:CLAIM-017]. |
| **FINDING-014** | Medium | Policy | Per-role table access rules were incomplete | Implemented strict per-role table allowlists (`ROLE_ALLOWED_TABLES`) enforced at AST, authorizer, and catalog resource [E:CLAIM-018]. |
| **FINDING-015** | High | Supply Chain | Transitive dependency vulnerabilities in `vitest@3.2.7` (`tinypool` prototype pollution) | Pinned `vitest@5.0.5`, pinned all dependencies to exact semver, and added `scripts/verify-deps.ts` and `pnpm audit` [E:CLAIM-038]. |
| **FINDING-016** | High | Database | Simulated execution on experimental Postgres adapter | Replaced simulated formatting with real `pg.Pool` connection pool, `BEGIN READ ONLY` transactions, and session resets [E:CLAIM-043]. |
| **FINDING-017** | Medium | Database | Unrestricted `search_path` on Postgres connection | Added `SET LOCAL search_path = public, pg_temp` to prevent schema search-path spoofing [E:CLAIM-043]. |
| **FINDING-018** | High | Validator | Single-dialect SQLite parser rejected Postgres syntax | Extended `SQLValidator` to support PostgreSQL dialect, casts (`::`), and explicit Postgres function allowlist [E:CLAIM-049]. |
| **FINDING-019** | High | Authorization | Reliance on AST-only column hiding without database role scoping | Implemented database-level PostgreSQL role authorization (`SET LOCAL ROLE`) with column-level grants (`02-roles.sql`) [E:CLAIM-043]. |

---

## 3. Engineering Remediation Architecture (P0 through P4)

### 3.1 Worker-Isolated SQLite Engine and Hard Deadlines (P0-1 & P0-2)
Queries execute within an isolated worker thread spawned via Node's `node:worker_threads` [E:CLAIM-025]. 
- **Resource Bounds**: Worker V8 heap is constrained via `resourceLimits` (128MB old generation, 16MB young generation) [E:CLAIM-026].
- **Hard Timeout**: When query execution exceeds `timeoutMs` (5000ms default; 800ms in timeout tests), the main thread immediately invokes `worker.terminate()`, aborting execution at the OS thread level [E:CLAIM-025]. The engine automatically respawns a clean worker thread for subsequent queries [E:CLAIM-025].
- **Engine Pragmas**: Configured with `PRAGMA query_only = ON`, `PRAGMA trusted_schema = OFF`, `PRAGMA cell_size_check = ON`, and `PRAGMA max_page_count = 4096` [E:CLAIM-026].
- **Compile-Time Authorizer**: `setAuthorizer` inspects actions (`SQLITE_SELECT`, `SQLITE_READ`, `SQLITE_FUNCTION`, `SQLITE_RECURSIVE`). Unauthorized table access, PII column reads (including via views), and unapproved function calls are rejected by SQLite before execution starts [E:CLAIM-026].

### 3.2 Recursive AST SQL Validation (P0-3)
Built with `node-sql-parser` (`5.4.0` [E:CLAIM-002]), the validator parses SQL into an AST and traverses all query constructs [E:CLAIM-004]:
- **Statement Gate**: Permits only single-statement `SELECT` queries [E:CLAIM-004]. Multi-statements, `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `ATTACH`, and `PRAGMA` are rejected [E:CLAIM-004].
- **Function Allowlist**: Rejects unknown functions by default [E:CLAIM-018]. Permitted functions: `LOWER`, `UPPER`, `TRIM`, `SUBSTR`, `LENGTH`, `ROUND`, `ABS`, `MIN`, `MAX`, `COUNT`, `SUM`, `AVG`, `COALESCE`, `IFNULL`, `NULLIF`, `STRFTIME`, `DATE`, `TIME`, `DATETIME`, `CAST`, `TYPEOF` [E:CLAIM-018]. Multi-argument requirements for `COALESCE` are verified.
- **Join Constraints**: Rejects explicit `CROSS JOIN`, `NATURAL JOIN`, comma-separated Cartesian joins, and tautological `ON` conditions (e.g. `ON 1=1`, `ON c.id = c.id`, `ON c.id = u.id OR 1=1`) [E:CLAIM-019].
- **Compound Query Bound**: Caps compound SELECT branches (`UNION`, `UNION ALL`) to 5 [E:CLAIM-021].
- **Automatic Limit Clamping**: Injects `LIMIT 100` when omitted and clamps requests above 1000 down to 1000 [E:CLAIM-007].

### 3.3 Multi-Layer Fail-Closed PII Protection (P0-5)
Sensitive columns (`billing_email`, `stripe_customer_id`, `webhook_secret`, `client_ip`, `hashed_secret`) are protected by three coordinated layers [E:CLAIM-020]:
1. **AST Analysis**: Identifies referenced columns across projection lists, `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`, CTEs, and subqueries [E:CLAIM-020].
2. **Authorizer Enforcement**: SQLite reports the underlying base column read during statement compilation, blocking views or subquery aliases that hide PII [E:CLAIM-020].
3. **Result-Level Value Scanning**: Post-execution policy inspects returned column names and cell string values for PII patterns (email formats, Stripe prefixes, bearer tokens, IPv4 addresses), failing closed if detected [E:CLAIM-020].

### 3.4 Default-Deny Protocol RBAC (P0-4)
`RBACManager` mediates all tool calls and resources [E:CLAIM-006]:
- Missing or invalid credentials resolve to `unauthenticated`, exposing only `whoami` [E:CLAIM-017].
- All database discovery tools (`list_tables`, `describe_table`), query execution tools (`execute_analytical_sql`), audit tools (`get_security_audit_log`), and catalog resources (`schema://catalog`) reject unauthenticated callers [E:CLAIM-006], [E:CLAIM-016], [E:CLAIM-017].
- Supports verified `mcp-use` OAuth scopes (`db:read:metadata`, `db:execute:analytics`, `db:audit:read`, `db:pii:access`) alongside static demo Bearer tokens [E:CLAIM-013].

### 3.5 Rate Limiting & Query Budgeting (P4)
`RateLimiter` enforces in-memory sliding-window request limits and row-budget accounting per principal [E:CLAIM-044]:
- `analyst`: 60 queries/minute, 10,000 rows/hour [E:CLAIM-044].
- `public_viewer`: 30 queries/minute, 2,000 rows/hour [E:CLAIM-044].
- Exceeded thresholds fail closed with `BLOCKED_RATE_LIMIT` [E:CLAIM-044].

### 3.6 Untrusted Data Tagging (P4)
Query execution results are marked with `untrustedData: true` and an explicit prompt safety advisory instructing calling models that database contents represent untrusted user content [E:CLAIM-046].

### 3.7 Persistent Redacted Audit Logging (P4)
`AuditLogger` maintains a 100-entry in-memory ring buffer for low-latency status inspection while appending all audit records to an append-only JSONL log on disk (`data/audit.jsonl`) [E:CLAIM-045]. Queries undergo sensitive literal redaction (scrubbing emails, tokens, secrets, IP addresses) before persistence [E:CLAIM-045].

### 3.8 Experimental PostgreSQL Adapter (P4)
`PostgresSecureAdapter` provides configuration templates and query validation for PostgreSQL environments [E:CLAIM-043]. Enforces read-only transaction parameters, `statement_timeout = '3000ms'`, and system catalog allowlists [E:CLAIM-043]. Marked `EXPERIMENTAL` due to absence of live local cluster [E:CLAIM-043].

---

## 4. Empirical Evidence and Verification Suite

The repository contains 181 automated tests across 15 test files [E:CLAIM-048]:

### 4.1 Public Bypass Corpus (`tests/bypass-corpus/`)
A structured corpus of 32 adversarial vectors categorized across 6 attack families [E:CLAIM-039]:
- `comment-tricks`: Inline comments, multi-line comment bypasses, trailing hyphens.
- `unicode-and-encoding`: Unicode Homoglyphs, null-byte injection (`\u0000`), control characters.
- `quoting-and-casing`: Backticks, bracket quoting, mixed-case function/table names.
- `function-and-io-exploits`: `load_extension`, file I/O primitives (`read_file`, `write_file`), PRAGMA queries.
- `cte-and-subquery-mutations`: Mutating statements hidden inside `WITH` clauses or derived subqueries.
- `cartesian-and-complexity`: Cartesian cross-joins, comma joins, and compound SELECT overflows.
All 32 vectors are verified to fail closed in `tests/bypass-corpus.test.ts` [E:CLAIM-039].

### 4.2 Differential Testing (`tests/differential.test.ts`)
93 queries run through both `SQLValidator` and real `node:sqlite` with authorizer active [E:CLAIM-040]. The harness asserts zero security divergences: any query permitted by the validator executes without engine-level policy violation or state mutation [E:CLAIM-040].

### 4.3 Grammar and Mutation Fuzzing (`tests/fuzz.test.ts`)
A deterministic linear congruential PRNG fuzzer evaluates 300 generated and mutated queries across varied roles [E:CLAIM-041]. The harness verifies that all allowed queries execute safely without exceeding row bounds or leaking restricted PII [E:CLAIM-041].

### 4.4 Dedicated Self Red-Team Pass (`tests/red-team-self.test.ts`)
32 adversarial attack vectors targeting AST parser edge cases, authorizer reentrancy, CTE depth limits, tautology variations, and PII exfiltration channels [E:CLAIM-042]. All 32 attacks are verified to fail closed [E:CLAIM-042].

### 4.5 Reproducible Latency Benchmark (`bench/validator.bench.ts`)
Executed on Node v24.12.0 x64 with 1,000 warm-up iterations and 10,000 timed iterations per query [E:CLAIM-022]:
- **Simple Projection**: p50 0.334 ms, p95 1.102 ms, p99 3.344 ms (1668 ops/sec) [E:CLAIM-022].
- **Relational Join**: p50 0.395 ms, p95 1.030 ms, p99 1.904 ms (1848 ops/sec) [E:CLAIM-022].
- **Aggregate Grouping**: p50 0.725 ms, p95 3.509 ms, p99 11.280 ms (751 ops/sec) [E:CLAIM-022].

---

## 5. Threat Model and Lethal Trifecta Analysis

A full threat model is maintained in `docs/THREAT_MODEL.md` [E:CLAIM-047].

### 5.1 The Lethal Trifecta
The system explicitly analyzes the convergence of:
1. Private data access (database read tools)
2. Untrusted content exposure (indirect prompt injections in stored text)
3. Exfiltration channels (external agent communication tools)

`mcp-secure-db` mitigates Leg 1 through default-deny RBAC, PII scanning, and row budgeting. It mitigates Leg 2 by tagging outputs with `untrustedData: true` [E:CLAIM-046] and blocking database writes. For Leg 3, `mcp-secure-db` provides zero network tools, but notes that host orchestrators must contain external egress tools.

### 5.2 OWASP Coverage Summary
The threat model evaluates all OWASP MCP Top 10 and OWASP LLM Top 10 risks [E:CLAIM-047]:
- `COVERED`: Token theft (MCP-01), Excessive tool permissions (MCP-02), Input validation (MCP-03), DoS (MCP-04), Insecure defaults (MCP-05), Audit logging (MCP-06), State mutation (MCP-07), Confused deputy (MCP-09), Untrusted output (MCP-10), Sensitive info disclosure (LLM-02), Supply chain (LLM-03), Improper output handling (LLM-05), Excessive agency (LLM-06), Unbounded consumption (LLM-10).
- `PARTIAL`: Insecure protocol deserialization (MCP-08), Indirect prompt injection (LLM-01).
- `OUT_OF_SCOPE`: Model poisoning (LLM-04), System prompt leakage (LLM-07), Vector weaknesses (LLM-08), Misinformation (LLM-09).

---

## 6. Honest Partner and Ecosystem Positioning

- **Company**: Manufact (formerly `mcp-use`), founded by Pietro Zullo and Luigi Pederzani, with CTO Enrico Toniato [E:CLAIM-012].
- **Funding & Batch**: Y Combinator batch S25; $6.3M seed round led by Peak XV in February 2026 [E:CLAIM-012].
- **Technology Focus**: Open-source TypeScript SDK and runtime infrastructure for Model Context Protocol servers.
- **Dependency Pinning**: Pinned exact dependency `mcp-use@2.12.2` verified against `pnpm-lock.yaml` sha512 integrity hashes [E:CLAIM-001].
- **Claims Boundary**: The unverified term "Dockpack" and unsubstantiated ROI claims have been removed from the repository.

---

## 7. Open Questions and Future Research

As documented in `docs/OPEN_QUESTIONS.md`:
- `OQ-001`: "Dockpack" terminology unverified in installed packages; removed pending official documentation.
- `OQ-002`: Scope of historical npm security notices on `mcp-use` mitigated by lockfile pinning and automated CI auditing.
- `OQ-003`: Upstream PR auto-close bot URLs unverified; not cited without primary link.
- `OQ-004`: Quantitative CISO adoption statistics avoided without primary survey citations.
- `OQ-005`: PostgreSQL adapter graduated to supported query engine with connection pooling, database-level role enforcement, and CI container testing [E:CLAIM-043].
- `OQ-006`: Independent third-party human security review remains recommended prior to production deployment.

---

## 8. Acceptance Criteria Evaluation and Sign-Off

The repository was evaluated against all 8 acceptance criteria:

| Criterion | Requirement | Verification Command / File | Status |
| :--- | :--- | :--- | :--- |
| **1. Clean CI Suite** | `pnpm test`, `claims:lint`, and `deps:verify` pass on clean checkout | `pnpm test` (184 tests pass) [E:CLAIM-048] | **PASSED** |
| **2. Worker Timeout Kill** | Slow recursive CTE terminated via `worker.terminate()` in tests | `tests/sqlite-controls.test.ts` [E:CLAIM-025] | **PASSED** |
| **3. Allowlists & Bypass Corpus** | Function/table allowlists active; 32 bypass cases fail closed | `tests/bypass-corpus.test.ts` [E:CLAIM-039] | **PASSED** |
| **4. Differential & Fuzz Runs** | Differential testing (93 queries) and fuzzing (300 queries) pass | `tests/differential.test.ts`, `tests/fuzz.test.ts` [E:CLAIM-040], [E:CLAIM-041] | **PASSED** |
| **5. Latency Benchmark** | Percentiles measured and cited via evidence tags | `bench/results.json`, `bench/validator.bench.ts` [E:CLAIM-022] | **PASSED** |
| **6. Accurate Threat Model** | Threat model and Limitations section match code reality | `docs/THREAT_MODEL.md` [E:CLAIM-047] | **PASSED** |
| **7. Persistent Redacted Audit** | Append-only JSONL log with literal scrubbing implemented | `src/database/audit.ts`, `tests/audit.test.ts` [E:CLAIM-045] | **PASSED** |
| **8. Claims Ledger Mapping** | Every factual/security claim maps to `SUPPORTED` in ledger | `docs/CLAIMS.md`, `scripts/claims-lint.ts` [E:CLAIM-037] | **PASSED** |

### Formal Classification

Because all 8 acceptance criteria are satisfied, `mcp-secure-db` earns the designation of a **hardened reference implementation and proof of concept**. It provides demonstrable defense-in-depth protections for AI database queries over MCP.

---

## 9. Limitations and Non-Goals

- **No regulatory certifications**: No claim of GDPR, HIPAA, SOC 2, or PCI compliance is made, and this software is out of scope for regulatory certification.
- **No formal security proofs**: Parser, authorizer, and result-level checks reduce risk for tested patterns; they do not constitute a formal proof of security.
- **Independent review requirement**: Organizations evaluating this architecture for production environments must conduct independent human security audits and operational penetration testing.
