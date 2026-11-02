# mcp-secure-db: Credibility Audit, Research Findings and Remediation Plan

*Prepared November 2026. Independent technical review of the "Executive Stakeholder & Investor Report" for `mcp-secure-db`, with web research, a claims register, a remediation roadmap, and a companion master prompt for an AI coding agent (see `mcp-secure-db-master-prompt.md`).*

---

## 1. Purpose and how to use this document

The original report describes a genuinely useful piece of engineering, but it states several things more strongly than the evidence supports. This document does four things:

1. Separates **verified facts**, **unverified claims**, and **incorrect or overstated claims** (Section 2).
2. Summarizes what current research says about the real threat model, so the project targets the right problems (Section 3).
3. Gives a concrete technical and positioning roadmap (Sections 4 to 7).
4. Pairs with a **master prompt** (separate file) that tells an AI coding agent to implement the fixes and to keep auditing its own output for overclaims.

Guiding principle: **every claim must be backed by a test, a measurement, or a citation. If it is not, it gets softened or removed.**

---

## 2. Claims register

### 2.1 External facts about Manufact and `mcp-use`

| Claim in report | Finding | Action |
|---|---|---|
| Founders are Pietro Zullo and Luigi Pederzani | Confirmed by Y Combinator's company pages and press coverage. | Keep. |
| Founders are "YC W24/S24" alumni | **Incorrect.** Y Combinator lists Manufact (formerly mcp-use) in the **S25** (Summer 2025) batch, founded in 2025, with a small team. | Fix to "YC S25". |
| Manufact is the "Vercel of MCP" | This is the founders' own marketing language (their public profile calls mcp-use an open-source "Vercel for MCP"). | Keep, but attribute it as their positioning, not an independent fact. |
| Company profile | Press reports a **$6.3M seed round in February 2026 led by Peak XV**, and a third core contributor, CTO Enrico Toniato. | Add. It shows the company is real and funded, and that "two founders" is incomplete. |
| `mcp-use` v2.12.2 | **Could not verify.** Registries show several packages and version lines (the npm `mcp-use` package, `@mcp-use/cli`, and a separate Python package). One package-health page also carries a notice that the npm package was involved in a security incident that led to compromised versions being published. | Verify the exact version from the lockfile, pin it, and add a supply-chain note (task P0-7). |
| "Dockpack" is Manufact's build system | **Could not verify** from the public sources found. | Confirm against Manufact's own documentation before repeating it. |
| Maintainer bot message closing Python PRs | Cannot be independently verified here. | Quote only with the PR link included. Do not call it "insider intelligence". |

### 2.2 Technical claims about the system

| Claim | Status | Why | Replacement language |
|---|---|---|---|
| "Mathematical, deterministic security guarantees" | **Overclaim** | A parser-based allow/deny check is a strong filter, not a proof. Its safety depends on the parser and the real engine agreeing on what a query means. | "Deterministic policy enforcement that reduces risk. Not a formal guarantee." |
| "Under 1 ms" validation | **Unmeasured** | No benchmark methodology is shown. | Report p50, p95, p99 from a documented benchmark, or drop the number. |
| "C++ AST parsing speeds" | **Incorrect** | The parser is a JavaScript library. | Delete. |
| "Hardware isolation", "kernel sandbox", "hardware watchdog" | **Incorrect terminology** | `sql.js` is SQLite compiled to WebAssembly running inside the Node process. That is software isolation, not hardware or kernel isolation. | "In-process WebAssembly sandbox with no filesystem or network handles." |
| "Hard 10-second execution cap" | **Likely not enforced as described** | `sql.js` executes synchronously and a running statement cannot be interrupted mid-execution. A timer on the same thread cannot fire until the statement ends. | Run the engine in a worker thread and terminate the worker at the deadline. Test with a deliberately slow query. |
| SSRF guard blocks `read_csv`, `read_parquet` | **Mismatched to the engine** | Those are DuckDB functions from the Python prototype. SQLite has a different attack surface, and a denylist of function names is weaker than an allowlist. | Replace with an allowlist of permitted functions. |
| PII protection via column-name checks | **Partial** | Name-based checks can be sidestepped by aliasing, CTEs, subqueries, expressions, and views, and do not stop inference. | "Column-level access policy with result-level redaction." Do not mention GDPR or HIPAA compliance. |
| `LIMIT` injection prevents bill shock | **Partial** | A row limit does not bound the work a join, sort, or aggregation does before the limit applies. | Add cost and time budgets, not just row caps. |
| "Thread-safe" audit ring buffer | **Meaningless here** | Node application code runs on one thread, and the buffer is lost on restart. | "In-memory recent-events buffer (not durable)." Add a persistent log. |
| 49/49 tests passing | **True but not security evidence** | The author wrote both the code and the tests. | Present as regression tests. Add fuzzing and an independent bypass corpus. |
| "CISOs are actively blocking AI database integrations" | **Unsourced** | No citation given. | Cite a survey or reword to "security teams are cautious". |
| "Production Ready" | **Overclaim** | It runs on seeded demo data in an in-memory SQLite database. | "Reference implementation and proof of concept." |

### 2.3 Presentation issues

- Local file paths (`C:\Users\...`) and a local screenshot path appear in a document meant for outsiders. Remove them.
- "Founder and ecosystem goodwill" is listed as ROI. It is not.
- There is no competitor section, no customer evidence, no pricing, and no measured cost comparison.

---

## 3. Research findings and what they mean for the project

### 3.1 The real attack is usually prompt injection plus legitimate data access

The best-known public example is the 2025 demonstration against a Supabase MCP setup. The agent ran with elevated database access that bypassed row-level security, and it also read customer-submitted support messages. An attacker wrote instructions inside a support ticket telling the agent to read a private tokens table and paste the contents back into the ticket. No SQL injection or syntax trick was needed. Every query was valid and "safe" by a SELECT-only standard.

Simon Willison named the pattern the **lethal trifecta**: access to private data, exposure to untrusted content, and a way to communicate data out. Making the server read-only removes one leg (writing data back) but not the underlying risk. Supabase itself stated that prompt injection remains the top concern even in read-only mode.

**Implication for `mcp-secure-db`:** a SELECT-only AST validator blocks `DROP TABLE`, but it cannot stop an agent from reading data its role is allowed to read and then leaking it through another channel. The project must (a) enforce least privilege per user, (b) treat results as untrusted data, and (c) say plainly what it does **not** protect against.

### 3.2 Industry guidance: assume the model can be tricked, and contain it

OWASP's 2026 Top 10 for LLM Applications again ranks prompt injection first, and its core control is containment: assume instructions can be bypassed, then limit actions, tool functionality, permissions, and output destinations. OWASP also maintains a dedicated, still-in-beta **MCP Top 10** covering token mismanagement, privilege escalation through scope creep, tool poisoning, command injection, and prompt injection through contextual payloads. Secondary security write-ups report dozens of MCP-related CVEs in early 2026. Treat their exact statistics with caution until checked against primary sources, but the direction is consistent.

**Implication:** map the project's features to the OWASP MCP Top 10 and LLM Top 10 explicitly, and be honest about which risks are covered, partly covered, or out of scope.

### 3.3 The "SELECT-only AST check" is common, and practitioners add database-level enforcement

Several existing open-source MCP database servers already combine SQL validation with database-level controls:

- **Postgres MCP Pro** has a restricted mode with parsed and validated SQL, read-only operations, and execution time limits, and still recommends a read-only database user.
- **MCP DB Gateway** describes schema and table allowlists, SQL validation, read-only transactions, row and statement-timeout limits, and audit events. It calls itself defense in depth, not magic, and recommends a dedicated SELECT-only role.
- Another Postgres server enforces read-only twice: a SQL guard plus the `default_transaction_read_only` setting, with server-side `statement_timeout`.
- A 2026 engineering write-up concludes that AST checks alone leave gaps (for example, mutations hidden in CTEs) and that database-level read-only enforcement is the better foundation.

**Implication:** the claim "most database tools are built for humans, ours is built for AI agents" is not defensible as written. The honest differentiators are narrower: role-based tool masking, column-level policy, a public bypass corpus, an audit trail, and native `mcp-use` integration. The report needs a competitor comparison.

### 3.4 SQLite's maintainers describe how to handle untrusted SQL, and it is more than a parser

SQLite's security guidance for applications that accept untrusted SQL recommends, among other things:

- Enabling the defensive configuration flag.
- Lowering the engine's built-in limits (SQL length, expression depth, compound selects, VDBE operations, function arguments, attached databases, LIKE pattern length).
- Using an **authorizer callback** to restrict which operations the engine will process at all.
- Capping memory with a hard heap limit.
- Using a progress handler, or a timer that calls the interrupt function, so a statement cannot run forever.

An authorizer works at the engine's compile step, so it sees what the engine actually resolved. That closes much of the parser-differential gap. Node's built-in `node:sqlite` exposes an authorizer callback, though the module is still an early release candidate and has had reentrancy issues reported. `sql.js` is synchronous, so interrupting a running statement requires a worker thread that can be terminated.

**Implication:** the engine layer should use SQLite's recommended controls. The AST validator then becomes a fast early check with good error messages, not the only wall.

### 3.5 Generic SQL parsers only approximate SQLite

SQLite tooling developers note that generic multi-dialect parsers approximate SQLite and can misparse valid syntax. Some projects now build parsers from SQLite's own grammar and test them differentially against the real engine. If the validator and the engine disagree about what a string means, an attacker can exploit the gap.

**Implication:** run **differential testing**. Feed the same queries to the validator and to real SQLite, and flag any case where the validator says "safe" but the engine would do something the policy forbids.

---

## 4. Technical remediation roadmap

### P0: Make the claims true (do first)

| ID | Task | Done when |
|---|---|---|
| P0-1 | Move SQLite execution into a **worker thread** with a hard deadline that terminates the worker. | A deliberately slow recursive query is killed within the deadline in a test. |
| P0-2 | Apply SQLite's recommended controls (defensive flag, reduced limits, authorizer or equivalent, heap limit) where the chosen engine supports them. If `sql.js` cannot, evaluate `node:sqlite` or `better-sqlite3` in a worker and document the trade-off. | A config test proves each control is active. |
| P0-3 | Replace function and table **denylists with allowlists**. Remove leftover DuckDB-era function names. | Unknown functions are rejected by default in tests. |
| P0-4 | **Default-deny authentication.** An unauthenticated caller gets no data tools unless an explicit demo flag is set. Prefer real OAuth over a static header key where the framework supports it. | Missing or invalid credentials return no data and are logged. |
| P0-5 | Add result-level checks so PII policy does not depend only on column names (aliases, CTEs, subqueries, expressions, views). | Bypass tests for each technique fail closed. |
| P0-6 | Remove or correct every item in the claims register (Section 2). | `claims-lint` passes. |
| P0-7 | Pin dependencies, commit the lockfile, verify package versions and integrity, enable dependency scanning. | CI fails on unpinned or unverified dependencies. |

### P1: Real database support and defense in depth

| ID | Task |
|---|---|
| P1-1 | Add a **PostgreSQL adapter** (optionally MySQL): dedicated read-only role, `default_transaction_read_only`, `statement_timeout`, schema and table allowlists. |
| P1-2 | Prefer **database-native** protections (row-level security, masked views, column privileges) and keep the validator as an additional layer. Document which layer stops which attack. |
| P1-3 | **Cost gating**: use `EXPLAIN` estimates (Postgres) or operation counters (SQLite) to reject queries over a cost budget. Row caps alone do not bound compute. |
| P1-4 | **Per-user credentials**: each caller maps to a scoped database identity, not one shared powerful connection. |

### P2: Prompt-injection containment (the real-world threat)

| ID | Task |
|---|---|
| P2-1 | Write a **lethal-trifecta analysis**: what private data the server can reach, what untrusted content it can ingest, and which channels could carry data out. |
| P2-2 | Do **not** expose write-back or messaging tools on the same server as data-reading tools. If unavoidable, require explicit human approval. |
| P2-3 | Mark returned rows as untrusted data in the response schema, and neutralize instruction-like content where feasible (a mitigation, not a cure). |
| P2-4 | Add **rate limits and query budgets** per identity to limit slow data extraction. |
| P2-5 | Map features to the OWASP MCP Top 10 and LLM Top 10 in a coverage table: covered, partial, out of scope. |

### P3: Audit and observability

| ID | Task |
|---|---|
| P3-1 | Keep the 100-entry ring buffer as a cache, but add a **persistent, append-only log** (JSON lines or OpenTelemetry). |
| P3-2 | Log identity, tool, normalized query, decision, rule that fired, row count, and duration. **Redact** values and never log secrets. |
| P3-3 | Add tamper-evidence (hash chaining) only if you intend to claim it. Otherwise do not claim it. |

### P4: Evidence and independent validation

| ID | Task |
|---|---|
| P4-1 | **Differential testing** of the validator against real SQLite on a large query corpus. |
| P4-2 | **Fuzzing** (grammar-based and mutation-based) with the property: anything the validator allows must not mutate state, read forbidden objects, or exceed budget. |
| P4-3 | A public **bypass corpus**: comment tricks, unicode, nested CTEs, quoting, case, whitespace, alternative function spellings, `WITH` plus mutation, `PRAGMA` and `ATTACH` variants, `load_extension`. |
| P4-4 | A reproducible **benchmark** with hardware, dataset, method, and percentiles. |
| P4-5 | Invite an **independent review** or red-team and publish the findings, including failures. |

---

## 5. Positioning and business rewrite

**Recommended framing:** "An open-source reference implementation and guardrail library showing layered defenses for AI database access over MCP, with an honest threat model and a public bypass test suite."

What to change in the investor-style narrative:

1. **Add a competitor table**: Postgres MCP Pro, MCP DB Gateway, other read-only Postgres MCP servers, and vendor read-only modes. State what overlaps and what is different.
2. **Add a limitations section** (Section 6). Honest limits raise credibility with security audiences.
3. **Replace ROI language** with measured numbers or remove it. Token savings should come from a measured comparison against an LLM-judge baseline on the same query set, with the method shown.
4. **Describe the partner relationship accurately.** Manufact is a funded, active company that publicly says it focuses on its open-source SDK and community. The better ask is a concrete contribution (an example server, docs, or a security guide) through their normal contribution process, not a pitch built on a bot message.
5. **Choose one audience.** An investor memo needs market size, customer evidence, and a revenue model. A technical write-up needs architecture, threat model, and test evidence. The current document tries to be both. Write them separately.
6. **Remove all personal and local details** (paths, screenshots with local URLs).

---

## 6. Required "Limitations and non-goals" section

The revised report should state, in plain language:

- The validator and sandbox do **not** prevent prompt injection. They limit what an injected instruction can do through SQL.
- If a role may read a table, an injected agent may read it too. Least privilege and row-level security remain the primary defense.
- Inference, aggregation, and re-identification attacks on permitted data are out of scope unless specifically addressed.
- The demo runs on seeded in-memory SQLite and is not evidence of production behavior against Postgres, Snowflake, or BigQuery.
- The in-memory audit buffer is for debugging, not compliance.
- No claim of GDPR, HIPAA, SOC 2, or similar compliance is made.
- The project has not yet had independent security review (update this line when it has).

---

## 7. Revised report outline

1. Summary (what it is, what it is not, current maturity)
2. Problem and threat model (with citations: lethal trifecta, OWASP)
3. Landscape and comparison with existing tools
4. Architecture (accurate terminology)
5. What each layer defends against, and what it does not
6. Evidence: tests, differential results, fuzzing, benchmarks, with methods
7. Known limitations and non-goals
8. Roadmap and request for review or contribution
9. References

---

## 8. Sources consulted

- Y Combinator company pages for Manufact (formerly mcp-use) and the YC open-source company listing
- Manufact seed announcement (manufact.com/blog/seed-announcement)
- VentureBeat coverage of the $6.3M seed round
- Dealroom and Preqin company profiles for Manufact
- Snyk package page for `mcp-use` on npm (security.snyk.io/package/npm/mcp-use)
- Simon Willison, "Supabase MCP can leak your entire SQL database" and "The Lethal Trifecta" (simonwillison.net)
- Supabase, "Defense in depth for MCP servers" (source in github.com/code/lib-supabase, pull 267)
- SQLite, "Defense Against The Dark Arts" (sqlite.org/security.html)
- Node.js documentation for `database.setAuthorizer()` in `node:sqlite`, and the related issue tracker discussion
- TableAtom (VS Code extension) documentation noting that `sql.js` executes synchronously and long statements cannot be interrupted
- Postgres MCP Pro repository README (restricted mode)
- MCP DB Gateway listing on Glama
- `database-mcp-postgres` on PyPI
- Pamela Fox, engineering blog, August 2026 (MCP database design spectrum)
- OWASP MCP Top 10 project (beta) and OWASP Top 10 for LLM Applications 2026, with secondary summaries from Cycode and others
- syntaqlite write-up (lalitm.com) and `tree-sitter-sqlite3` on PyPI, on SQLite parsing fidelity

*Statistics from secondary blog posts (for example CVE counts or attack success rates) should be re-checked against primary sources before being quoted in any formal document.*
