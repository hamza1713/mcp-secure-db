# Threat Model and Security Architecture

## 1. System Overview

`mcp-secure-db` is a reference implementation of a Model Context Protocol (MCP) database server. It mediates LLM agent access to structured SQL databases through layered defensive controls:

1. **Protocol RBAC and Tool Masking**: Dynamically filters tool lists and rejects unauthorized tool calls at the MCP protocol boundary [E:CLAIM-006].
2. **AST SQL Validator**: Traverses the SQL Abstract Syntax Tree to enforce read-only `SELECT` queries, per-role table/column allowlists, function allowlists, and row bounds [E:CLAIM-004], [E:CLAIM-008].
3. **Database Engine Hardening**: Configures SQLite with compile-time authorizers (`SQLITE_READ`, `SQLITE_SELECT`, `SQLITE_FUNCTION`), defensive mode, query-only pragma, extension loading disabled, and page caps [E:CLAIM-026].
4. **Worker Thread Sandbox and Hard Deadline**: Isolates query execution in dedicated `node:worker_threads` with strict V8 heap resource limits (`128MB` old generation) and hard deadline termination via `worker.terminate()` [E:CLAIM-025].
5. **Result-Level Fail-Closed Scanning and Untrusted Data Tagging**: Scans returned result sets for sensitive patterns (emails, tokens, keys) and tags rows with `untrustedData: true` [E:CLAIM-020], [E:CLAIM-046].
6. **Rate Limiting and Persistent Redacted Audit Logging**: Enforces per-principal query and row budgets, alongside an append-only redacted JSONL audit log [E:CLAIM-044], [E:CLAIM-045].

---

## 2. The "Lethal Trifecta" Analysis

Simon Willison articulated the "lethal trifecta" of AI agent security:
1. **Access to private data**: The agent has tools or credentials to read private information.
2. **Exposure to untrusted content**: The agent processes untrusted inputs (e.g., web pages, user messages, database text) that may contain indirect prompt injections.
3. **An exfiltration communication channel**: The agent has access to external communication tools (e.g., HTTP requests, messaging, webhooks, search).

When all three conditions exist simultaneously, an indirect prompt injection in untrusted data can instruct the agent to read private data and exfiltrate it via the communication channel.

```
       +-----------------------------+
       |   1. Private Data Access    |
       |  (mcp-secure-db read tools) |
       +--------------+--------------+
                      |
                      v
       +-----------------------------+         +-------------------------------+
       |   2. Untrusted Content      | ------> |  3. Exfiltration Channel      |
       |  (Row values / injections)  |         | (External agent HTTP / tools) |
       +-----------------------------+         +-------------------------------+
```

### How `mcp-secure-db` Addresses the Trifecta

- **Leg 1 (Private Data Access)**: Mitigated by default-deny RBAC, strict column/table allowlists, result-level PII scanning, and rate/row egress budgets. An analyst agent cannot view `billing_email`, `stripe_customer_id`, or `api_keys`.
- **Leg 2 (Untrusted Content)**: The database schema explicitly annotates all output data with `untrustedData: true` and a machine-readable notice instructing calling models never to execute row contents as instructions [E:CLAIM-046]. Furthermore, `mcp-secure-db` blocks all write operations, preventing agents from persisting injection payloads into the database.
- **Leg 3 (Exfiltration Channel)**: `mcp-secure-db` contains **zero external network egress tools**. It cannot send HTTP requests or socket connections. However, if host environments bundle `mcp-secure-db` alongside uncontained browsing or messaging tools, exfiltration risk remains present at the agent orchestrator tier.

---

## 3. Layer-by-Layer Defense & Non-Defense Matrix

Each defensive layer is designed with explicit boundaries:

| Layer | Primary Defenses (What it stops) | Boundaries & Non-Defenses (What it CANNOT stop) |
| :--- | :--- | :--- |
| **Layer 1: Protocol RBAC** | Unauthenticated callers; discovery or invocation of tools exceeding role grant [E:CLAIM-006]. | Authorized principals abusing legitimately granted permissions. |
| **Layer 2: AST SQL Validator** | Mutating statements (`DROP`, `INSERT`, `UPDATE`, `DELETE`, `ALTER`); schema tampering (`ATTACH`, `PRAGMA`); unapproved functions and tables; unbounded result sets; Cartesian joins [E:CLAIM-004], [E:CLAIM-018], [E:CLAIM-019]. | Logical data inference within allowed columns; parser-engine semantic edge cases (addressed by Layer 3). |
| **Layer 3: SQLite Hardening & Authorizer** | AST parser bypasses; views querying restricted columns; extension loading; writes via built-in engine mechanisms [E:CLAIM-026]. | CPU exhaustion on single thread (addressed by Layer 4); high-volume legitimate reads (addressed by Layer 6). |
| **Layer 4: Worker Thread Sandbox** | Runaway queries and recursive CTEs exceeding deadline; event-loop blocking; memory exhaustion exceeding 128MB heap limit [E:CLAIM-025]. | Complex queries completing just below deadline threshold; logical errors in query semantics. |
| **Layer 5: Result Policy & Data Tagging** | Accidental PII leakage via aliases, expressions, or wildcard projections; tags data as untrusted [E:CLAIM-020], [E:CLAIM-046]. | LLM models that ignore untrusted-data advisory notices due to weak instruction adherence. |
| **Layer 6: Rate Limiter & Persistent Audit** | Rapid automated data scraping; unrecorded actions; credential leakage in audit logs [E:CLAIM-044], [E:CLAIM-045]. | Slow, distributed exfiltration below query thresholds; compromised local host storage. |

---

## 4. OWASP MCP & LLM Top 10 Coverage

| Risk Identifier | Risk Name | Project Status | Mitigation & Architecture |
| :--- | :--- | :--- | :--- |
| **MCP-01** | Token / Credential Theft | `COVERED` | Default-deny authentication [E:CLAIM-017]; sensitive literal scrubbing from persistent audit logs [E:CLAIM-045]; no credentials stored in client responses. |
| **MCP-02** | Excessive Tool Permissions | `COVERED` | Least-privilege RBAC tool masking [E:CLAIM-006]; unauthenticated callers see zero data tools. |
| **MCP-03** | Lack of Input Validation | `COVERED` | Recursive AST validation [E:CLAIM-004], SQLite authorizer [E:CLAIM-026], strict function/table allowlists [E:CLAIM-018]. |
| **MCP-04** | Resource Exhaustion (DoS) | `COVERED` | Hard worker-thread deadline termination [E:CLAIM-025], V8 heap memory bounds, sliding-window rate limiting [E:CLAIM-044]. |
| **MCP-05** | Insecure Defaults | `COVERED` | Default-deny authentication [E:CLAIM-017]; `MCP_SECURE_DB_INSECURE_DEMO=true` required for demo fallback and documented as insecure. |
| **MCP-06** | Insufficient Audit Logging | `COVERED` | Dual-tier logging: in-memory ring buffer plus append-only redacted JSONL persistent log (`data/audit.jsonl`) [E:CLAIM-045]. |
| **MCP-07** | State / Data Mutation | `COVERED` | Enforced read-only at validator, authorizer (`SQLITE_READ` only), and engine (`query_only = ON`, `enableDefensive(true)`) [E:CLAIM-026]. |
| **MCP-08** | Insecure Protocol Deserialization | `PARTIAL` | Framework-level JSON-RPC serialization handled by pinned `mcp-use@2.12.2` [E:CLAIM-001]. Schema input validated via Zod schemas. |
| **MCP-09** | Confused Deputy Attacks | `COVERED` | Principal and role propagated through all validation, authorizer, and result-check layers. |
| **MCP-10** | Untrusted Output Injection | `COVERED` | Responses explicitly marked with `untrustedData: true` and prompt safety notices [E:CLAIM-046]. |
| **LLM-01** | Prompt Injection (Indirect) | `PARTIAL` | Database writes disabled; untrusted data tags applied [E:CLAIM-046]. Full mitigation requires client-side context isolation. |
| **LLM-02** | Sensitive Information Disclosure | `COVERED` | Three-layer PII defense (AST check, authorizer check, result-level value scanning) [E:CLAIM-020]. |
| **LLM-03** | Supply Chain Vulnerabilities | `COVERED` | Pinned exact semver dependencies, lockfile verification, and zero audit advisories [E:CLAIM-038]. |
| **LLM-04** | Data and Model Poisoning | `OUT_OF_SCOPE` | Model training and weights are managed upstream of the MCP server. |
| **LLM-05** | Improper Output Handling | `COVERED` | AST validation sanitizes and standardizes queries before execution. |
| **LLM-06** | Excessive Agency | `COVERED` | MCP server grants query execution only; no filesystem or external execution tools provided. |
| **LLM-07** | System Prompt Leakage | `OUT_OF_SCOPE` | System prompts belong to the client orchestrator, not the database tool. |
| **LLM-08** | Vector and Embedding Weaknesses | `OUT_OF_SCOPE` | Relational SQL database; vector search is not implemented. |
| **LLM-09** | Misinformation | `OUT_OF_SCOPE` | Database reflects stored records; factual accuracy of ingested data is an ETL responsibility. |
| **LLM-10** | Unbounded Consumption | `COVERED` | Rate limiter and row budgets bound per-principal consumption [E:CLAIM-044]. |

---

## 5. Limitations and Explicit Non-Claims

This project is a **reference implementation and proof of concept** designed to demonstrate defense-in-depth principles. The following boundaries are explicitly stated:

- **No regulatory certifications**: This software does not confer or imply compliance with regulations or standards such as GDPR, HIPAA, SOC 2, or PCI DSS. Regulatory compliance requires organizational policies, key management, operational audits, and independent human review.
- **No formal security proofs**: Layered defenses reduce risk through defense in depth; this implementation does not provide a formal proof of security.
- **Independent review requirement**: Organizations evaluating this architecture for production environments must conduct independent human security audits and operational penetration testing.
- **Experimental PostgreSQL adapter**: The PostgreSQL adapter (`src/database/postgres-adapter.ts`) is marked `EXPERIMENTAL` and requires validation against target PostgreSQL cluster deployments.
