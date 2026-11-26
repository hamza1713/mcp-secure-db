# Security Policy

`mcp-secure-db` is a security gateway, so reports of bypasses are especially welcome.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately through GitHub's **"Report a vulnerability"** button on this repository's
**Security** tab (GitHub private vulnerability reporting). Include:

- a description of the issue and its impact (for example: which layer is bypassed, what data or action becomes reachable);
- the policy file, role, credentials type (API key / OAuth / stdio) and engine (SQLite / PostgreSQL) used;
- a minimal SQL payload or MCP request that reproduces it;
- the commit hash you tested.

## What to expect

| Step | Target |
| :--- | :--- |
| Acknowledgement | within 3 business days |
| Initial assessment | within 10 business days |
| Fix or mitigation for confirmed issues | prioritised by severity; critical bypasses first |
| Public disclosure | coordinated with the reporter after a fix is available |

Reporters are credited in the release notes unless they prefer to stay anonymous.

## Scope

In scope:

- Any query, request or token that bypasses a layer described in `docs/THREAT_MODEL.md`
  (RBAC, SQL validation, engine authorizer / PostgreSQL grants, deadlines, result PII policy,
  rate limits, tenant isolation, audit chain integrity).
- Authentication flaws in API-key or OAuth/JWT handling (`src/security/rbac.ts`, `src/security/oauth-provider.ts`).
- Disagreement between the validator and the database engine that results in unsafe execution.

Out of scope (documented limitations, see README "Limitations and Non-Goals"):

- A prompt-injected agent reading data its authenticated role is legitimately allowed to read.
- Statistical inference over columns a role is permitted to query.
- Deployments that enable `MCP_SECURE_DB_INSECURE_DEMO`, `MCP_SECURE_DB_ALLOW_DEMO_TOKENS` or
  `MCP_SECURE_DB_METRICS_PUBLIC` on untrusted networks.

## Supported versions

Only the latest commit on `main` receives security fixes until versioned releases are published.

## Independent review

All tests in this repository were written alongside the code. An independent third-party
security review has **not** yet been performed and is recommended before production use
(tracked as `OQ-006` in `docs/OPEN_QUESTIONS.md`).
