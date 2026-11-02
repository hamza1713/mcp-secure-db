# Open Questions and Unverified Items

Items listed here cannot be verified solely from the local repository, lockfile, or reproducible local execution and are therefore marked `UNVERIFIED` until primary-source confirmation or external infrastructure is available.

| ID | Topic | Current Status | Detail and Next Step |
| :--- | :--- | :--- | :--- |
| OQ-001 | Manufact "Dockpack" build-system terminology | `UNVERIFIED` | The term `Dockpack` does not appear in the installed `mcp-use` package (`pnpm-lock.yaml` [E:CLAIM-001]). Removed from active claims until confirmed against official Manufact documentation. |
| OQ-002 | Historical `mcp-use` npm supply-chain incident scope | `UNVERIFIED` | `docs/mcp-secure-db-audit-and-remediation-report.md` notes a Snyk package-health notice referencing compromised historical npm versions of `mcp-use`. The exact affected version range cannot be verified offline; mitigation is exact version pinning, lockfile integrity hashes, and automated dependency auditing in CI. |
| OQ-003 | Upstream Python PR auto-close bot comment URL | `UNVERIFIED` | Earlier project notes quote an upstream GitHub bot message closing new Python PRs, but no verifiable public PR URL is stored in the repository. Do not cite as insider intelligence; only reference if linked to a public PR URL. |
| OQ-004 | Enterprise CISO adoption survey citation | `UNVERIFIED` | Earlier reports stated that security officers actively block AI database integrations without citing a primary industry survey. Reworded to cautious, non-quantitative phrasing unless a primary citation is added. |
| OQ-005 | Live PostgreSQL server in local/CI environment | `UNVERIFIED` | Local workspace and default CI containers may not run a live PostgreSQL instance during unit tests. When the PostgreSQL adapter is added in Phase 4, live integration status must be verified or explicitly marked `EXPERIMENTAL` if tested via mock/protocol unit tests only. |
| OQ-006 | Independent external human security review | `OPEN` | All current tests, differential harnesses, and red-team passes are authored within the project. Independent third-party human review remains required before production deployment. |
