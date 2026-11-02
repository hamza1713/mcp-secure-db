import { describe, it, expect } from "vitest";
import path from "node:path";
import {
  parseClaimsLedger,
  scanTextContent,
  type ClaimEntry,
} from "../scripts/claims-lint.js";

const REPO_ROOT = path.resolve(process.cwd());

function buildSampleClaims(): Map<string, ClaimEntry> {
  const sampleLedger = [
    "| ID | Claim Text | Location | Evidence Type | Evidence Reference | Status |",
    "| :--- | :--- | :--- | :--- | :--- | :--- |",
    "| CLAIM-100 | Regression suite runs 49 tests | `tests/validator.test.ts` | TEST | `tests/validator.test.ts` | SUPPORTED |",
    "| CLAIM-101 | Validator p50 latency is 0.42 ms | `tests/validator.test.ts` | BENCH | `tests/validator.test.ts` | SUPPORTED |",
    "| CLAIM-102 | Partial column policy check | `src/security/validator.ts` | TEST | `tests/validator.test.ts` | PARTIAL |",
    "| CLAIM-103 | Unverified external marketing term | `README.md` | NONE | `NONE` | UNVERIFIED |",
  ].join("\n");

  const parsed = parseClaimsLedger(sampleLedger, REPO_ROOT);
  expect(parsed.violations).toEqual([]);
  return parsed.claims;
}

describe("claims-lint self-auditing honesty linter", () => {
  describe("passing sample text", () => {
    it("accepts measured, plain-language claims tagged with SUPPORTED evidence IDs", () => {
      const claims = buildSampleClaims();
      const markdown = [
        "# Architecture Notes",
        "",
        "The validator enforces a SELECT-only check that reduces risk against known mutation patterns.",
        "Regression suite executes 49 tests in Vitest [E:CLAIM-100].",
        "Measured median validation time is 0.42 ms (< 1 ms p50) on the local benchmark [E:CLAIM-101].",
        "",
        "## Limitations and Non-Goals",
        "",
        "- No claim of GDPR, HIPAA, SOC 2, or PCI compliance is made.",
        "- Out of scope for regulatory compliance certification.",
      ].join("\n");

      const violations = scanTextContent({
        file: "docs/SAMPLE.md",
        content: markdown,
        claims,
        mode: "markdown",
      });

      expect(violations).toEqual([]);
    });

    it("accepts clean TypeScript comments and URIs such as schema://catalog", () => {
      const claims = buildSampleClaims();
      const tsSource = [
        "// Enforces table allowlists in tests without calling an external LLM.",
        'const uri = "schema://catalog"; // Resource identifier for catalog lookup',
        "/* Multi-line comment:",
        "   Measured p50 latency 0.42 ms [E:CLAIM-101] */",
      ].join("\n");

      const violations = scanTextContent({
        file: "src/sample.ts",
        content: tsSource,
        claims,
        mode: "typescript",
      });

      expect(violations).toEqual([]);
    });
  });

  describe("failing sample text", () => {
    it("rejects absolute and inflated wording", () => {
      const claims = buildSampleClaims();
      const phrases = [
        "Provides a formal guarantee against SQL injection.",
        "Uses mathematical AST verification.",
        "This server is 100% secure [E:CLAIM-100].",
        "An unbreakable sandbox boundary.",
        "A bulletproof guardrail layer.",
        "Makes it impossible to leak records.",
        "Delivers zero risk database access.",
        "Completely eliminates prompt injection.",
        "Prevents all unauthorized reads.",
        "Built with military-grade controls.",
        "An enterprise-grade MCP database server.",
      ];

      for (const line of phrases) {
        const violations = scanTextContent({
          file: "README.md",
          content: line,
          claims,
          mode: "markdown",
        });
        expect(
          violations.some((v) => v.rule === "inflated-wording"),
          `Expected inflated-wording violation for: ${line}`
        ).toBe(true);
      }
    });

    it("rejects inaccurate sandbox and parser terminology", () => {
      const claims = buildSampleClaims();
      const phrases = [
        "Runs SQLite inside hardware isolation.",
        "Executes queries inside an in-memory kernel sandbox.",
        "Aborts slow queries with a hardware watchdog.",
        "Parses SQL at C++ AST speeds.",
      ];

      for (const line of phrases) {
        const violations = scanTextContent({
          file: "README.md",
          content: line,
          claims,
          mode: "markdown",
        });
        expect(
          violations.some((v) => v.rule === "incorrect-terminology"),
          `Expected incorrect-terminology violation for: ${line}`
        ).toBe(true);
      }
    });

    it("rejects compliance implications outside explicit Limitations non-claims", () => {
      const claims = buildSampleClaims();
      const outsideLimitations = [
        "# Security Overview",
        "PII column blocking supports GDPR and HIPAA readiness.",
        "Audit buffer assists SOC 2 and PCI compliance.",
      ].join("\n");

      const v1 = scanTextContent({
        file: "README.md",
        content: outsideLimitations,
        claims,
        mode: "markdown",
      });
      expect(v1.filter((v) => v.rule === "compliance-implication").length).toBeGreaterThanOrEqual(4);

      const positiveClaimInsideLimitations = [
        "## Limitations",
        "The server is already GDPR compliant for read-only workloads.",
      ].join("\n");

      const v2 = scanTextContent({
        file: "README.md",
        content: positiveClaimInsideLimitations,
        claims,
        mode: "markdown",
      });
      expect(v2.some((v) => v.rule === "compliance-implication")).toBe(true);
    });

    it("rejects unearned maturity phrases", () => {
      const claims = buildSampleClaims();
      for (const phrase of [
        "Status: Production Ready.",
        "A production-ready database gateway.",
        "Battle-tested SQLite execution engine.",
      ]) {
        const violations = scanTextContent({
          file: "README.md",
          content: phrase,
          claims,
          mode: "markdown",
        });
        expect(violations.some((v) => v.rule === "unearned-maturity")).toBe(true);
      }
    });

    it("rejects unmeasured performance claims and untagged numeric claims", () => {
      const claims = buildSampleClaims();
      const untagged = [
        "Pre-execution validation finishes in < 1 ms.",
        "Delivers sub-millisecond query checks.",
        "Completes under 1ms on average.",
        "Verified by 49 passing tests.",
        "Blocks 99.5% of injection attempts.",
        "Raised $6.3M in seed funding.",
      ];

      for (const line of untagged) {
        const violations = scanTextContent({
          file: "README.md",
          content: line,
          claims,
          mode: "markdown",
        });
        expect(
          violations.some(
            (v) =>
              v.rule === "unmeasured-performance" ||
              v.rule === "untagged-numeric-claim"
          ),
          `Expected performance/numeric violation for: ${line}`
        ).toBe(true);
      }
    });

    it("rejects personal and local filesystem paths", () => {
      const claims = buildSampleClaims();
      const localPaths = [
        "Workspace path: C:\\Users\\alice\\project",
        "See file:///c:/workspace/README.md",
        "Located in /Users/alice/repo",
        "Located in /home/ubuntu/repo",
      ];

      for (const line of localPaths) {
        const violations = scanTextContent({
          file: "docs/REPORT.md",
          content: line,
          claims,
          mode: "markdown",
        });
        expect(
          violations.some((v) => v.rule === "personal-or-local-path"),
          `Expected personal-or-local-path violation for: ${line}`
        ).toBe(true);
      }
    });

    it("rejects unknown or non-SUPPORTED evidence tags", () => {
      const claims = buildSampleClaims();
      const badTags = [
        "Runs 49 tests [E:CLAIM-999].",
        "Enforces column rules across 49 tests [E:CLAIM-102].",
        "External claim [E:CLAIM-103].",
      ];

      const vUnknown = scanTextContent({
        file: "README.md",
        content: badTags[0],
        claims,
        mode: "markdown",
      });
      expect(vUnknown.some((v) => v.rule === "unknown-evidence-tag")).toBe(true);

      const vPartial = scanTextContent({
        file: "README.md",
        content: badTags[1],
        claims,
        mode: "markdown",
      });
      expect(vPartial.some((v) => v.rule === "unsupported-evidence-tag")).toBe(true);

      const vUnverified = scanTextContent({
        file: "README.md",
        content: badTags[2],
        claims,
        mode: "markdown",
      });
      expect(vUnverified.some((v) => v.rule === "unsupported-evidence-tag")).toBe(true);
    });

    it("fails when a ledger entry references a nonexistent test or benchmark file", () => {
      const brokenLedger = [
        "| ID | Claim Text | Location | Evidence Type | Evidence Reference | Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
        "| CLAIM-200 | Benchmark p99 latency | `README.md` | BENCH | `bench/missing-file.bench.ts` | SUPPORTED |",
      ].join("\n");

      const parsed = parseClaimsLedger(brokenLedger, REPO_ROOT);
      expect(
        parsed.violations.some(
          (v) => v.rule === "ledger-nonexistent-evidence-file"
        )
      ).toBe(true);
    });
  });
});
