import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type ClaimStatus =
  | "SUPPORTED"
  | "PARTIAL"
  | "UNSUPPORTED"
  | "UNVERIFIED"
  | "REMOVED";

export interface ClaimEntry {
  id: string;
  claimText: string;
  location: string;
  evidenceType: string;
  evidenceRef: string;
  status: ClaimStatus;
  line: number;
}

export interface LintViolation {
  file: string;
  line: number;
  rule: string;
  message: string;
  snippet: string;
}

export interface LintReport {
  ok: boolean;
  claimsCount: number;
  filesScanned: number;
  violations: LintViolation[];
}

const VALID_STATUSES = new Set<ClaimStatus>([
  "SUPPORTED",
  "PARTIAL",
  "UNSUPPORTED",
  "UNVERIFIED",
  "REMOVED",
]);

const AUDITOR_SPEC_FILES = new Set([
  "docs/mcp-secure-db-audit-and-remediation-report.md",
  "docs/mcp-secure-db-master-prompt.md",
]);

const ABSOLUTE_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "guarantee", regex: /\bguarantee[sd]?\b/i },
  { label: "mathematical", regex: /\bmathematical(?:ly)?\b/i },
  { label: "100% secure", regex: /100%\s*secure/i },
  { label: "unbreakable", regex: /\bunbreakable\b/i },
  { label: "bulletproof", regex: /\bbulletproof\b/i },
  { label: "impossible to", regex: /\bimpossible\s+to\b/i },
  { label: "zero risk", regex: /\bzero[- ]risk\b/i },
  { label: "eliminates", regex: /\beliminate[sd]?\b/i },
  { label: "prevents all", regex: /\bprevents?\s+all\b/i },
  { label: "military-grade", regex: /\bmilitary[- ]grade\b/i },
  { label: "enterprise-grade", regex: /\benterprise[- ]grade\b/i },
];

const TERMINOLOGY_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "hardware isolation", regex: /\bhardware[- ]isolation\b/i },
  { label: "kernel sandbox", regex: /\bkernel[- ]sandbox\b/i },
  { label: "hardware watchdog", regex: /\bhardware[- ]watchdog\b/i },
  {
    label: "C++ AST",
    regex:
      /\bc\+\+\s+ast\b|\bast\s+c\+\+\b|\bc\+\+\s+speeds?\b|\bast\s+c\+\+\s+evaluation\b/i,
  },
  { label: "database kernel", regex: /\bsandboxed\s+database\s+kernel\b/i },
];

const COMPLIANCE_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "GDPR", regex: /\bGDPR\b/i },
  { label: "HIPAA", regex: /\bHIPAA\b/i },
  { label: "SOC 2", regex: /\bSOC\s*2\b/i },
  { label: "PCI", regex: /\bPCI(?:-DSS)?\b/i },
  { label: "compliant", regex: /\bcompliant\b/i },
  { label: "compliance", regex: /\bcompliance\b/i },
];

const COMPLIANCE_NEGATION_REGEX =
  /\b(?:no\s+claim|not\s+claim|does\s+not\s+claim|do\s+not\s+claim|not\s+for\s+compliance|not\s+compliance|non-goal|no\s+.*?\s*compliance|not\s+.*?\s*compliant|out\s+of\s+scope)\b/i;

const MATURITY_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "production ready", regex: /\bproduction[- ]ready\b/i },
  { label: "battle-tested", regex: /\bbattle[- ]tested\b/i },
];

const PERF_CLAIM_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  {
    label: "< N ms / sub-ms latency",
    regex:
      /(?:<\s*\d+(?:\.\d+)?\s*(?:ms|milliseconds?|µs|us)\b|\bsub-millisecond\b|\bunder\s+\d+(?:\.\d+)?\s*(?:ms|milliseconds?)\b)/i,
  },
];

const LOCAL_PATH_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  { label: "C:\\Users", regex: /c:\\+users\b/i },
  { label: "C:/Users", regex: /c:\/users\b/i },
  { label: "/Users/", regex: /\/users\//i },
  { label: "/home/", regex: /\/home\//i },
  { label: "file:///", regex: /file:\/\/\//i },
];

const NUMERIC_CLAIM_PATTERNS: Array<{ label: string; regex: RegExp }> = [
  {
    label: "test count claim",
    regex:
      /(?:\b\d+\s*(?:\/\s*\d+\s*)?(?:passing\s+|passed\s+|automated\s+|unit\s+|integration\s+|regression\s+|security\s+|vitest\s+|pytest\s+){0,3}(?:tests?|test\s+cases?|test\s+files?)\b|Tests-\d+(?:%2F\d+)?|\b\d+\s+passed\b)/i,
  },
  {
    label: "percentage claim",
    regex: /(?<!%[0-9A-Fa-f])\b\d+(?:\.\d+)?%(?![0-9A-Fa-f]{2})/,
  },
  {
    label: "latency or duration measurement",
    regex:
      /(?:\b\d+(?:\.\d+)?\s*(?:ms|milliseconds?|µs|microseconds?)\b|\bp(?:50|90|95|99)\s*[:=]\s*\d+(?:\.\d+)?)/i,
  },
  {
    label: "dollar amount claim",
    regex:
      /\$\s*\d+(?:[.,]\d+)?(?:\s*[kKmMbB]\b|\s*(?:thousand|million|billion)\b)?/,
  },
  {
    label: "corpus / benchmark count claim",
    regex:
      /\b\d[\d,]*\+?\s*(?:attack\s+vectors?|attack\s+queries|fuzz\s+cases|differential\s+queries|benchmark\s+iterations|bypass\s+cases)\b/i,
  },
];

const EVIDENCE_TAG_REGEX = /\[E:(CLAIM-\d{3,})\]/g;

export function parseClaimsLedger(
  markdown: string,
  rootDir: string
): { claims: Map<string, ClaimEntry>; violations: LintViolation[] } {
  const claims = new Map<string, ClaimEntry>();
  const violations: LintViolation[] = [];
  const lines = markdown.split(/\r?\n/);

  for (let idx = 0; idx < lines.length; idx++) {
    const raw = lines[idx];
    const trimmed = raw.trim();
    if (!trimmed.startsWith("|")) continue;

    const cells = trimmed
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 6) continue;
    const [id, claimText, location, evidenceType, evidenceRef, statusRaw] =
      cells;

    if (id === "ID" || /^-+$/.test(id.replace(/:/g, ""))) continue;

    if (!/^CLAIM-\d{3,}$/.test(id)) {
      violations.push({
        file: "docs/CLAIMS.md",
        line: idx + 1,
        rule: "ledger-id-format",
        message: `Invalid claim ID '${id}' (expected CLAIM-NNN).`,
        snippet: trimmed,
      });
      continue;
    }

    if (claims.has(id)) {
      violations.push({
        file: "docs/CLAIMS.md",
        line: idx + 1,
        rule: "ledger-duplicate-id",
        message: `Duplicate claim ID '${id}' in ledger.`,
        snippet: trimmed,
      });
      continue;
    }

    if (!VALID_STATUSES.has(statusRaw as ClaimStatus)) {
      violations.push({
        file: "docs/CLAIMS.md",
        line: idx + 1,
        rule: "ledger-invalid-status",
        message: `Invalid status '${statusRaw}' for ${id}.`,
        snippet: trimmed,
      });
      continue;
    }

    const status = statusRaw as ClaimStatus;
    claims.set(id, {
      id,
      claimText,
      location,
      evidenceType,
      evidenceRef,
      status,
      line: idx + 1,
    });

    const cleanRef = evidenceRef.replace(/`/g, "").trim();
    const refPaths = cleanRef
      .split(/[,;]+/)
      .map((s) => s.trim())
      .filter(
        (s) =>
          s.length > 0 &&
          s.toUpperCase() !== "NONE" &&
          s.toUpperCase() !== "REMOVED" &&
          !s.startsWith("http://") &&
          !s.startsWith("https://")
      )
      .map((s) => s.split("#")[0].split(":")[0].trim())
      .filter((s) => /[./\\]/.test(s) || s === "Dockerfile");

    if (status === "SUPPORTED") {
      if (
        evidenceType.toUpperCase() === "NONE" ||
        cleanRef.toUpperCase() === "NONE" ||
        refPaths.length === 0
      ) {
        violations.push({
          file: "docs/CLAIMS.md",
          line: idx + 1,
          rule: "ledger-missing-evidence",
          message: `SUPPORTED claim ${id} must reference at least one existing repo evidence file.`,
          snippet: trimmed,
        });
      }
    }

    if (status !== "REMOVED") {
      for (const relPath of refPaths) {
        const resolved = path.resolve(rootDir, relPath);
        if (!fs.existsSync(resolved)) {
          violations.push({
            file: "docs/CLAIMS.md",
            line: idx + 1,
            rule: "ledger-nonexistent-evidence-file",
            message: `Claim ${id} references '${relPath}', which does not exist.`,
            snippet: trimmed,
          });
        }
      }
    }
  }

  if (claims.size === 0) {
    violations.push({
      file: "docs/CLAIMS.md",
      line: 1,
      rule: "ledger-empty",
      message: "No claim entries found in docs/CLAIMS.md.",
      snippet: "",
    });
  }

  return { claims, violations };
}

export function extractSourceScannableLines(
  source: string
): Array<{ line: number; text: string; isComment: boolean }> {
  const results: Array<{ line: number; text: string; isComment: boolean }> = [];
  const lines = source.split(/\r?\n/);
  let inBlockComment = false;
  let inTemplateLiteral = false;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const raw = lines[lineIdx];
    const lineNum = lineIdx + 1;
    let commentSegments: string[] = [];
    let stringSegments: string[] = [];
    let currentStr = "";
    let currentComment = "";
    let quoteChar: "'" | '"' | null = null;

    let i = 0;
    while (i < raw.length) {
      const ch = raw[i];
      const next = i + 1 < raw.length ? raw[i + 1] : "";

      if (inBlockComment) {
        if (ch === "*" && next === "/") {
          commentSegments.push(currentComment);
          currentComment = "";
          inBlockComment = false;
          i += 2;
        } else {
          currentComment += ch;
          i++;
        }
        continue;
      }

      if (inTemplateLiteral) {
        if (ch === "\\" && i + 1 < raw.length) {
          currentStr += ch + next;
          i += 2;
          continue;
        }
        if (ch === "`") {
          stringSegments.push(currentStr);
          currentStr = "";
          inTemplateLiteral = false;
          i++;
          continue;
        }
        currentStr += ch;
        i++;
        continue;
      }

      if (quoteChar) {
        if (ch === "\\" && i + 1 < raw.length) {
          currentStr += ch + next;
          i += 2;
          continue;
        }
        if (ch === quoteChar) {
          stringSegments.push(currentStr);
          currentStr = "";
          quoteChar = null;
          i++;
          continue;
        }
        currentStr += ch;
        i++;
        continue;
      }

      // Outside comments and quotes
      if (ch === "/" && next === "/") {
        commentSegments.push(raw.slice(i + 2));
        break;
      }
      if (ch === "/" && next === "*") {
        inBlockComment = true;
        i += 2;
        continue;
      }
      if (ch === "'" || ch === '"') {
        quoteChar = ch;
        i++;
        continue;
      }
      if (ch === "`") {
        inTemplateLiteral = true;
        i++;
        continue;
      }
      i++;
    }

    if (inBlockComment && currentComment.length > 0) {
      commentSegments.push(currentComment);
    }
    if (inTemplateLiteral && currentStr.length > 0) {
      stringSegments.push(currentStr);
    }

    if (commentSegments.length > 0) {
      results.push({
        line: lineNum,
        text: commentSegments.join(" "),
        isComment: true,
      });
    }
    if (stringSegments.length > 0) {
      results.push({
        line: lineNum,
        text: stringSegments.join(" "),
        isComment: false,
      });
    }
  }

  return results;
}

export function scanTextContent(options: {
  file: string;
  content: string;
  claims: Map<string, ClaimEntry>;
  mode: "markdown" | "dockerfile" | "typescript";
}): LintViolation[] {
  const { file, content, claims, mode } = options;
  const violations: LintViolation[] = [];
  const normFile = file.replace(/\\/g, "/");

  let linesToScan: Array<{ line: number; text: string; checkNumeric: boolean }> =
    [];

  if (mode === "typescript") {
    linesToScan = extractSourceScannableLines(content).map((item) => ({
      line: item.line,
      text: item.text,
      checkNumeric: item.isComment,
    }));
  } else if (mode === "dockerfile") {
    const rawLines = content.split(/\r?\n/);
    rawLines.forEach((raw, idx) => {
      const trimmed = raw.trim();
      if (trimmed.startsWith("#")) {
        linesToScan.push({
          line: idx + 1,
          text: trimmed.slice(1),
          checkNumeric: true,
        });
      }
    });
  } else {
    const rawLines = content.split(/\r?\n/);
    let inCodeFence = false;
    rawLines.forEach((raw, idx) => {
      const trimmed = raw.trim();
      if (trimmed.startsWith("```")) {
        inCodeFence = !inCodeFence;
        return;
      }
      // In docs/CLAIMS.md, skip table rows whose status is UNSUPPORTED, UNVERIFIED, or REMOVED
      if (normFile === "docs/CLAIMS.md" && trimmed.startsWith("|")) {
        const cells = trimmed
          .split("|")
          .slice(1, -1)
          .map((c) => c.trim());
        if (cells.length >= 6) {
          const rowStatus = cells[5];
          if (
            rowStatus === "UNSUPPORTED" ||
            rowStatus === "UNVERIFIED" ||
            rowStatus === "REMOVED"
          ) {
            return;
          }
          if (rowStatus === "SUPPORTED" || rowStatus === "PARTIAL") {
            linesToScan.push({
              line: idx + 1,
              text: cells[1],
              checkNumeric: false,
            });
            return;
          }
        }
      }
      // In docs/CHANGELOG-CLAIMS.md, skip explicit historical "- Before:" lines
      if (
        normFile === "docs/CHANGELOG-CLAIMS.md" &&
        /^-\s*Before:/i.test(trimmed)
      ) {
        return;
      }

      linesToScan.push({
        line: idx + 1,
        text: raw,
        checkNumeric: !inCodeFence,
      });
    });
  }

  const rawAllLines = content.split(/\r?\n/);
  const headingAtLine = new Map<number, string>();
  if (mode === "markdown") {
    let currentHeading = "";
    rawAllLines.forEach((l, i) => {
      const m = l.match(/^#{1,4}\s+(.+)$/);
      if (m) currentHeading = m[1].trim();
      headingAtLine.set(i + 1, currentHeading);
    });
  }

  for (const item of linesToScan) {
    const { line, text, checkNumeric } = item;

    const tagMatches = [...text.matchAll(EVIDENCE_TAG_REGEX)];
    let hasSupportedEvidenceTag = false;
    for (const match of tagMatches) {
      const claimId = match[1];
      const entry = claims.get(claimId);
      if (!entry) {
        violations.push({
          file: normFile,
          line,
          rule: "unknown-evidence-tag",
          message: `Evidence tag [E:${claimId}] does not exist in docs/CLAIMS.md.`,
          snippet: text.trim(),
        });
      } else if (entry.status !== "SUPPORTED") {
        violations.push({
          file: normFile,
          line,
          rule: "unsupported-evidence-tag",
          message: `Evidence tag [E:${claimId}] resolves to status '${entry.status}' (must be SUPPORTED).`,
          snippet: text.trim(),
        });
      } else {
        hasSupportedEvidenceTag = true;
      }
    }

    for (const pat of ABSOLUTE_PATTERNS) {
      if (pat.regex.test(text)) {
        violations.push({
          file: normFile,
          line,
          rule: "inflated-wording",
          message: `Disallowed absolute/inflated wording matched ('${pat.label}').`,
          snippet: text.trim(),
        });
      }
    }

    for (const pat of TERMINOLOGY_PATTERNS) {
      if (pat.regex.test(text)) {
        violations.push({
          file: normFile,
          line,
          rule: "incorrect-terminology",
          message: `Disallowed inaccurate terminology matched ('${pat.label}').`,
          snippet: text.trim(),
        });
      }
    }

    const currentHeading = headingAtLine.get(line) ?? "";
    const inLimitationsSection = /\blimitations?\b|\bnon-goals?\b/i.test(
      currentHeading
    );
    for (const pat of COMPLIANCE_PATTERNS) {
      if (pat.regex.test(text)) {
        const isExplicitNonClaim =
          inLimitationsSection && COMPLIANCE_NEGATION_REGEX.test(text);
        if (!isExplicitNonClaim) {
          violations.push({
            file: normFile,
            line,
            rule: "compliance-implication",
            message: `Compliance term '${pat.label}' is disallowed outside an explicit non-claim in a Limitations section.`,
            snippet: text.trim(),
          });
        }
      }
    }

    for (const pat of MATURITY_PATTERNS) {
      if (pat.regex.test(text)) {
        violations.push({
          file: normFile,
          line,
          rule: "unearned-maturity",
          message: `Disallowed maturity claim matched ('${pat.label}').`,
          snippet: text.trim(),
        });
      }
    }

    for (const pat of PERF_CLAIM_PATTERNS) {
      if (pat.regex.test(text) && !hasSupportedEvidenceTag) {
        violations.push({
          file: normFile,
          line,
          rule: "unmeasured-performance",
          message: `Performance claim ('${pat.label}') requires a SUPPORTED [E:CLAIM-NNN] benchmark tag on the same line.`,
          snippet: text.trim(),
        });
      }
    }

    for (const pat of LOCAL_PATH_PATTERNS) {
      if (pat.regex.test(text)) {
        violations.push({
          file: normFile,
          line,
          rule: "personal-or-local-path",
          message: `Local or personal path pattern '${pat.label}' found.`,
          snippet: text.trim(),
        });
      }
    }

    if (checkNumeric) {
      for (const pat of NUMERIC_CLAIM_PATTERNS) {
        if (pat.regex.test(text) && !hasSupportedEvidenceTag) {
          violations.push({
            file: normFile,
            line,
            rule: "untagged-numeric-claim",
            message: `Numeric claim (${pat.label}) requires a SUPPORTED [E:CLAIM-NNN] evidence tag on the same line.`,
            snippet: text.trim(),
          });
        }
      }
    }
  }

  return violations;
}

function collectFilesRecursive(dir: string, extFilter: string[]): string[] {
  if (!fs.existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectFilesRecursive(full, extFilter));
    } else if (
      extFilter.some((ext) => entry.name.toLowerCase().endsWith(ext))
    ) {
      out.push(full);
    }
  }
  return out;
}

export function lintRepository(rootDir: string): LintReport {
  const ledgerPath = path.join(rootDir, "docs", "CLAIMS.md");
  if (!fs.existsSync(ledgerPath)) {
    return {
      ok: false,
      claimsCount: 0,
      filesScanned: 0,
      violations: [
        {
          file: "docs/CLAIMS.md",
          line: 1,
          rule: "ledger-missing",
          message: "docs/CLAIMS.md does not exist.",
          snippet: "",
        },
      ],
    };
  }

  const ledgerContent = fs.readFileSync(ledgerPath, "utf8");
  const { claims, violations } = parseClaimsLedger(ledgerContent, rootDir);
  let filesScanned = 0;

  const readmePath = path.join(rootDir, "README.md");
  if (fs.existsSync(readmePath)) {
    filesScanned++;
    violations.push(
      ...scanTextContent({
        file: "README.md",
        content: fs.readFileSync(readmePath, "utf8"),
        claims,
        mode: "markdown",
      })
    );
  }

  const dockerfilePath = path.join(rootDir, "Dockerfile");
  if (fs.existsSync(dockerfilePath)) {
    filesScanned++;
    violations.push(
      ...scanTextContent({
        file: "Dockerfile",
        content: fs.readFileSync(dockerfilePath, "utf8"),
        claims,
        mode: "dockerfile",
      })
    );
  }

  const docFiles = collectFilesRecursive(path.join(rootDir, "docs"), [".md"]);
  for (const docFull of docFiles) {
    const rel = path.relative(rootDir, docFull).replace(/\\/g, "/");
    if (AUDITOR_SPEC_FILES.has(rel)) continue;
    filesScanned++;
    violations.push(
      ...scanTextContent({
        file: rel,
        content: fs.readFileSync(docFull, "utf8"),
        claims,
        mode: "markdown",
      })
    );
  }

  const srcFiles = collectFilesRecursive(path.join(rootDir, "src"), [".ts"]);
  for (const srcFull of srcFiles) {
    const rel = path.relative(rootDir, srcFull).replace(/\\/g, "/");
    filesScanned++;
    violations.push(
      ...scanTextContent({
        file: rel,
        content: fs.readFileSync(srcFull, "utf8"),
        claims,
        mode: "typescript",
      })
    );
  }

  return {
    ok: violations.length === 0,
    claimsCount: claims.size,
    filesScanned,
    violations,
  };
}

const isDirectRun =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) ===
    path.resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  const rootDir = process.cwd();
  const report = lintRepository(rootDir);
  if (!report.ok) {
    console.error(
      `[claims-lint] FAILED with ${report.violations.length} violation(s) across ${report.filesScanned} scanned file(s):`
    );
    for (const v of report.violations) {
      console.error(
        `  - ${v.file}:${v.line} [${v.rule}] ${v.message}\n      > ${v.snippet}`
      );
    }
    process.exit(1);
  }
  console.log(
    `[claims-lint] PASSED (${report.claimsCount} ledger entries, ${report.filesScanned} files scanned, 0 violations).`
  );
}
