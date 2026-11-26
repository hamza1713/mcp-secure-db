import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { AuditLogEntry, UserRole } from "../types.js";

const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024; // 10 MiB rotation threshold
const DEFAULT_TAIL_READ_BYTES = 256 * 1024; // 256 KiB tail-chunk read bound
export const AUDIT_GENESIS_HASH = "0".repeat(64);
const HEX_SHA256_REGEX = /^[0-9a-f]{64}$/;

/**
 * Sanitizes sensitive literals (emails, SSNs, JWTs, tokens, keys, IP addresses)
 * from queries and error reasons before writing to persistent audit logs.
 */
export function redactSensitiveLiterals(text: string): string {
  if (!text) return text;
  return text
    .replace(
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi,
      "[REDACTED_EMAIL]"
    )
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_SSN]")
    .replace(
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      "[REDACTED_JWT]"
    )
    .replace(
      /\b(?:cus|sub|ch|tok|whsec|sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9_]{4,}\b/gi,
      "[REDACTED_TOKEN]"
    )
    .replace(
      /\b(?:(?:stripe|gemini|aws|redis|gcp|azure|openai|anthropic)[-_](?:mock[-_])?(?:secret|key|token)[-_][A-Za-z0-9_-]{4,}|token-(?:viewer|analyst|admin)-demo|gh[po]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b/gi,
      "[REDACTED_TOKEN]"
    )
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, "Bearer [REDACTED_TOKEN]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_IP]");
}

/**
 * Builds a deterministic JSON representation of an audit entry (sorted keys,
 * omitting `entryHash` and `persisted` so in-memory and disk records share the
 * exact same verifiable digest).
 */
export function canonicalAuditPayload(entry: Record<string, unknown>): string {
  const keys = Object.keys(entry)
    .filter((k) => k !== "entryHash" && k !== "persisted" && entry[k] !== undefined)
    .sort();
  const sorted: Record<string, unknown> = {};
  for (const k of keys) {
    sorted[k] = entry[k];
  }
  return JSON.stringify(sorted);
}

export function computeAuditEntryHash(
  entry: Record<string, unknown>,
  hmacKey?: string
): { hash: string; algorithm: "sha256" | "hmac-sha256" } {
  const payload = canonicalAuditPayload(entry);
  if (hmacKey && hmacKey.length > 0) {
    const hash = crypto
      .createHmac("sha256", hmacKey)
      .update(payload, "utf8")
      .digest("hex");
    return { hash, algorithm: "hmac-sha256" };
  }
  const hash = crypto.createHash("sha256").update(payload, "utf8").digest("hex");
  return { hash, algorithm: "sha256" };
}

export interface AuditChainVerificationOptions {
  hmacKey?: string;
  expectedPrevHash?: string;
  expectedStartSeq?: number;
}

export interface AuditChainVerificationResult {
  valid: boolean;
  filePath: string;
  totalEntries: number;
  firstSeq: number | null;
  lastSeq: number | null;
  lastHash: string | null;
  algorithm: "sha256" | "hmac-sha256" | "mixed" | "none";
  failureLine?: number;
  failureSeq?: number;
  error?: string;
}

/**
 * Cryptographically verifies a JSONL audit log file line-by-line, checking
 * JSON integrity, monotonic sequence continuity, prevHash chaining, and
 * constant-time SHA-256 or HMAC-SHA256 digest equality.
 */
export function verifyAuditLogFile(
  filePath: string,
  options: AuditChainVerificationOptions = {}
): AuditChainVerificationResult {
  const absPath = path.resolve(filePath);
  const hmacKey =
    options.hmacKey ?? (process.env.MCP_SECURE_DB_AUDIT_HMAC_KEY?.trim() || undefined);

  if (!fs.existsSync(absPath)) {
    return {
      valid: false,
      filePath: absPath,
      totalEntries: 0,
      firstSeq: null,
      lastSeq: null,
      lastHash: null,
      algorithm: "none",
      error: `Audit log file not found at '${absPath}'.`,
    };
  }

  const raw = fs.readFileSync(absPath, "utf8");
  const rawLines = raw.split(/\r?\n/);
  // Trim trailing empty line(s) caused by final newline
  while (rawLines.length > 0 && rawLines[rawLines.length - 1] === "") {
    rawLines.pop();
  }

  if (rawLines.length === 0) {
    return {
      valid: true,
      filePath: absPath,
      totalEntries: 0,
      firstSeq: null,
      lastSeq: null,
      lastHash: null,
      algorithm: "none",
    };
  }

  let expectedSeq = options.expectedStartSeq ?? 1;
  let expectedPrevHash = options.expectedPrevHash ?? AUDIT_GENESIS_HASH;
  let firstSeq: number | null = null;
  let lastSeq: number | null = null;
  let lastHash: string | null = null;
  const algsSeen = new Set<"sha256" | "hmac-sha256">();

  for (let i = 0; i < rawLines.length; i++) {
    const lineNum = i + 1;
    const line = rawLines[i];
    if (line.trim().length === 0) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        error: `Unexpected blank line at line ${lineNum} (possible truncation or manual edit).`,
      };
    }

    let entry: AuditLogEntry;
    try {
      entry = JSON.parse(line) as AuditLogEntry;
    } catch (err: any) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        error: `Invalid JSON at line ${lineNum}: ${err.message}`,
      };
    }

    if (
      typeof entry.seq !== "number" ||
      !Number.isInteger(entry.seq) ||
      entry.seq < 1
    ) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        error: `Missing or invalid sequence number 'seq' at line ${lineNum}.`,
      };
    }

    if (
      typeof entry.prevHash !== "string" ||
      !HEX_SHA256_REGEX.test(entry.prevHash) ||
      typeof entry.entryHash !== "string" ||
      !HEX_SHA256_REGEX.test(entry.entryHash)
    ) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        failureSeq: entry.seq,
        error: `Missing or malformed hex hash fields at line ${lineNum} (seq ${entry.seq}).`,
      };
    }

    // Line 1 of a rotated segment begins with ROTATION_ANCHOR linking prior segment's lastHash
    if (
      i === 0 &&
      entry.status === "ROTATION_ANCHOR" &&
      entry.seq > 1 &&
      options.expectedStartSeq === undefined
    ) {
      expectedSeq = entry.seq;
      if (options.expectedPrevHash === undefined) {
        expectedPrevHash = entry.prevHash;
      }
    }

    if (entry.seq !== expectedSeq) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        failureSeq: entry.seq,
        error: `Sequence discontinuity at line ${lineNum}: expected seq ${expectedSeq}, found seq ${entry.seq}.`,
      };
    }

    if (entry.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        failureSeq: entry.seq,
        error: `Hash chain break at line ${lineNum} (seq ${entry.seq}): prevHash does not match prior entryHash.`,
      };
    }

    const declaredAlg = entry.hashAlg ?? "sha256";
    if (declaredAlg === "hmac-sha256" && !hmacKey) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        failureSeq: entry.seq,
        error: `Entry at line ${lineNum} (seq ${entry.seq}) uses hmac-sha256 and requires MCP_SECURE_DB_AUDIT_HMAC_KEY to verify.`,
      };
    }

    const effectiveKey = declaredAlg === "hmac-sha256" ? hmacKey : undefined;
    const { hash: recomputed } = computeAuditEntryHash(
      entry as unknown as Record<string, unknown>,
      effectiveKey
    );

    const expectedBuf = Buffer.from(recomputed, "hex");
    const actualBuf = Buffer.from(entry.entryHash, "hex");
    if (
      expectedBuf.length !== actualBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, actualBuf)
    ) {
      return {
        valid: false,
        filePath: absPath,
        totalEntries: i,
        firstSeq,
        lastSeq,
        lastHash,
        algorithm:
          algsSeen.size === 0
            ? "none"
            : algsSeen.size === 1
              ? [...algsSeen][0]
              : "mixed",
        failureLine: lineNum,
        failureSeq: entry.seq,
        error: `Digest mismatch at line ${lineNum} (seq ${entry.seq}): entry content was modified or HMAC key is incorrect.`,
      };
    }

    algsSeen.add(declaredAlg);
    if (firstSeq === null) firstSeq = entry.seq;
    lastSeq = entry.seq;
    lastHash = entry.entryHash;
    expectedSeq = entry.seq + 1;
    expectedPrevHash = entry.entryHash;
  }

  return {
    valid: true,
    filePath: absPath,
    totalEntries: rawLines.length,
    firstSeq,
    lastSeq,
    lastHash,
    algorithm:
      algsSeen.size === 0
        ? "none"
        : algsSeen.size === 1
          ? [...algsSeen][0]
          : "mixed",
  };
}

export interface AuditLoggerOptions {
  maxSize?: number;
  logFilePath?: string;
  enablePersistence?: boolean;
  maxFileBytes?: number;
  tailReadBytes?: number;
  hmacKey?: string;
}

/**
 * Two-tier tamper-evident audit logger:
 * 1. An in-memory ring buffer for low-latency status and stats (non-durable cache).
 * 2. An append-only persistent JSONL file on disk with sensitive literal redaction,
 *    SHA-256 (or keyed HMAC-SHA256) hash-chaining, restart chain resumption,
 *    rotation anchor linking, and bounded tail-chunk reads.
 */
export class AuditLogger {
  private buffer: AuditLogEntry[] = [];
  private maxSize: number;
  private logFilePath: string;
  private persistentLoggingEnabled: boolean;
  private maxFileBytes: number;
  private tailReadBytes: number;
  private hmacKey?: string;
  private dirEnsured = false;
  private persistenceFailureWarned = false;
  private chainInitialized = false;
  private lastSeq = 0;
  private lastHash = AUDIT_GENESIS_HASH;

  constructor(options: number | AuditLoggerOptions = 100) {
    const envPath = process.env.MCP_SECURE_DB_AUDIT_PATH?.trim();
    const defaultPath = envPath
      ? path.resolve(envPath)
      : path.resolve(process.cwd(), "data", "audit.jsonl");
    const envHmac = process.env.MCP_SECURE_DB_AUDIT_HMAC_KEY?.trim() || undefined;

    if (typeof options === "number") {
      this.maxSize = options;
      this.logFilePath = defaultPath;
      this.persistentLoggingEnabled = true;
      this.maxFileBytes = DEFAULT_MAX_FILE_BYTES;
      this.tailReadBytes = DEFAULT_TAIL_READ_BYTES;
      this.hmacKey = envHmac;
    } else {
      this.maxSize = options.maxSize ?? 100;
      this.logFilePath = options.logFilePath ?? defaultPath;
      this.persistentLoggingEnabled = options.enablePersistence ?? true;
      this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
      this.tailReadBytes = options.tailReadBytes ?? DEFAULT_TAIL_READ_BYTES;
      this.hmacKey =
        options.hmacKey !== undefined
          ? options.hmacKey.trim() || undefined
          : envHmac;
    }
  }

  private ensureChainInitialized(): void {
    if (this.chainInitialized) return;
    this.chainInitialized = true;

    if (!this.persistentLoggingEnabled) return;
    try {
      const existing = this.getPersistentEntries(1);
      if (existing.length > 0) {
        const last = existing[0];
        if (
          typeof last.seq === "number" &&
          Number.isInteger(last.seq) &&
          last.seq >= 1 &&
          typeof last.entryHash === "string" &&
          HEX_SHA256_REGEX.test(last.entryHash)
        ) {
          this.lastSeq = last.seq;
          this.lastHash = last.entryHash;
        }
      }
    } catch {
      // Fall back to genesis chain state if prior file cannot be read
    }
  }

  private signEntry(
    baseEntry: Omit<AuditLogEntry, "seq" | "prevHash" | "entryHash" | "hashAlg">
  ): AuditLogEntry {
    const seq = this.lastSeq + 1;
    const prevHash = this.lastHash;
    const hashAlg: "sha256" | "hmac-sha256" = this.hmacKey
      ? "hmac-sha256"
      : "sha256";

    const unsigned: AuditLogEntry = {
      ...baseEntry,
      seq,
      prevHash,
      hashAlg,
    };
    const { hash } = computeAuditEntryHash(
      unsigned as unknown as Record<string, unknown>,
      this.hmacKey
    );
    const signed: AuditLogEntry = {
      ...unsigned,
      entryHash: hash,
    };
    this.lastSeq = seq;
    this.lastHash = hash;
    return signed;
  }

  private rotateIfNeeded(): void {
    try {
      const stat = fs.statSync(this.logFilePath);
      if (stat.size >= this.maxFileBytes) {
        const rotatedPath = `${this.logFilePath}.1`;
        if (fs.existsSync(rotatedPath)) {
          fs.unlinkSync(rotatedPath);
        }
        fs.renameSync(this.logFilePath, rotatedPath);

        // Anchor the fresh segment cryptographically to the final hash of the rotated file
        const anchor = this.signEntry({
          id: `audit_rot_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
          timestamp: new Date().toISOString(),
          principal: "system",
          role: "admin",
          query: "[AUDIT_LOG_ROTATION]",
          status: "ROTATION_ANCHOR",
          reason: `Rotated prior audit segment to ${path.basename(rotatedPath)}`,
          persisted: true,
        });
        fs.appendFileSync(
          this.logFilePath,
          JSON.stringify({ ...anchor, persisted: true }) + "\n",
          "utf8"
        );
      }
    } catch {
      // File may not exist yet; safe to ignore
    }
  }

  log(
    entry: Omit<
      AuditLogEntry,
      "id" | "timestamp" | "seq" | "prevHash" | "entryHash" | "hashAlg"
    >
  ): AuditLogEntry {
    this.ensureChainInitialized();

    const redactedQuery = redactSensitiveLiterals(entry.query);
    const redactedReason =
      typeof entry.reason === "string"
        ? redactSensitiveLiterals(entry.reason)
        : undefined;
    const ruleFired =
      entry.ruleFired ??
      (entry.status.startsWith("BLOCKED_") ? entry.status : undefined);

    const baseEntry: Omit<
      AuditLogEntry,
      "seq" | "prevHash" | "entryHash" | "hashAlg"
    > = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      ...entry,
      query: redactedQuery,
      ...(redactedReason !== undefined ? { reason: redactedReason } : {}),
      ruleFired,
      persisted: false,
    };

    // Tier 2: Check rotation BEFORE signing this entry so seq/prevHash align cleanly
    if (this.persistentLoggingEnabled) {
      try {
        if (!this.dirEnsured) {
          const dir = path.dirname(this.logFilePath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          this.dirEnsured = true;
        }
        this.rotateIfNeeded();
      } catch {
        // Handled during append below
      }
    }

    const fullEntry = this.signEntry(baseEntry);

    // Tier 1: In-memory ring buffer (non-durable cache)
    this.buffer.unshift(fullEntry);
    if (this.buffer.length > this.maxSize) {
      this.buffer.pop();
    }

    if (this.persistentLoggingEnabled) {
      try {
        const persistedRecord: AuditLogEntry = {
          ...fullEntry,
          persisted: true,
        };
        const jsonlLine = JSON.stringify(persistedRecord) + "\n";
        fs.appendFileSync(this.logFilePath, jsonlLine, "utf8");
        fullEntry.persisted = true;
      } catch (err: any) {
        fullEntry.persisted = false;
        this.dirEnsured = false;
        if (!this.persistenceFailureWarned) {
          this.persistenceFailureWarned = true;
          console.error(
            `[mcp-secure-db] Audit log persistence failed for '${this.logFilePath}': ${err?.message ?? err}`
          );
        }
      }
    }

    return fullEntry;
  }

  getChainState(): {
    seq: number;
    lastHash: string;
    algorithm: "sha256" | "hmac-sha256";
  } {
    this.ensureChainInitialized();
    return {
      seq: this.lastSeq,
      lastHash: this.lastHash,
      algorithm: this.hmacKey ? "hmac-sha256" : "sha256",
    };
  }

  verifyFile(): AuditChainVerificationResult {
    return verifyAuditLogFile(this.logFilePath, { hmacKey: this.hmacKey });
  }

  getEntries(limit = 50, roleFilter?: UserRole): AuditLogEntry[] {
    let results = this.buffer;
    if (roleFilter) {
      results = results.filter((e) => e.role === roleFilter);
    }
    return results.slice(0, limit);
  }

  /**
   * Reads the most recent audit entries from disk using a bounded tail chunk
   * instead of loading the entire log file into memory.
   */
  getPersistentEntries(limit = 50): AuditLogEntry[] {
    let fd: number | null = null;
    try {
      if (!fs.existsSync(this.logFilePath)) {
        return [];
      }
      fd = fs.openSync(this.logFilePath, "r");
      const stat = fs.fstatSync(fd);
      if (stat.size === 0) {
        return [];
      }

      const bytesToRead = Math.min(stat.size, this.tailReadBytes);
      const startOffset = stat.size - bytesToRead;
      const buf = Buffer.allocUnsafe(bytesToRead);
      const bytesRead = fs.readSync(fd, buf, 0, bytesToRead, startOffset);
      let content = buf.subarray(0, bytesRead).toString("utf8");

      // If we started mid-file, drop the potentially partial first line
      if (startOffset > 0) {
        const firstNewline = content.indexOf("\n");
        if (firstNewline >= 0) {
          content = content.slice(firstNewline + 1);
        }
      }

      const lines = content
        .trim()
        .split("\n")
        .filter((l) => l.trim().length > 0);
      const parsed: AuditLogEntry[] = [];
      for (let i = lines.length - 1; i >= 0 && parsed.length < limit; i--) {
        try {
          parsed.push(JSON.parse(lines[i]));
        } catch {
          // ignore malformed line
        }
      }
      return parsed;
    } catch {
      return [];
    } finally {
      if (fd !== null) {
        try {
          fs.closeSync(fd);
        } catch {
          // ignore close error
        }
      }
    }
  }

  getStats(): {
    total: number;
    success: number;
    blockedAuth: number;
    blockedRbac: number;
    blockedAst: number;
    blockedAuthorizer: number;
    blockedResultPolicy: number;
    blockedRateLimit: number;
    timeouts: number;
    errors: number;
  } {
    return {
      total: this.buffer.length,
      success: this.buffer.filter((e) => e.status === "SUCCESS").length,
      blockedAuth: this.buffer.filter((e) => e.status === "BLOCKED_AUTH")
        .length,
      blockedRbac: this.buffer.filter((e) => e.status === "BLOCKED_RBAC")
        .length,
      blockedAst: this.buffer.filter((e) => e.status === "BLOCKED_AST").length,
      blockedAuthorizer: this.buffer.filter(
        (e) => e.status === "BLOCKED_AUTHORIZER"
      ).length,
      blockedResultPolicy: this.buffer.filter(
        (e) => e.status === "BLOCKED_RESULT_POLICY"
      ).length,
      blockedRateLimit: this.buffer.filter(
        (e) => e.status === "BLOCKED_RATE_LIMIT"
      ).length,
      timeouts: this.buffer.filter((e) => e.status === "TIMEOUT").length,
      errors: this.buffer.filter((e) => e.status === "ERROR").length,
    };
  }

  getLogFilePath(): string {
    return this.logFilePath;
  }

  clear(): void {
    this.buffer = [];
  }
}

export const auditLogger = new AuditLogger();
