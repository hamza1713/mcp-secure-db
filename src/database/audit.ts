import fs from "node:fs";
import path from "node:path";
import { AuditLogEntry, AuditStatus, UserRole } from "../types.js";

/**
 * Sanitizes sensitive literals (emails, tokens, keys, IP addresses) from queries
 * before writing to persistent storage or audit logs.
 */
export function redactSensitiveLiterals(text: string): string {
  if (!text) return text;
  return text
    .replace(
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      "[REDACTED_EMAIL]"
    )
    .replace(
      /\b(cus|sub|ch|tok|whsec|sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9_]{8,}\b/g,
      "[REDACTED_TOKEN]"
    )
    .replace(/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, "Bearer [REDACTED_TOKEN]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "[REDACTED_IP]");
}

export interface AuditLoggerOptions {
  maxSize?: number;
  logFilePath?: string;
  enablePersistence?: boolean;
}

/**
 * Two-tier audit logger:
 * 1. An in-memory ring buffer for low-latency status and stats (non-durable cache).
 * 2. An append-only persistent JSONL file on disk with sensitive literals redacted.
 */
export class AuditLogger {
  private buffer: AuditLogEntry[] = [];
  private maxSize: number;
  private logFilePath: string;
  private persistentLoggingEnabled: boolean;

  constructor(options: number | AuditLoggerOptions = 100) {
    if (typeof options === "number") {
      this.maxSize = options;
      this.logFilePath = path.resolve(process.cwd(), "data", "audit.jsonl");
      this.persistentLoggingEnabled = true;
    } else {
      this.maxSize = options.maxSize ?? 100;
      this.logFilePath =
        options.logFilePath ??
        path.resolve(process.cwd(), "data", "audit.jsonl");
      this.persistentLoggingEnabled = options.enablePersistence ?? true;
    }
  }

  log(entry: Omit<AuditLogEntry, "id" | "timestamp">): AuditLogEntry {
    const redactedQuery = redactSensitiveLiterals(entry.query);
    const ruleFired =
      entry.ruleFired ??
      (entry.status.startsWith("BLOCKED_") ? entry.status : undefined);

    const fullEntry: AuditLogEntry = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      ...entry,
      query: redactedQuery,
      ruleFired,
      persisted: false,
    };

    // Tier 1: In-memory ring buffer (non-durable cache)
    this.buffer.unshift(fullEntry);
    if (this.buffer.length > this.maxSize) {
      this.buffer.pop();
    }

    // Tier 2: Persistent append-only JSONL file on disk
    if (this.persistentLoggingEnabled) {
      try {
        const dir = path.dirname(this.logFilePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        const jsonlLine = JSON.stringify(fullEntry) + "\n";
        fs.appendFileSync(this.logFilePath, jsonlLine, "utf8");
        fullEntry.persisted = true;
      } catch {
        fullEntry.persisted = false;
      }
    }

    return fullEntry;
  }

  getEntries(limit = 50, roleFilter?: UserRole): AuditLogEntry[] {
    let results = this.buffer;
    if (roleFilter) {
      results = results.filter((e) => e.role === roleFilter);
    }
    return results.slice(0, limit);
  }

  getPersistentEntries(limit = 50): AuditLogEntry[] {
    try {
      if (!fs.existsSync(this.logFilePath)) {
        return [];
      }
      const content = fs.readFileSync(this.logFilePath, "utf8");
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
