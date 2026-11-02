import { AuditLogEntry, UserRole } from "../types.js";

export class AuditLogger {
  private buffer: AuditLogEntry[] = [];
  private maxSize: number;

  constructor(maxSize = 100) {
    this.maxSize = maxSize;
  }

  log(entry: Omit<AuditLogEntry, "id" | "timestamp">): AuditLogEntry {
    const fullEntry: AuditLogEntry = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      ...entry,
    };

    this.buffer.unshift(fullEntry);
    if (this.buffer.length > this.maxSize) {
      this.buffer.pop();
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

  getStats(): {
    total: number;
    success: number;
    blockedRbac: number;
    blockedAst: number;
    timeouts: number;
    errors: number;
  } {
    return {
      total: this.buffer.length,
      success: this.buffer.filter((e) => e.status === "SUCCESS").length,
      blockedRbac: this.buffer.filter((e) => e.status === "BLOCKED_RBAC").length,
      blockedAst: this.buffer.filter((e) => e.status === "BLOCKED_AST").length,
      timeouts: this.buffer.filter((e) => e.status === "TIMEOUT").length,
      errors: this.buffer.filter((e) => e.status === "ERROR").length,
    };
  }

  clear(): void {
    this.buffer = [];
  }
}

export const auditLogger = new AuditLogger();
