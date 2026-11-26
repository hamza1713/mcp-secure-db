import crypto from "node:crypto";
import { redactSensitiveLiterals } from "../database/audit.js";

export type LogLevel = "info" | "warn" | "error";

const LEVEL_RANK: Record<LogLevel, number> = {
  info: 1,
  warn: 2,
  error: 3,
};

export interface StructuredLogEvent {
  event: string;
  requestId?: string;
  role?: string;
  tenantId?: string;
  tool?: string;
  status?: string;
  durationMs?: number;
  rowCount?: number;
  detail?: string;
}

export function generateRequestId(): string {
  return `req_${Date.now().toString(36)}_${crypto.randomBytes(4).toString("hex")}`;
}

export interface StructuredLoggerOptions {
  enabled?: boolean;
  minLevel?: LogLevel;
  sink?: (line: string) => void;
}

/**
 * Lightweight zero-dependency NDJSON structured logger.
 * Writes strictly to `process.stderr` (or an injected test sink) so `stdio`
 * MCP JSON-RPC frames on `stdout` are never corrupted.
 */
export class StructuredLogger {
  private readonly explicitEnabled?: boolean;
  private readonly minLevel: LogLevel;
  private readonly sink: (line: string) => void;

  constructor(options: StructuredLoggerOptions = {}) {
    this.explicitEnabled = options.enabled;
    const envLevel = (process.env.MCP_SECURE_DB_LOG_LEVEL ?? "info").toLowerCase();
    this.minLevel =
      options.minLevel ??
      (envLevel === "warn" || envLevel === "error" ? envLevel : "info");
    this.sink =
      options.sink ??
      ((line: string) => {
        process.stderr.write(line + "\n");
      });
  }

  private isEnabled(): boolean {
    if (this.explicitEnabled !== undefined) {
      return this.explicitEnabled;
    }
    const fmt = process.env.MCP_SECURE_DB_LOG_FORMAT?.trim().toLowerCase();
    if (fmt === "off" || fmt === "none" || fmt === "false") {
      return false;
    }
    if (fmt === "json") {
      return true;
    }
    // Keep Vitest test runs quiet unless explicitly opted in
    return process.env.VITEST !== "true";
  }

  public log(level: LogLevel, payload: StructuredLogEvent): void {
    if (!this.isEnabled()) return;
    if (LEVEL_RANK[level] < LEVEL_RANK[this.minLevel]) return;

    const record: Record<string, unknown> = {
      timestamp: new Date().toISOString(),
      level,
      service: "mcp-secure-db",
      event: payload.event,
    };

    if (payload.requestId) record.requestId = payload.requestId;
    if (payload.role) record.role = payload.role;
    if (payload.tenantId) record.tenantId = payload.tenantId;
    if (payload.tool) record.tool = payload.tool;
    if (payload.status) record.status = payload.status;
    if (payload.durationMs !== undefined) record.durationMs = payload.durationMs;
    if (payload.rowCount !== undefined) record.rowCount = payload.rowCount;
    if (payload.detail) {
      record.detail = redactSensitiveLiterals(payload.detail);
    }

    this.sink(JSON.stringify(record));
  }

  public info(payload: StructuredLogEvent): void {
    this.log("info", payload);
  }

  public warn(payload: StructuredLogEvent): void {
    this.log("warn", payload);
  }

  public error(payload: StructuredLogEvent): void {
    this.log("error", payload);
  }
}

export const structuredLogger = new StructuredLogger();
