import { AuditStatus, SqliteWorkerPoolStats, UserRole } from "../types.js";

const VALIDATION_BUCKETS_MS = [0.25, 0.5, 1, 2.5, 5, 10, 25, 50, 100];
const EXECUTION_BUCKETS_MS = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000];

const SAFE_LABEL_VALUE_REGEX = /^[a-zA-Z0-9_.:/-]{1,64}$/;

function sanitizeLabel(value: string, fallback = "other"): string {
  const trimmed = value.trim();
  if (!trimmed || !SAFE_LABEL_VALUE_REGEX.test(trimmed)) {
    return fallback;
  }
  return trimmed.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "");
}

function formatLabels(labels: Record<string, string>): string {
  const entries = Object.entries(labels);
  if (entries.length === 0) return "";
  const inner = entries
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${sanitizeLabel(v)}"`)
    .join(",");
  return `{${inner}}`;
}

interface HistogramState {
  buckets: readonly number[];
  counts: number[];
  sum: number;
  count: number;
}

function createHistogram(buckets: readonly number[]): HistogramState {
  return {
    buckets,
    counts: new Array(buckets.length).fill(0),
    sum: 0,
    count: 0,
  };
}

function observeHistogram(hist: HistogramState, valueMs: number): void {
  const v = Number.isFinite(valueMs) && valueMs >= 0 ? valueMs : 0;
  hist.count += 1;
  hist.sum += v;
  for (let i = 0; i < hist.buckets.length; i++) {
    if (v <= hist.buckets[i]) {
      hist.counts[i] += 1;
    }
  }
}

function renderHistogram(
  name: string,
  help: string,
  hist: HistogramState
): string[] {
  const lines: string[] = [
    `# HELP ${name} ${help}`,
    `# TYPE ${name} histogram`,
  ];
  for (let i = 0; i < hist.buckets.length; i++) {
    lines.push(`${name}_bucket{le="${hist.buckets[i]}"} ${hist.counts[i]}`);
  }
  lines.push(`${name}_bucket{le="+Inf"} ${hist.count}`);
  lines.push(`${name}_sum ${Math.round(hist.sum * 1000) / 1000}`);
  lines.push(`${name}_count ${hist.count}`);
  return lines;
}

export type SecurityBlockLayer =
  | "rbac"
  | "ast"
  | "rate_limit"
  | "authorizer"
  | "result_policy"
  | "tenant_isolation"
  | "timeout";

/**
 * Zero-dependency Prometheus text-exposition metrics registry.
 * Enforces strict low-cardinality labels (never emits raw SQL, principals, or PII).
 */
export class MetricsRegistry {
  private requestCounters = new Map<string, number>();
  private blockCounters = new Map<string, number>();
  private rowsReturnedCounters = new Map<string, number>();
  private workerTerminations = 0;
  private validationHistogram = createHistogram(VALIDATION_BUCKETS_MS);
  private executionHistogram = createHistogram(EXECUTION_BUCKETS_MS);
  private auditChainSeq = 0;
  private poolStats: SqliteWorkerPoolStats | null = null;
  private readonly startedAtEpochSec = Math.floor(Date.now() / 1000);

  public incRequest(
    method: string,
    tool: string,
    role: UserRole,
    status: string
  ): void {
    const key = formatLabels({ method, tool, role, status });
    this.requestCounters.set(key, (this.requestCounters.get(key) ?? 0) + 1);
  }

  public incBlock(
    layer: SecurityBlockLayer,
    role: UserRole,
    status: AuditStatus | string
  ): void {
    const key = formatLabels({ layer, role, status });
    this.blockCounters.set(key, (this.blockCounters.get(key) ?? 0) + 1);
  }

  public addRowsReturned(role: UserRole, tool: string, rowCount: number): void {
    const count = Math.max(0, Math.trunc(rowCount));
    const key = formatLabels({ role, tool });
    this.rowsReturnedCounters.set(
      key,
      (this.rowsReturnedCounters.get(key) ?? 0) + count
    );
  }

  public incWorkerTermination(): void {
    this.workerTerminations += 1;
  }

  public observeValidationDurationMs(durationMs: number): void {
    observeHistogram(this.validationHistogram, durationMs);
  }

  public observeExecutionDurationMs(durationMs: number): void {
    observeHistogram(this.executionHistogram, durationMs);
  }

  public setAuditChainSeq(seq: number): void {
    this.auditChainSeq = Math.max(0, Math.trunc(seq));
  }

  public setSqlitePoolStats(stats: SqliteWorkerPoolStats | null): void {
    this.poolStats = stats;
  }

  public renderPrometheus(): string {
    const lines: string[] = [];

    lines.push(
      "# HELP mcp_secure_db_process_start_time_seconds Unix timestamp when the gateway instance started.",
      "# TYPE mcp_secure_db_process_start_time_seconds gauge",
      `mcp_secure_db_process_start_time_seconds ${this.startedAtEpochSec}`
    );

    lines.push(
      "# HELP mcp_secure_db_requests_total Total MCP tool/resource requests processed.",
      "# TYPE mcp_secure_db_requests_total counter"
    );
    for (const [labels, val] of [...this.requestCounters.entries()].sort()) {
      lines.push(`mcp_secure_db_requests_total${labels} ${val}`);
    }

    lines.push(
      "# HELP mcp_secure_db_blocks_total Total security blocks by defense layer, role, and audit status.",
      "# TYPE mcp_secure_db_blocks_total counter"
    );
    for (const [labels, val] of [...this.blockCounters.entries()].sort()) {
      lines.push(`mcp_secure_db_blocks_total${labels} ${val}`);
    }

    lines.push(
      "# HELP mcp_secure_db_rows_returned_total Cumulative rows returned to authorized callers.",
      "# TYPE mcp_secure_db_rows_returned_total counter"
    );
    for (const [labels, val] of [...this.rowsReturnedCounters.entries()].sort()) {
      lines.push(`mcp_secure_db_rows_returned_total${labels} ${val}`);
    }

    lines.push(
      "# HELP mcp_secure_db_worker_terminations_total Total SQLite worker threads forcibly terminated on query deadline.",
      "# TYPE mcp_secure_db_worker_terminations_total counter",
      `mcp_secure_db_worker_terminations_total ${this.workerTerminations}`
    );

    lines.push(
      ...renderHistogram(
        "mcp_secure_db_validation_duration_ms",
        "Pre-execution AST SQL validation duration in milliseconds.",
        this.validationHistogram
      )
    );

    lines.push(
      ...renderHistogram(
        "mcp_secure_db_execution_duration_ms",
        "Database query execution duration in milliseconds.",
        this.executionHistogram
      )
    );

    lines.push(
      "# HELP mcp_secure_db_audit_chain_seq Current monotonic sequence number of the hash-chained audit log.",
      "# TYPE mcp_secure_db_audit_chain_seq gauge",
      `mcp_secure_db_audit_chain_seq ${this.auditChainSeq}`
    );

    if (this.poolStats) {
      lines.push(
        "# HELP mcp_secure_db_sqlite_pool_workers SQLite worker pool capacity and live utilization.",
        "# TYPE mcp_secure_db_sqlite_pool_workers gauge",
        `mcp_secure_db_sqlite_pool_workers{state="pool_size"} ${this.poolStats.poolSize}`,
        `mcp_secure_db_sqlite_pool_workers{state="active"} ${this.poolStats.activeWorkers}`,
        `mcp_secure_db_sqlite_pool_workers{state="busy"} ${this.poolStats.busyWorkers}`,
        `mcp_secure_db_sqlite_pool_workers{state="queued"} ${this.poolStats.queuedQueries}`
      );
    }

    return lines.join("\n") + "\n";
  }

  public reset(): void {
    this.requestCounters.clear();
    this.blockCounters.clear();
    this.rowsReturnedCounters.clear();
    this.workerTerminations = 0;
    this.validationHistogram = createHistogram(VALIDATION_BUCKETS_MS);
    this.executionHistogram = createHistogram(EXECUTION_BUCKETS_MS);
    this.auditChainSeq = 0;
    this.poolStats = null;
  }
}

export const metricsRegistry = new MetricsRegistry();
