import os from "node:os";
import { performance } from "node:perf_hooks";
import { SQLValidator } from "../src/security/validator.js";

export interface BenchmarkMetrics {
  iterations: number;
  warmupIterations: number;
  minMs: number;
  p50Ms: number;
  p90Ms: number;
  p95Ms: number;
  p99Ms: number;
  maxMs: number;
  meanMs: number;
  opsPerSec: number;
}

export interface BenchmarkResult {
  environment: {
    nodeVersion: string;
    os: string;
    arch: string;
    cpuModel: string;
    cpuCores: number;
  };
  timestamp: string;
  query: string;
  metrics: BenchmarkMetrics;
}

export const BENCHMARK_QUERIES = [
  {
    name: "simple_projection",
    sql: "SELECT id, name, plan FROM customers",
  },
  {
    name: "filtered_aggregation",
    sql: "SELECT endpoint, COUNT(*), SUM(request_count) FROM api_usage WHERE compute_ms > 100000 GROUP BY endpoint",
  },
  {
    name: "relational_join_with_limit",
    sql: "SELECT c.name, u.endpoint, u.request_count FROM customers c JOIN api_usage u ON c.id = u.customer_id WHERE c.plan = 'enterprise' LIMIT 50",
  },
];

export function runBenchmarkOnQuery(
  validator: SQLValidator,
  sql: string,
  iterations = 10000,
  warmupIterations = 1000
): BenchmarkMetrics {
  // 1. Warm-up JIT
  for (let i = 0; i < warmupIterations; i++) {
    validator.validate(sql, "analyst");
  }

  // 2. Measure sample timings
  const timingsMs = new Float64Array(iterations);
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    validator.validate(sql, "analyst");
    timingsMs[i] = performance.now() - start;
  }

  // 3. Sort for percentiles
  timingsMs.sort();

  const totalMs = timingsMs.reduce((acc, t) => acc + t, 0);
  const minMs = Math.round(timingsMs[0] * 1000) / 1000;
  const maxMs = Math.round(timingsMs[timingsMs.length - 1] * 1000) / 1000;
  const meanMs = Math.round((totalMs / iterations) * 1000) / 1000;
  const p50Ms = Math.round(timingsMs[Math.floor(iterations * 0.5)] * 1000) / 1000;
  const p90Ms = Math.round(timingsMs[Math.floor(iterations * 0.9)] * 1000) / 1000;
  const p95Ms = Math.round(timingsMs[Math.floor(iterations * 0.95)] * 1000) / 1000;
  const p99Ms = Math.round(timingsMs[Math.floor(iterations * 0.99)] * 1000) / 1000;
  const opsPerSec = Math.round((iterations / (totalMs / 1000)) * 10) / 10;

  return {
    iterations,
    warmupIterations,
    minMs,
    p50Ms,
    p90Ms,
    p95Ms,
    p99Ms,
    maxMs,
    meanMs,
    opsPerSec,
  };
}

export function executeFullBenchmarkSuite(
  iterations = 10000,
  warmupIterations = 1000
): BenchmarkResult[] {
  const validator = new SQLValidator();
  const cpus = os.cpus();
  const cpuModel = cpus.length > 0 ? cpus[0].model : "unknown";

  const results: BenchmarkResult[] = [];
  for (const q of BENCHMARK_QUERIES) {
    const metrics = runBenchmarkOnQuery(
      validator,
      q.sql,
      iterations,
      warmupIterations
    );
    results.push({
      environment: {
        nodeVersion: process.version,
        os: `${os.type()} ${os.release()}`,
        arch: process.arch,
        cpuModel,
        cpuCores: cpus.length,
      },
      timestamp: new Date().toISOString(),
      query: q.sql,
      metrics,
    });
  }
  return results;
}
