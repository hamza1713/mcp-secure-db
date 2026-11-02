import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import {
  executeFullBenchmarkSuite,
  BenchmarkResult,
} from "../bench/validator.bench.js";

describe("Reproducible Performance Benchmark Harness", () => {
  it(
    "executes the benchmark suite (1,000 warmup + 10,000 iterations per query) and records percentiles",
    () => {
    const results: BenchmarkResult[] = executeFullBenchmarkSuite(10000, 1000);
    expect(results.length).toBe(3);

    for (const res of results) {
      expect(res.metrics.iterations).toBe(10000);
      expect(res.metrics.warmupIterations).toBe(1000);
      expect(res.metrics.p50Ms).toBeGreaterThan(0);
      expect(res.metrics.p95Ms).toBeGreaterThanOrEqual(res.metrics.p50Ms);
      expect(res.metrics.p99Ms).toBeGreaterThanOrEqual(res.metrics.p95Ms);
      expect(res.metrics.opsPerSec).toBeGreaterThan(100);
    }

    const outPath = path.join(process.cwd(), "bench", "results.json");
    fs.writeFileSync(outPath, JSON.stringify(results, null, 2), "utf8");
    expect(fs.existsSync(outPath)).toBe(true);

    const simple = results[0];
    console.log(
      `[Benchmark Output] Query: "${simple.query}" | p50: ${simple.metrics.p50Ms}ms | p90: ${simple.metrics.p90Ms}ms | p95: ${simple.metrics.p95Ms}ms | p99: ${simple.metrics.p99Ms}ms | mean: ${simple.metrics.meanMs}ms | ${simple.metrics.opsPerSec} ops/sec`
    );
  }, 45000);
});
