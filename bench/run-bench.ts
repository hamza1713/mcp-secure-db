import fs from "node:fs";
import path from "node:path";
import { executeFullBenchmarkSuite } from "./validator.bench.js";

const results = executeFullBenchmarkSuite(10000, 1000);
const outPath = path.join(process.cwd(), "bench", "results.json");
fs.writeFileSync(outPath, JSON.stringify(results, null, 2), "utf8");

console.log("=== MCP-SECURE-DB VALIDATOR BENCHMARK RESULTS ===");
console.log(`Environment: Node ${results[0].environment.nodeVersion} (${results[0].environment.os}, ${results[0].environment.cpuModel}, ${results[0].environment.cpuCores} cores)`);
console.log(`Method: 1,000 warmup iterations + 10,000 timed iterations per query`);
console.log("--------------------------------------------------------------------------------------------------");
console.log("| Query | p50 (ms) | p90 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Ops/sec |");
console.log("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |");
for (const r of results) {
  const m = r.metrics;
  const shortQ = r.query.length > 35 ? r.query.slice(0, 32) + "..." : r.query;
  console.log(`| \`${shortQ}\` | ${m.p50Ms} | ${m.p90Ms} | ${m.p95Ms} | ${m.p99Ms} | ${m.meanMs} | ${m.opsPerSec} |`);
}
console.log("--------------------------------------------------------------------------------------------------");
console.log(`Results saved to ${outPath}`);
