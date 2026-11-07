import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { COMPANY_SEED_SQL, COMPANY_TABLE_METADATA } from "../src/database/seed.js";

export interface SeedResult {
  ok: boolean;
  dbPath: string;
  tableCounts: Record<string, number>;
}

export function seedCompanyDatabase(targetPath?: string): SeedResult {
  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const dbPath = targetPath ?? process.env.MCP_SECURE_DB_SQLITE_PATH ?? path.join(rootDir, "real_world_company.db");

  // Remove existing file if present to make seeding strictly idempotent
  if (fs.existsSync(dbPath)) {
    try {
      fs.unlinkSync(dbPath);
    } catch {
      // If busy or locked, recreate or overwrite
    }
  }

  const db = new DatabaseSync(dbPath);

  // Execute schema creation and data population
  db.exec(COMPANY_SEED_SQL);

  const tableCounts: Record<string, number> = {};
  for (const tableName of Object.keys(COMPANY_TABLE_METADATA)) {
    const row = db.prepare(`SELECT count(*) as count FROM ${tableName}`).get() as { count: number } | undefined;
    tableCounts[tableName] = row?.count ?? 0;
  }

  db.close();

  return {
    ok: true,
    dbPath,
    tableCounts,
  };
}

const isDirectRun =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  console.log("============================================================");
  console.log("  MCP Secure DB - Provisioning Custom Company Database");
  console.log("============================================================");

  const result = seedCompanyDatabase();

  console.log(`Database provisioned successfully: ${result.dbPath}`);
  console.log("\nPopulated Tables and Record Counts:");
  for (const [table, count] of Object.entries(result.tableCounts)) {
    const meta = COMPANY_TABLE_METADATA[table];
    const piiCols = meta?.columns.filter((c) => c.isPII).map((c) => c.name) ?? [];
    const piiNotice = piiCols.length > 0 ? ` [PII: ${piiCols.join(", ")}]` : "";
    const adminNotice = meta?.adminOnly ? " (Admin Only)" : "";
    console.log(`  - ${table.padEnd(16)}: ${count} rows${adminNotice}${piiNotice}`);
  }
  console.log("\nReady for live interactive testing with Gemini 3.8 Flash.");
}
