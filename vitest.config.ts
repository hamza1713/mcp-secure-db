import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    testTimeout: 90000,
    exclude: ["**/node_modules/**", "**/dist/**", "tests/integration/**"],
    env: {
      MCP_SECURE_DB_SQLITE_PATH: "",
      MCP_SECURE_DB_ALLOW_DEMO_TOKENS: "true",
      MCP_SECURE_DB_AUDIT_PATH: "tests/scratch/vitest-audit.jsonl",
    },
  },
});
