import { describe, it, expect, beforeAll, afterAll } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { seedCompanyDatabase } from "../scripts/seed-company-db.js";
import { SecureDatabaseEngine, QueryTimeoutError } from "../src/database/engine.js";
import { COMPANY_TABLE_METADATA } from "../src/database/seed.js";
import { SQLValidator } from "../src/security/validator.js";

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const testCompanyDbPath = path.join(rootDir, "real_world_company_test.db");

describe("Company Database and Real-World LLM Testing Suite", () => {
  let engine: SecureDatabaseEngine;
  let validator: SQLValidator;

  beforeAll(async () => {
    // Seed test database
    seedCompanyDatabase(testCompanyDbPath);

    // Set environment variable to activate company schema
    process.env.MCP_SECURE_DB_SQLITE_PATH = testCompanyDbPath;

    engine = new SecureDatabaseEngine({
      sqliteDbPath: testCompanyDbPath,
      timeoutMs: 1500,
    });
    await engine.init();

    validator = new SQLValidator();
  });

  afterAll(async () => {
    delete process.env.MCP_SECURE_DB_SQLITE_PATH;
    await engine.close();
    await new Promise((resolve) => setTimeout(resolve, 100));
    if (fs.existsSync(testCompanyDbPath)) {
      try {
        fs.unlinkSync(testCompanyDbPath);
      } catch {
        // cleanup
      }
    }
  });

  describe("Database Seeding & Schema Integrity", () => {
    it("creates 5 tables with accurate record counts", () => {
      expect(COMPANY_TABLE_METADATA.departments.rowCount).toBe(5);
      expect(COMPANY_TABLE_METADATA.products.rowCount).toBe(8);
      expect(COMPANY_TABLE_METADATA.orders.rowCount).toBe(20);
      expect(COMPANY_TABLE_METADATA.employees.rowCount).toBe(12);
      expect(COMPANY_TABLE_METADATA.api_secrets.rowCount).toBe(4);
    });

    it("correctly identifies sensitive PII columns on employees", () => {
      const piiCols = COMPANY_TABLE_METADATA.employees.columns
        .filter((c) => c.isPII)
        .map((c) => c.name);
      expect(piiCols).toContain("salary_usd");
      expect(piiCols).toContain("ssn");
      expect(piiCols).toContain("personal_email");
      expect(piiCols).not.toContain("name");
      expect(piiCols).not.toContain("role");
    });

    it("connects cleanly via constructor sqliteDbPath even when process.env.MCP_SECURE_DB_SQLITE_PATH is initially unset", async () => {
      const savedEnv = process.env.MCP_SECURE_DB_SQLITE_PATH;
      delete process.env.MCP_SECURE_DB_SQLITE_PATH;
      const isolatedEngine = new SecureDatabaseEngine({
        sqliteDbPath: testCompanyDbPath,
      });
      await isolatedEngine.init();
      const tables = isolatedEngine.getTables("analyst");
      expect(tables.map((t) => t.name)).toContain("departments");
      const res = await isolatedEngine.executeQuery(
        "SELECT id, name FROM departments LIMIT 2;",
        "analyst",
        "test-user"
      );
      expect(res.rowCount).toBe(2);
      await isolatedEngine.close();
      if (savedEnv) process.env.MCP_SECURE_DB_SQLITE_PATH = savedEnv;
    });
  });

  describe("Role-Based Access Control on Company Tables", () => {
    it("exposes only public tables (departments, products) to public_viewer", () => {
      const tables = engine.getTables("public_viewer");
      const names = tables.map((t) => t.name);
      expect(names).toContain("departments");
      expect(names).toContain("products");
      expect(names).not.toContain("orders");
      expect(names).not.toContain("employees");
      expect(names).not.toContain("api_secrets");
    });

    it("exposes business and analytical tables to analyst", () => {
      const tables = engine.getTables("analyst");
      const names = tables.map((t) => t.name);
      expect(names).toContain("departments");
      expect(names).toContain("products");
      expect(names).toContain("orders");
      expect(names).toContain("employees");
      expect(names).not.toContain("api_secrets");
    });

    it("exposes all 5 tables including api_secrets to admin", () => {
      const tables = engine.getTables("admin");
      const names = tables.map((t) => t.name);
      expect(names.length).toBe(5);
      expect(names).toContain("api_secrets");
    });
  });

  describe("Analytical Query Execution & Layered Guardrails", () => {
    it("allows analyst to run complex JOIN aggregation between orders and products", async () => {
      const sql = `
        SELECT p.title, count(o.id) as order_count, sum(o.amount_usd) as total_revenue
        FROM products p
        JOIN orders o ON p.id = o.product_id
        GROUP BY p.title
        ORDER BY total_revenue DESC
        LIMIT 5;
      `;
      const result = await engine.executeQuery(sql, "analyst", "analyst-user-1");
      expect(result.rowCount).toBeGreaterThan(0);
      expect(result.rows.length).toBeGreaterThan(0);
      expect(result.rows[0]).toHaveProperty("title");
      expect(result.rows[0]).toHaveProperty("order_count");
      expect(result.rows[0]).toHaveProperty("total_revenue");
    });

    it("allows analyst to query non-PII employee columns", async () => {
      const sql = "SELECT id, name, dept_id, role FROM employees LIMIT 5;";
      const result = await engine.executeQuery(sql, "analyst", "analyst-user-1");
      expect(result.rowCount).toBe(5);
      expect(result.rows[0]).toHaveProperty("name");
      expect(result.rows[0]).toHaveProperty("role");
      expect(result.rows[0]).not.toHaveProperty("salary_usd");
      expect(result.rows[0]).not.toHaveProperty("ssn");
    });

    it("blocks analyst from querying PII columns (salary_usd, ssn) at compile/authorizer time", async () => {
      const sql = "SELECT name, salary_usd, ssn FROM employees LIMIT 5;";
      await expect(
        engine.executeQuery(sql, "analyst", "analyst-user-1")
      ).rejects.toThrow(/salary_usd|ssn|denied/i);
    });

    it("blocks analyst from wildcard SELECT * on employees containing PII", async () => {
      const sql = "SELECT * FROM employees LIMIT 5;";
      await expect(
        engine.executeQuery(sql, "analyst", "analyst-user-1")
      ).rejects.toThrow(/Wildcard SELECT \* on table 'employees' containing PII/i);
    });

    it("blocks analyst from querying api_secrets table", async () => {
      const sql = "SELECT * FROM api_secrets;";
      await expect(
        engine.executeQuery(sql, "analyst", "analyst-user-1")
      ).rejects.toThrow(/requires admin privileges|not in the authorized catalog/i);
    });

    it("allows admin to query PII and api_secrets", async () => {
      const sql = "SELECT service_name, secret_token, environment FROM api_secrets;";
      const result = await engine.executeQuery(sql, "admin", "admin-user-1");
      expect(result.rowCount).toBe(4);
      expect(result.rows[0]).toHaveProperty("secret_token");
    });
  });

  describe("Adversarial Defense Verification", () => {
    it("blocks DROP TABLE injection payload in analyst query", async () => {
      const maliciousSql = "DROP TABLE employees;";
      expect(validator.validate(maliciousSql, "analyst").valid).toBe(false);
      await expect(
        engine.executeQuery(maliciousSql, "analyst", "adversary-1")
      ).rejects.toThrow();
    });

    it("blocks stacked queries attempting table mutation", async () => {
      const stackedSql = "SELECT count(*) FROM products; DELETE FROM orders;";
      expect(validator.validate(stackedSql, "analyst").valid).toBe(false);
      await expect(
        engine.executeQuery(stackedSql, "analyst", "adversary-1")
      ).rejects.toThrow();
    });

    it("enforces worker sandbox timeout on runaway recursive query", async () => {
      const runawaySql = `
        WITH RECURSIVE spin(n) AS (
          SELECT 1
          UNION ALL
          SELECT n + 1 FROM spin WHERE n < 500000000
        )
        SELECT SUM(n) AS total FROM spin;
      `;
      await expect(
        engine.executeQuery(runawaySql, "analyst", "adversary-1")
      ).rejects.toThrow(QueryTimeoutError);
    });
  });
});
