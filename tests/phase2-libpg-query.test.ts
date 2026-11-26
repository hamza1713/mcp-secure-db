import { describe, it, expect } from "vitest";
import { PostgresAstValidator } from "../src/security/pg-ast-validator.js";

describe("Phase 2: Official PostgreSQL WASM AST Validator (libpg-query)", () => {
  const validator = new PostgresAstValidator({
    allowedSchemas: ["public"],
  });

  describe("Legitimate PostgreSQL Analytical Queries (Must Pass)", () => {
    const validQueries = [
      {
        name: "schema-qualified public.customers with type cast",
        sql: 'SELECT id, name, created_at::TEXT FROM public."customers" WHERE id = 1',
      },
      {
        name: "PostgreSQL date_trunc and EXTRACT",
        sql: "SELECT date_trunc('day', created_at) AS day, EXTRACT(YEAR FROM created_at) AS yr, COUNT(*) FROM customers GROUP BY 1, 2",
      },
      {
        name: "FETCH FIRST N ROWS ONLY within limit",
        sql: "SELECT id, name FROM customers ORDER BY id ASC FETCH FIRST 10 ROWS ONLY",
      },
      {
        name: "dollar-quoted string literal containing comment-like text",
        sql: "SELECT id, name FROM customers WHERE name = $$safe -- not a comment; /* ok */$$",
      },
      {
        name: "PostgreSQL E-string with escaped quote and dashes",
        sql: "SELECT id, name FROM customers WHERE name = E'O\\'Reilly -- analytics'",
      },
      {
        name: "explicit relational join with extra AND filter",
        sql: "SELECT c.name, SUM(u.request_count) FROM customers c JOIN api_usage u ON c.id = u.customer_id AND c.plan = 'enterprise' GROUP BY c.name",
      },
      {
        name: "CURRENT_DATE and COALESCE",
        sql: "SELECT id, COALESCE(name, 'unknown'), CURRENT_DATE FROM customers",
      },
      {
        name: "LIMIT 0 (protobuf3 zero integer preservation)",
        sql: "SELECT id, name FROM customers LIMIT 0",
      },
    ];

    for (const q of validQueries) {
      it(`allows: ${q.name}`, () => {
        const res = validator.validate(q.sql, "analyst");
        expect(res.valid, res.violationReason).toBe(true);
        expect(res.sanitizedQuery).toBeDefined();
      });
    }

    it("clamps explicit LIMIT and FETCH FIRST exceeding maxRows via _mcp_bounded wrapper", () => {
      const r1 = validator.validate(
        "SELECT id, name FROM customers LIMIT 50000",
        "analyst"
      );
      expect(r1.valid).toBe(true);
      expect(r1.limitInjected).toBe(1000);
      expect(r1.sanitizedQuery).toContain("_mcp_bounded LIMIT 1000");

      const r2 = validator.validate(
        "SELECT id, name FROM customers FETCH FIRST 99999 ROWS ONLY",
        "analyst"
      );
      expect(r2.valid).toBe(true);
      expect(r2.limitInjected).toBe(1000);
      expect(r2.sanitizedQuery).toContain("_mcp_bounded LIMIT 1000");
    });

    it("preserves LIMIT 0 accurately without defaulting to 100", () => {
      const res = validator.validate(
        "SELECT id, name FROM customers LIMIT 0",
        "analyst"
      );
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(0);
    });
  });

  describe("Adversarial PostgreSQL Attack Vectors (Must All Fail Closed)", () => {
    const attacks: Array<{ name: string; sql: string; role?: "analyst" | "admin" }> = [
      {
        name: "DO $$ anonymous PL/pgSQL block",
        sql: "DO $$ BEGIN PERFORM pg_sleep(5); END $$",
        role: "admin",
      },
      {
        name: "COPY TO PROGRAM OS command execution",
        sql: "COPY customers TO PROGRAM 'id'",
        role: "admin",
      },
      {
        name: "SET statement_timeout = 0",
        sql: "SET statement_timeout = 0",
        role: "admin",
      },
      {
        name: "EXPLAIN ANALYZE DELETE mutation",
        sql: "EXPLAIN ANALYZE DELETE FROM customers",
        role: "admin",
      },
      {
        name: "PREPARE / EXECUTE statement",
        sql: "PREPARE p AS SELECT * FROM customers",
        role: "admin",
      },
      {
        name: "Data-modifying CTE (WITH DELETE RETURNING)",
        sql: "WITH d AS (DELETE FROM customers RETURNING id) SELECT id FROM d",
        role: "admin",
      },
      {
        name: "SELECT ... FOR UPDATE locking clause",
        sql: "SELECT id FROM customers FOR UPDATE",
        role: "admin",
      },
      {
        name: "SELECT INTO table creation",
        sql: "SELECT id INTO leaked_tbl FROM customers",
        role: "admin",
      },
      {
        name: "Table-valued function generate_series in FROM",
        sql: "SELECT * FROM generate_series(1, 10000000)",
        role: "analyst",
      },
      {
        name: "Table-valued function pg_ls_dir in FROM",
        sql: "SELECT * FROM pg_ls_dir('.')",
        role: "admin",
      },
      {
        name: "WINDOW clause calling set_config('statement_timeout', '0', true)",
        sql: "SELECT id, COUNT(*) OVER w FROM customers WINDOW w AS (ORDER BY set_config('statement_timeout', '0', TRUE))",
        role: "analyst",
      },
      {
        name: "FILTER (WHERE pg_sleep(5) IS NULL)",
        sql: "SELECT COUNT(*) FILTER (WHERE pg_sleep(5) IS NULL) FROM customers",
        role: "analyst",
      },
      {
        name: "DISTINCT ON (billing_email) PII leak",
        sql: "SELECT DISTINCT ON (billing_email) id, name FROM customers",
        role: "analyst",
      },
      {
        name: "Aggregate ORDER BY billing_email PII leak",
        sql: "SELECT COUNT(name ORDER BY billing_email) FROM customers",
        role: "analyst",
      },
      {
        name: "SQLValueFunction CURRENT_USER info leak",
        sql: "SELECT id, CURRENT_USER FROM customers",
        role: "analyst",
      },
      {
        name: "Schema-qualified pg_catalog.pg_sleep",
        sql: "SELECT pg_catalog.pg_sleep(5) FROM customers",
        role: "analyst",
      },
      {
        name: "Nested C-style comment smuggling",
        sql: "SELECT /* outer /* inner */ */ id FROM customers",
        role: "analyst",
      },
      {
        name: "Trailing SQL comment",
        sql: "SELECT id FROM customers -- trailing",
        role: "analyst",
      },
      {
        name: "Stacked multi-statement injection",
        sql: "SELECT id FROM customers; DROP TABLE customers",
        role: "admin",
      },
      {
        name: "Disallowed regex operator ~",
        sql: "SELECT id FROM customers WHERE name ~ '^A'",
        role: "analyst",
      },
      {
        name: "Disallowed SIMILAR TO operator",
        sql: "SELECT id FROM customers WHERE name SIMILAR TO '%Corp%'",
        role: "analyst",
      },
      {
        name: "Disallowed JSON arrow operator ->",
        sql: "SELECT name -> 'a' FROM customers",
        role: "analyst",
      },
      {
        name: "Dynamic concatenated LIKE pattern",
        sql: "SELECT name FROM customers WHERE name LIKE 'a' || 'b'",
        role: "analyst",
      },
      {
        name: "Explicit CROSS JOIN",
        sql: "SELECT c.id FROM customers c CROSS JOIN api_usage u",
        role: "analyst",
      },
      {
        name: "Implicit comma join",
        sql: "SELECT c.id FROM customers c, api_usage u",
        role: "analyst",
      },
      {
        name: "NATURAL JOIN",
        sql: "SELECT c.id FROM customers c NATURAL JOIN api_usage u",
        role: "analyst",
      },
      {
        name: "Non-correlating join ON c.id IS NOT NULL",
        sql: "SELECT c.id FROM customers c JOIN api_usage u ON c.id IS NOT NULL",
        role: "analyst",
      },
      {
        name: "Tautological join ON c.id = u.customer_id OR 1 = 1",
        sql: "SELECT c.id FROM customers c JOIN api_usage u ON c.id = u.customer_id OR 1 = 1",
        role: "analyst",
      },
      {
        name: "Excessive OFFSET exceeding maxOffset",
        sql: "SELECT id FROM customers LIMIT 10 OFFSET 999999",
        role: "analyst",
      },
      {
        name: "pg_catalog.pg_tables system catalog read",
        sql: "SELECT tablename FROM pg_catalog.pg_tables",
        role: "admin",
      },
      {
        name: "information_schema.columns read",
        sql: "SELECT column_name FROM information_schema.columns",
        role: "admin",
      },
    ];

    for (const atk of attacks) {
      it(`blocks: ${atk.name}`, () => {
        const res = validator.validate(atk.sql, atk.role ?? "analyst");
        expect(res.valid, `Unexpectedly allowed: ${atk.sql}`).toBe(false);
        expect(res.violationReason).toBeDefined();
      });
    }
  });
});
