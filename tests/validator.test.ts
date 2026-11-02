import { describe, it, expect } from "vitest";
import { SQLValidator } from "../src/security/validator.js";

describe("SQLValidator Allowlist and Recursive AST Security", () => {
  const validator = new SQLValidator();

  describe("Comment Token Detection", () => {
    it("should reject double-dash comments", () => {
      const res = validator.validate(
        "SELECT id FROM customers -- trailing comment",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("comments");
    });

    it("should reject C-style slash-star comments", () => {
      const res = validator.validate(
        "SELECT /* injected */ id FROM customers",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("comments");
    });

    it("should allow dashes and slashes inside valid string literals", () => {
      const res = validator.validate(
        "SELECT id FROM customers WHERE plan = 'pro--tier'",
        "analyst"
      );
      expect(res.valid).toBe(true);
    });
  });

  describe("Multi-Statement Prevention", () => {
    it("should reject chained semicolon statements", () => {
      const res = validator.validate(
        "SELECT id FROM customers; DROP TABLE customers;",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason?.toLowerCase()).toContain(
        "multiple sql statements"
      );
    });

    it("should allow semicolons inside string literals", () => {
      const res = validator.validate(
        "SELECT id FROM customers WHERE name = 'semi;colon'",
        "analyst"
      );
      expect(res.valid).toBe(true);
    });
  });

  describe("Mutating Statement Rejection (SELECT Only)", () => {
    it("should reject DROP TABLE", () => {
      const res = validator.validate("DROP TABLE customers", "analyst");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject DELETE FROM", () => {
      const res = validator.validate(
        "DELETE FROM customers WHERE id = 1",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject UPDATE statements", () => {
      const res = validator.validate(
        "UPDATE customers SET plan = 'enterprise'",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject INSERT INTO", () => {
      const res = validator.validate(
        "INSERT INTO customers VALUES (99, 'Test', 'a@b.com', 'cus_1', 'pro', 'now')",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject ALTER TABLE, PRAGMA, and ATTACH", () => {
      expect(
        validator.validate("ALTER TABLE customers ADD COLUMN secret TEXT", "admin")
          .valid
      ).toBe(false);
      expect(
        validator.validate("PRAGMA table_info(customers)", "admin").valid
      ).toBe(false);
      expect(
        validator.validate("ATTACH DATABASE ':memory:' AS aux", "admin").valid
      ).toBe(false);
    });
  });

  describe("Strict SQLite Function and Table Allowlists (P0-3)", () => {
    it("should reject load_extension calls", () => {
      const res = validator.validate(
        "SELECT load_extension('malicious.so') FROM customers",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("function allowlist");
    });

    it("should reject unknown or non-allowlisted SQLite functions by default", () => {
      for (const fnQuery of [
        "SELECT printf('%s', name) FROM customers",
        "SELECT randomblob(64) FROM customers",
        "SELECT zeroblob(1024) FROM customers",
        "SELECT sqlite_version() FROM customers",
        "SELECT custom_udf(id) FROM customers",
      ]) {
        const res = validator.validate(fnQuery, "admin");
        expect(res.valid).toBe(false);
        expect(res.violationReason).toContain("function allowlist");
      }
    });

    it("should permit explicitly allowlisted scalar and aggregate functions", () => {
      const res = validator.validate(
        "SELECT COUNT(*), SUM(request_count), ROUND(AVG(compute_ms), 2), LOWER(endpoint) FROM api_usage GROUP BY endpoint",
        "analyst"
      );
      expect(res.valid).toBe(true);
    });

    it("should reject sqlite_master and sqlite_schema for all roles including admin", () => {
      expect(
        validator.validate("SELECT sql FROM sqlite_master", "analyst").valid
      ).toBe(false);
      expect(
        validator.validate("SELECT sql FROM sqlite_schema", "admin").valid
      ).toBe(false);
    });
  });

  describe("Cartesian Join & Tautology Prevention", () => {
    it("should reject explicit CROSS JOIN", () => {
      const res = validator.validate(
        "SELECT c.id FROM customers c CROSS JOIN api_usage u",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("CROSS JOIN");
    });

    it("should reject implicit comma-separated joins", () => {
      const res = validator.validate(
        "SELECT c.id FROM customers c, api_usage u",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Implicit comma-separated");
    });

    it("should reject tautological and constant join conditions (ON 1=1, ON true, OR 1=1)", () => {
      for (const q of [
        "SELECT c.id FROM customers c JOIN api_usage u ON 1 = 1",
        "SELECT c.id FROM customers c JOIN api_usage u ON true",
        "SELECT c.id FROM customers c JOIN api_usage u ON c.id = c.id",
        "SELECT c.id FROM customers c JOIN api_usage u ON c.id = u.customer_id OR 1 = 1",
      ]) {
        const res = validator.validate(q, "analyst");
        expect(res.valid).toBe(false);
        expect(res.violationReason).toContain("tautological");
      }
    });

    it("should allow valid relational foreign-key joins", () => {
      const res = validator.validate(
        "SELECT c.name, SUM(u.request_count) AS total_reqs FROM customers c JOIN api_usage u ON c.id = u.customer_id GROUP BY c.name",
        "analyst"
      );
      expect(res.valid).toBe(true);
    });
  });

  describe("Role-Based Access Control & PII Policy", () => {
    it("should reject all queries for unauthenticated role", () => {
      const res = validator.validate("SELECT id FROM customers", "unauthenticated");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Authentication required");
    });

    it("should block non-admins from accessing security_incidents and api_keys", () => {
      const res = validator.validate(
        "SELECT id FROM security_incidents",
        "analyst"
      );
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("requires admin privileges");
    });

    it("should allow admin to access security_incidents table", () => {
      const res = validator.validate(
        "SELECT id, incident_type FROM security_incidents",
        "admin"
      );
      expect(res.valid).toBe(true);
    });

    it("should block non-admins from selecting PII columns", () => {
      expect(
        validator.validate("SELECT billing_email FROM customers", "analyst").valid
      ).toBe(false);
      expect(
        validator.validate(
          "SELECT stripe_customer_id FROM customers",
          "public_viewer"
        ).valid
      ).toBe(false);
    });

    it("should allow admin to select PII columns", () => {
      const res = validator.validate(
        "SELECT billing_email, stripe_customer_id FROM customers",
        "admin"
      );
      expect(res.valid).toBe(true);
    });

    it("should block non-admins from wildcard SELECT * on tables with PII", () => {
      const res = validator.validate("SELECT * FROM customers", "analyst");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain(
        "Wildcard SELECT * on table 'customers' containing PII"
      );
    });

    it("should allow non-admins to select explicit safe columns", () => {
      const res = validator.validate(
        "SELECT id, name, plan FROM customers",
        "analyst"
      );
      expect(res.valid).toBe(true);
    });
  });

  describe("Automatic LIMIT Clamping and Injection", () => {
    it("should inject default LIMIT 100 when omitted", () => {
      const res = validator.validate(
        "SELECT id, name FROM customers",
        "analyst"
      );
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(100);
      expect(res.sanitizedQuery).toContain("LIMIT 100");
    });

    it("should clamp LIMIT exceeding maxRows (1000) to 1000", () => {
      const res = validator.validate(
        "SELECT id, name FROM customers LIMIT 50000",
        "analyst"
      );
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(1000);
      expect(res.sanitizedQuery).toContain("LIMIT 1000");
    });

    it("should preserve valid user limits under 1000", () => {
      const res = validator.validate(
        "SELECT id, name FROM customers LIMIT 25",
        "analyst"
      );
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(25);
      expect(res.sanitizedQuery).toContain("LIMIT 25");
    });

    it("should attach injected LIMIT after compound UNION ALL properly", () => {
      const res = validator.validate(
        "SELECT id FROM customers UNION ALL SELECT customer_id FROM api_usage",
        "analyst"
      );
      expect(res.valid).toBe(true);
      expect(res.sanitizedQuery).toMatch(/UNION ALL.*LIMIT 100$/i);
    });
  });
});
