import { describe, it, expect } from "vitest";
import { SQLValidator } from "../src/security/validator.js";

describe("SQLValidator Deterministic AST Security", () => {
  const validator = new SQLValidator();

  describe("Comment Token Detection (Anti-Smuggling)", () => {
    it("should reject double-dash comments", () => {
      const res = validator.validate("SELECT id FROM customers -- dangerous comment");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("comments");
    });

    it("should reject C-style slash-star comments", () => {
      const res = validator.validate("SELECT /* injected */ id FROM customers");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("comments");
    });

    it("should allow dashes and slashes inside valid string literals", () => {
      const res = validator.validate("SELECT id FROM customers WHERE plan = 'pro--tier'");
      expect(res.valid).toBe(true);
    });
  });

  describe("Multi-Statement Prevention", () => {
    it("should reject chained semicolon statements", () => {
      const res = validator.validate("SELECT id FROM customers; DROP TABLE customers;");
      expect(res.valid).toBe(false);
      expect(res.violationReason?.toLowerCase()).toContain("multiple sql statements");
    });

    it("should allow semicolons inside string literals", () => {
      const res = validator.validate("SELECT id FROM customers WHERE name = 'semi;colon'");
      expect(res.valid).toBe(true);
    });
  });

  describe("Mutating Statement Rejection (SELECT Only)", () => {
    it("should reject DROP TABLE", () => {
      const res = validator.validate("DROP TABLE customers");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject DELETE FROM", () => {
      const res = validator.validate("DELETE FROM customers WHERE id = 1");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject UPDATE statements", () => {
      const res = validator.validate("UPDATE customers SET plan = 'enterprise'");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject INSERT INTO", () => {
      const res = validator.validate("INSERT INTO customers VALUES (99, 'Hacker', 'a@b.com', 'cus_1', 'pro', 'now')");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Only SELECT statements are permitted");
    });

    it("should reject ALTER TABLE", () => {
      const res = validator.validate("ALTER TABLE customers ADD COLUMN secret TEXT");
      expect(res.valid).toBe(false);
    });
  });

  describe("SSRF & Dangerous Function Blocking", () => {
    it("should reject read_csv functions", () => {
      const res = validator.validate("SELECT read_csv('/etc/passwd')");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Forbidden dangerous function");
    });

    it("should reject load_extension calls", () => {
      const res = validator.validate("SELECT load_extension('malicious.so')");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Forbidden dangerous function");
    });
  });

  describe("Cartesian Join & DoS Prevention", () => {
    it("should reject explicit CROSS JOIN", () => {
      const res = validator.validate("SELECT * FROM customers CROSS JOIN api_usage");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("CROSS JOIN");
    });

    it("should reject tautological join conditions (ON 1=1)", () => {
      const res = validator.validate("SELECT c.id FROM customers c JOIN api_usage u ON 1 = 1");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("tautological");
    });
  });

  describe("Role-Based Access Control & PII Masking", () => {
    it("should block non-admins from accessing security_incidents table", () => {
      const res = validator.validate("SELECT id FROM security_incidents", "analyst");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("requires admin privileges");
    });

    it("should allow admin to access security_incidents table", () => {
      const res = validator.validate("SELECT id, incident_type FROM security_incidents", "admin");
      expect(res.valid).toBe(true);
    });

    it("should block non-admins from selecting PII columns (billing_email)", () => {
      const res = validator.validate("SELECT billing_email FROM customers", "analyst");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("contains sensitive PII");
    });

    it("should block non-admins from selecting PII columns (stripe_customer_id)", () => {
      const res = validator.validate("SELECT stripe_customer_id FROM customers", "public_viewer");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("contains sensitive PII");
    });

    it("should allow admin to select PII columns", () => {
      const res = validator.validate("SELECT billing_email, stripe_customer_id FROM customers", "admin");
      expect(res.valid).toBe(true);
    });

    it("should block non-admins from wildcard SELECT * on tables with PII", () => {
      const res = validator.validate("SELECT * FROM customers", "analyst");
      expect(res.valid).toBe(false);
      expect(res.violationReason).toContain("Wildcard SELECT * on table 'customers' containing PII");
    });

    it("should allow non-admins to select explicit safe columns", () => {
      const res = validator.validate("SELECT id, name, plan FROM customers", "analyst");
      expect(res.valid).toBe(true);
    });
  });

  describe("Automatic LIMIT Clamping and Injection", () => {
    it("should inject default LIMIT 100 when omitted", () => {
      const res = validator.validate("SELECT id, name FROM customers", "analyst");
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(100);
      expect(res.sanitizedQuery).toContain("LIMIT 100");
    });

    it("should clamp LIMIT exceeding maxRows (1000) to 1000", () => {
      const res = validator.validate("SELECT id, name FROM customers LIMIT 50000", "analyst");
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(1000);
      expect(res.sanitizedQuery).toContain("LIMIT 1000");
    });

    it("should preserve valid user limits under 1000", () => {
      const res = validator.validate("SELECT id, name FROM customers LIMIT 25", "analyst");
      expect(res.valid).toBe(true);
      expect(res.limitInjected).toBe(25);
      expect(res.sanitizedQuery).toContain("LIMIT 25");
    });
  });
});
