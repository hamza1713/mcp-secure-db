import { describe, it, expect, afterAll } from "vitest";
import { SecureDatabaseEngine } from "../src/database/engine.js";
import {
  enforceResultPolicy,
  SecurityResultPolicyViolation,
} from "../src/security/result-policy.js";

describe("Multi-Layer Fail-Closed PII Bypass Defenses (P0-5)", () => {
  const engine = new SecureDatabaseEngine({
    timeoutMs: 3000,
    extraSeedSql:
      "CREATE VIEW v_customer_summary AS SELECT id, name, billing_email AS contact_alias, stripe_customer_id AS payment_ref FROM customers;",
    extraAllowedViews: ["v_customer_summary"],
  });

  afterAll(async () => {
    await engine.close();
  });

  const bypassVectors: Array<{ name: string; sql: string }> = [
    {
      name: "column alias on PII column",
      sql: "SELECT billing_email AS public_contact FROM customers",
    },
    {
      name: "single-level CTE aliasing PII column",
      sql: "WITH c AS (SELECT billing_email AS contact FROM customers) SELECT contact FROM c",
    },
    {
      name: "multi-stage nested CTE smuggling PII column",
      sql: "WITH c1 AS (SELECT stripe_customer_id AS s FROM customers), c2 AS (SELECT s AS token_ref FROM c1) SELECT token_ref FROM c2",
    },
    {
      name: "derived-table subquery in FROM",
      sql: "SELECT leaked FROM (SELECT billing_email AS leaked FROM customers) sub",
    },
    {
      name: "derived-table subquery accessing admin-only api_keys",
      sql: "SELECT leaked FROM (SELECT webhook_secret AS leaked FROM api_keys) sub",
    },
    {
      name: "scalar subquery in SELECT projection",
      sql: "SELECT id, (SELECT billing_email FROM customers LIMIT 1) AS leak FROM api_usage",
    },
    {
      name: "compound UNION ALL second branch",
      sql: "SELECT name FROM customers UNION ALL SELECT billing_email FROM customers",
    },
    {
      name: "compound UNION accessing admin-only table",
      sql: "SELECT name FROM customers UNION SELECT webhook_secret FROM api_keys",
    },
    {
      name: "scalar function wrapping PII column (LOWER)",
      sql: "SELECT LOWER(billing_email) AS clean_val FROM customers",
    },
    {
      name: "SUBSTR partial extraction of PII column",
      sql: "SELECT SUBSTR(billing_email, 1, 10) AS prefix FROM customers",
    },
    {
      name: "CAST expression wrapping PII column",
      sql: "SELECT CAST(stripe_customer_id AS TEXT) AS txt FROM customers",
    },
    {
      name: "string concatenation expression on PII column",
      sql: "SELECT billing_email || '_tag' AS tagged FROM customers",
    },
    {
      name: "CASE expression referencing PII column",
      sql: "SELECT CASE WHEN id = 1 THEN billing_email ELSE name END AS out_val FROM customers",
    },
    {
      name: "WHERE predicate boolean inference on PII column",
      sql: "SELECT id, name FROM customers WHERE billing_email LIKE 'billing%'",
    },
    {
      name: "GROUP BY on PII column",
      sql: "SELECT COUNT(*) FROM customers GROUP BY billing_email",
    },
    {
      name: "HAVING clause referencing PII column",
      sql: "SELECT plan, COUNT(*) FROM customers GROUP BY plan HAVING MIN(billing_email) > 'a'",
    },
    {
      name: "ORDER BY side-channel sorting on PII column",
      sql: "SELECT id, name FROM customers ORDER BY billing_email ASC",
    },
    {
      name: "SQL VIEW aliasing underlying PII columns",
      sql: "SELECT id, contact_alias FROM v_customer_summary",
    },
    {
      name: "SELECT * on SQL VIEW backed by PII table",
      sql: "SELECT * FROM v_customer_summary",
    },
    {
      name: "SELECT * on sensitive table",
      sql: "SELECT * FROM customers",
    },
    {
      name: "table-qualified wildcard SELECT c.* on sensitive table",
      sql: "SELECT c.* FROM customers c",
    },
    {
      name: "SELECT * inside CTE over sensitive table",
      sql: "WITH all_rows AS (SELECT * FROM customers) SELECT id, name FROM all_rows",
    },
  ];

  for (const vector of bypassVectors) {
    it(`fails closed for analyst on: ${vector.name}`, async () => {
      await expect(
        engine.executeQuery(vector.sql, "analyst", "bypass-tester")
      ).rejects.toThrow();
    });
  }

  describe("Result-level policy enforcement (enforceResultPolicy)", () => {
    it("fails closed when synthetic rows contain aliased email addresses", () => {
      expect(() =>
        enforceResultPolicy({
          role: "analyst",
          columns: ["innocent_label"],
          rows: [{ innocent_label: "contact: billing@acme.example.com" }],
        })
      ).toThrow(SecurityResultPolicyViolation);
    });

    it("fails closed when synthetic rows contain Stripe customer IDs, webhook secrets, API keys, or IPs", () => {
      const payloads = [
        "cus_9921_acme",
        "whsec_987216345abcdef",
        "pk_live_acme_9281",
        "198.51.100.44",
        "BILLING@ACME",
      ];

      for (const value of payloads) {
        expect(() =>
          enforceResultPolicy({
            role: "analyst",
            columns: ["computed_value"],
            rows: [{ computed_value: value }],
          })
        ).toThrow(SecurityResultPolicyViolation);
      }
    });

    it("permits admin role to receive PII columns and values", () => {
      expect(() =>
        enforceResultPolicy({
          role: "admin",
          columns: ["billing_email", "stripe_customer_id"],
          rows: [
            {
              billing_email: "billing@acme.example.com",
              stripe_customer_id: "cus_9921_acme",
            },
          ],
        })
      ).not.toThrow();
    });
  });
});
