import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { sqlValidator } from "../src/security/validator.js";
import { SecureDatabaseEngine } from "../src/database/engine.js";
import { DatabaseSync } from "node:sqlite";
import { UserRole } from "../src/types.js";
import { PII_COLUMNS, ROLE_ALLOWED_TABLES } from "../src/security/policy.js";
import { SEED_SQL } from "../src/database/seed.js";

interface DifferentialQueryItem {
  id: string;
  sql: string;
  role: UserRole;
  expectedOutcome: "ALLOW_AND_VERIFY_SAFE" | "REJECT_PRE_EXECUTION";
  category: string;
}

export const DIFFERENTIAL_CORPUS: DifferentialQueryItem[] = [
  // 1. Valid Analytical Queries across customers and api_usage (Safe to run)
  {
    id: "DIFF-SAFE-001",
    sql: "SELECT id, name, plan FROM customers",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_projection",
  },
  {
    id: "DIFF-SAFE-002",
    sql: "SELECT id, endpoint, request_count, compute_ms, date FROM api_usage WHERE compute_ms > 100000",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_filter",
  },
  {
    id: "DIFF-SAFE-003",
    sql: "SELECT endpoint, COUNT(*) AS hits, SUM(request_count) AS total_requests, AVG(compute_ms) AS avg_ms FROM api_usage GROUP BY endpoint",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_aggregation",
  },
  {
    id: "DIFF-SAFE-004",
    sql: "SELECT c.name, u.endpoint, u.request_count FROM customers c JOIN api_usage u ON c.id = u.customer_id WHERE c.plan = 'enterprise'",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_relational_join",
  },
  {
    id: "DIFF-SAFE-005",
    sql: "SELECT c.name, SUM(u.request_count) AS total_reqs FROM customers c LEFT JOIN api_usage u ON c.id = u.customer_id GROUP BY c.name HAVING total_reqs > 50000 ORDER BY total_reqs DESC",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_group_having_order",
  },
  {
    id: "DIFF-SAFE-006",
    sql: "SELECT id, UPPER(TRIM(name)) AS clean_name, LENGTH(name) AS len, plan FROM customers WHERE LOWER(plan) IN ('pro', 'enterprise')",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_scalar_functions",
  },
  {
    id: "DIFF-SAFE-007",
    sql: "SELECT id, name, CASE WHEN plan = 'enterprise' THEN 1 ELSE 0 END AS is_enterprise FROM customers",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_case_expression",
  },
  {
    id: "DIFF-SAFE-008",
    sql: "SELECT id, CAST(id AS TEXT) AS id_str, ROUND(compute_ms / 1000.0, 2) AS compute_sec FROM api_usage",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_cast_and_math",
  },
  {
    id: "DIFF-SAFE-009",
    sql: "WITH totals AS (SELECT customer_id, SUM(request_count) AS s FROM api_usage GROUP BY customer_id) SELECT c.name, t.s FROM customers c JOIN totals t ON c.id = t.customer_id",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_cte_join",
  },
  {
    id: "DIFF-SAFE-010",
    sql: "SELECT id, name, plan FROM customers WHERE id IN (SELECT customer_id FROM api_usage WHERE request_count > 100000)",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_in_subquery",
  },
  {
    id: "DIFF-SAFE-011",
    sql: "SELECT c.id, c.name FROM customers c WHERE EXISTS (SELECT 1 FROM api_usage u WHERE u.customer_id = c.id AND u.compute_ms > 500000)",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_exists_subquery",
  },
  {
    id: "DIFF-SAFE-012",
    sql: "SELECT id FROM customers UNION ALL SELECT customer_id FROM api_usage LIMIT 10",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_union_all",
  },
  {
    id: "DIFF-PARSE-013",
    sql: "SELECT id FROM customers INTERSECT SELECT customer_id FROM api_usage",
    role: "analyst",
    expectedOutcome: "REJECT_PRE_EXECUTION",
    category: "unsupported_parser_dialect_syntax",
  },
  {
    id: "DIFF-PARSE-014",
    sql: "SELECT id FROM customers EXCEPT SELECT customer_id FROM api_usage",
    role: "analyst",
    expectedOutcome: "REJECT_PRE_EXECUTION",
    category: "unsupported_parser_dialect_syntax",
  },
  {
    id: "DIFF-SAFE-015",
    sql: "SELECT id, incident_type, severity, client_ip, details, detected_at FROM security_incidents",
    role: "admin",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_admin_table_read",
  },
  {
    id: "DIFF-SAFE-016",
    sql: "SELECT id, customer_id, key_prefix, webhook_secret, is_active FROM api_keys",
    role: "admin",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_admin_keys_read",
  },
  {
    id: "DIFF-SAFE-017",
    sql: "SELECT billing_email, stripe_customer_id FROM customers",
    role: "admin",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_admin_pii_read",
  },
  {
    id: "DIFF-SAFE-018",
    sql: "SELECT DATE('now') AS cur_date, TIME('now') AS cur_time, JULIANDAY('now') AS jd",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_date_functions",
  },
  {
    id: "DIFF-SAFE-019",
    sql: "SELECT COALESCE(NULL, IFNULL(NULL, name)) AS resolved FROM customers",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_null_functions",
  },
  {
    id: "DIFF-SAFE-020",
    sql: "SELECT SUBSTR(endpoint, 1, 3) AS pfx, REPLACE(endpoint, 'agent', 'bot') AS rep FROM api_usage",
    role: "analyst",
    expectedOutcome: "ALLOW_AND_VERIFY_SAFE",
    category: "safe_string_functions",
  },

  // 2. Mutating Statements (All Must Reject)
  ...[
    "DROP TABLE customers",
    "DROP TABLE api_usage",
    "DELETE FROM customers",
    "DELETE FROM api_usage WHERE id = 1",
    "UPDATE customers SET plan = 'hacked'",
    "UPDATE api_usage SET request_count = 0",
    "INSERT INTO customers VALUES (999, 'Hacked', 'h@h.com', 'cus_999', 'pro', 'now')",
    "INSERT INTO api_usage VALUES (999, 1, '/hack', 1, 1, '2026-01-01')",
    "CREATE TABLE backdoor (id INT)",
    "CREATE TEMP TABLE tmp_exfil AS SELECT * FROM customers",
    "ALTER TABLE customers ADD COLUMN leak TEXT",
    "ALTER TABLE customers RENAME TO customers_old",
    "ATTACH DATABASE ':memory:' AS pwn",
    "ATTACH ':memory:' AS shadow",
    "DETACH DATABASE main",
    "PRAGMA writable_schema = ON",
    "PRAGMA foreign_keys = OFF",
    "PRAGMA trusted_schema = ON",
    "PRAGMA max_page_count = 100000",
    "VACUUM",
    "REINDEX",
    "ANALYZE",
  ].map((sql, idx) => ({
    id: `DIFF-MUT-${String(idx + 1).padStart(3, "0")}`,
    sql,
    role: "admin" as UserRole,
    expectedOutcome: "REJECT_PRE_EXECUTION" as const,
    category: "mutating_statement",
  })),

  // 3. System Table Access & Information Leakage (All Must Reject)
  ...[
    "SELECT * FROM sqlite_master",
    "SELECT name, sql FROM sqlite_master WHERE type = 'table'",
    "SELECT * FROM sqlite_schema",
    "SELECT * FROM sqlite_temp_master",
    "SELECT * FROM sqlite_temp_schema",
    "SELECT sql FROM sqlite_master WHERE name = 'api_keys'",
    "SELECT sql FROM sqlite_master WHERE name = 'security_incidents'",
    "SELECT * FROM pragma_table_info('customers')",
    "SELECT * FROM pragma_table_info('api_keys')",
  ].map((sql, idx) => ({
    id: `DIFF-SYS-${String(idx + 1).padStart(3, "0")}`,
    sql,
    role: "admin" as UserRole,
    expectedOutcome: "REJECT_PRE_EXECUTION" as const,
    category: "system_catalog_read",
  })),

  // 4. Role Authorization Violations (Analyst attempting Admin Objects)
  ...[
    "SELECT id FROM security_incidents",
    "SELECT id, incident_type FROM security_incidents",
    "SELECT id FROM api_keys",
    "SELECT id, webhook_secret FROM api_keys",
    "SELECT c.name, k.key_prefix FROM customers c JOIN api_keys k ON c.id = k.customer_id",
    "SELECT c.name, s.incident_type FROM customers c, security_incidents s",
    "SELECT x FROM (SELECT id AS x FROM api_keys) sub",
    "WITH k AS (SELECT id FROM api_keys) SELECT id FROM k",
  ].map((sql, idx) => ({
    id: `DIFF-RBAC-${String(idx + 1).padStart(3, "0")}`,
    sql,
    role: "analyst" as UserRole,
    expectedOutcome: "REJECT_PRE_EXECUTION" as const,
    category: "rbac_table_violation",
  })),

  // 5. PII Access Violations for Non-Admins
  ...[
    "SELECT billing_email FROM customers",
    "SELECT stripe_customer_id FROM customers",
    "SELECT LOWER(billing_email) FROM customers",
    "SELECT SUBSTR(stripe_customer_id, 1, 8) FROM customers",
    "SELECT id, billing_email || '' AS e FROM customers",
    "SELECT * FROM customers",
    "SELECT c.* FROM customers c",
    "SELECT id FROM customers WHERE billing_email LIKE 'b%'",
    "SELECT id FROM customers WHERE stripe_customer_id = 'cus_9921_acme'",
    "SELECT COUNT(*) FROM customers GROUP BY billing_email",
    "SELECT plan, COUNT(*) FROM customers GROUP BY plan HAVING MAX(billing_email) > 'a'",
    "SELECT id, name FROM customers ORDER BY billing_email",
    "SELECT x FROM (SELECT billing_email AS x FROM customers) s",
    "WITH b AS (SELECT billing_email AS em FROM customers) SELECT em FROM b",
  ].map((sql, idx) => ({
    id: `DIFF-PII-${String(idx + 1).padStart(3, "0")}`,
    sql,
    role: "analyst" as UserRole,
    expectedOutcome: "REJECT_PRE_EXECUTION" as const,
    category: "pii_column_violation",
  })),

  // 6. Non-Allowlisted Functions & Extension Loading
  ...[
    "SELECT load_extension('sec.so') FROM customers",
    "SELECT load_extension('x') FROM api_usage",
    "SELECT printf('%s', name) FROM customers",
    "SELECT randomblob(32) FROM customers",
    "SELECT zeroblob(1024) FROM customers",
    "SELECT sqlite_version() FROM customers",
    "SELECT glob('*.com', billing_email) FROM customers",
    "SELECT dangerous_func(1) FROM customers",
    "SELECT unquote(name) FROM customers",
  ].map((sql, idx) => ({
    id: `DIFF-FN-${String(idx + 1).padStart(3, "0")}`,
    sql,
    role: "admin" as UserRole,
    expectedOutcome: "REJECT_PRE_EXECUTION" as const,
    category: "non_allowlisted_function",
  })),

  // 7. Cartesian Joins & Tautologies
  ...[
    "SELECT c.id FROM customers c CROSS JOIN api_usage u",
    "SELECT c.id FROM customers c, api_usage u",
    "SELECT c.id FROM customers c NATURAL JOIN api_usage u",
    "SELECT c.id FROM customers c JOIN api_usage u ON 1=1",
    "SELECT c.id FROM customers c JOIN api_usage u ON true",
    "SELECT c.id FROM customers c JOIN api_usage u ON c.id = c.id",
    "SELECT c.id FROM customers c JOIN api_usage u ON c.id = u.customer_id OR 1=1",
  ].map((sql, idx) => ({
    id: `DIFF-JOIN-${String(idx + 1).padStart(3, "0")}`,
    sql,
    role: "analyst" as UserRole,
    expectedOutcome: "REJECT_PRE_EXECUTION" as const,
    category: "cartesian_join",
  })),

  // 8. Comment & Multi-Statement Smuggling
  ...[
    "SELECT id FROM customers -- comment",
    "SELECT /* comment */ id FROM customers",
    "SELECT id FROM customers; SELECT id FROM api_usage",
    "SELECT id FROM customers; DROP TABLE customers",
  ].map((sql, idx) => ({
    id: `DIFF-SMUG-${String(idx + 1).padStart(3, "0")}`,
    sql,
    role: "analyst" as UserRole,
    expectedOutcome: "REJECT_PRE_EXECUTION" as const,
    category: "comment_or_multistatement",
  })),
];

describe("Differential Testing Harness (Validator vs Real SQLite Engine)", () => {
  let engine: SecureDatabaseEngine;
  let referenceDb: DatabaseSync;

  beforeAll(async () => {
    engine = new SecureDatabaseEngine(3000);
    await engine.init();

    // Baseline reference database used to verify database state integrity before/after
    referenceDb = new DatabaseSync(":memory:");
    referenceDb.exec(SEED_SQL);
  });

  afterAll(async () => {
    await engine.close();
    referenceDb.close();
  });

  it(`runs ${DIFFERENTIAL_CORPUS.length} queries through differential verification with 0 divergences`, async () => {
    expect(DIFFERENTIAL_CORPUS.length).toBeGreaterThanOrEqual(80);

    let allowedCount = 0;
    let rejectedCount = 0;
    const divergences: string[] = [];

    // Capture baseline table checksum / row counts in reference database
    const baselineCustomerCount = Number(
      referenceDb.prepare("SELECT COUNT(*) AS c FROM customers").get()?.c
    );
    const baselineUsageCount = Number(
      referenceDb.prepare("SELECT COUNT(*) AS c FROM api_usage").get()?.c
    );

    for (const item of DIFFERENTIAL_CORPUS) {
      const validation = sqlValidator.validate(item.sql, item.role);

      if (item.expectedOutcome === "ALLOW_AND_VERIFY_SAFE") {
        if (!validation.valid) {
          divergences.push(
            `[${item.id}] Expected ALLOW but validator rejected: ${validation.violationReason} (SQL: ${item.sql})`
          );
          continue;
        }

        allowedCount++;

        // Execute in real worker engine and verify safety invariants
        try {
          const res = await engine.executeQuery(
            item.sql,
            item.role,
            "differential-tester"
          );

          // Invariant 1: Row count must be bounded
          expect(res.rowCount).toBeLessThanOrEqual(1000);

          // Invariant 2: If caller is non-admin, output columns must not include PII
          if (item.role !== "admin") {
            for (const col of res.columns) {
              expect(PII_COLUMNS.has(col.toLowerCase())).toBe(false);
            }
          }

          // Invariant 3: Authorizer operations occurred
          expect(res.authorizerOperations).toBeGreaterThan(0);
        } catch (err: any) {
          divergences.push(
            `[${item.id}] Validator allowed query, but real SQLite failed during safe query: ${err.message}`
          );
        }
      } else {
        // Expected REJECT_PRE_EXECUTION
        if (validation.valid) {
          divergences.push(
            `[${item.id}] SECURITY DIFFERENTIAL DIVERGENCE: Validator allowed unsafe query: ${item.sql}`
          );
          continue;
        }

        rejectedCount++;

        // Invariant 4: Engine must also fail closed if invoked directly
        await expect(
          engine.executeQuery(item.sql, item.role, "differential-tester")
        ).rejects.toThrow();
      }
    }

    // Invariant 5: Engine database state has not been mutated
    const postCustomerRes = await engine.executeQuery(
      "SELECT COUNT(*) AS c FROM customers",
      "analyst",
      "diff-verifier"
    );
    expect(Number(postCustomerRes.rows[0]?.c)).toBe(baselineCustomerCount);

    const postUsageRes = await engine.executeQuery(
      "SELECT COUNT(*) AS c FROM api_usage",
      "analyst",
      "diff-verifier"
    );
    expect(Number(postUsageRes.rows[0]?.c)).toBe(baselineUsageCount);

    // Fail test if any differential divergence occurred between validator and engine
    if (divergences.length > 0) {
      console.error("Differential Divergences Found:\n" + divergences.join("\n"));
    }
    expect(divergences).toEqual([]);
    expect(allowedCount).toBeGreaterThan(15);
    expect(rejectedCount).toBeGreaterThan(60);
  });
});
