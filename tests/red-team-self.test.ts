import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { sqlValidator } from "../src/security/validator.js";
import { SecureDatabaseEngine } from "../src/database/engine.js";

interface RedTeamAttack {
  id: string;
  name: string;
  sql: string;
  targetDefenseLayer: string;
}

export const RED_TEAM_ATTACKS: RedTeamAttack[] = [
  {
    id: "RT-001",
    name: "Window function PARTITION BY on sensitive PII column",
    sql: "SELECT id, ROW_NUMBER() OVER (PARTITION BY billing_email ORDER BY id) AS rn FROM customers",
    targetDefenseLayer: "AST validator & SQLite authorizer PII column filter",
  },
  {
    id: "RT-002",
    name: "Window function ORDER BY on sensitive PII column",
    sql: "SELECT id, DENSE_RANK() OVER (ORDER BY stripe_customer_id) AS rnk FROM customers",
    targetDefenseLayer: "AST validator & SQLite authorizer PII column filter",
  },
  {
    id: "RT-003",
    name: "Aggregate COUNT on sensitive PII column",
    sql: "SELECT COUNT(billing_email) FROM customers",
    targetDefenseLayer: "AST validator & SQLite authorizer PII column filter",
  },
  {
    id: "RT-004",
    name: "Aggregate COUNT DISTINCT on sensitive PII column",
    sql: "SELECT COUNT(DISTINCT stripe_customer_id) FROM customers",
    targetDefenseLayer: "AST validator & SQLite authorizer PII column filter",
  },
  {
    id: "RT-005",
    name: "Scalar subquery in WHERE clause accessing PII column",
    sql: "SELECT name FROM customers WHERE (SELECT billing_email FROM customers WHERE id = 1) LIKE 'b%'",
    targetDefenseLayer: "AST validator & SQLite authorizer subquery inspection",
  },
  {
    id: "RT-006",
    name: "EXISTS subquery inspecting admin-only api_keys table",
    sql: "SELECT name FROM customers WHERE EXISTS (SELECT 1 FROM api_keys WHERE is_active = 1)",
    targetDefenseLayer: "AST validator table permission check in subqueries",
  },
  {
    id: "RT-007",
    name: "NOT EXISTS subquery inspecting admin-only security_incidents table",
    sql: "SELECT name FROM customers WHERE NOT EXISTS (SELECT 1 FROM security_incidents)",
    targetDefenseLayer: "AST validator table permission check in subqueries",
  },
  {
    id: "RT-008",
    name: "Subquery in IN predicate referencing PII column",
    sql: "SELECT name FROM customers WHERE 'billing@acme.example.com' IN (SELECT billing_email FROM customers)",
    targetDefenseLayer: "AST validator & SQLite authorizer PII column check in IN predicates",
  },
  {
    id: "RT-009",
    name: "GLOB operator invocation",
    sql: "SELECT name FROM customers WHERE name GLOB '*Corp*'",
    targetDefenseLayer: "AST validator operator allowlist",
  },
  {
    id: "RT-010",
    name: "REGEXP operator invocation",
    sql: "SELECT name FROM customers WHERE name REGEXP '^A'",
    targetDefenseLayer: "AST validator operator allowlist",
  },
  {
    id: "RT-011",
    name: "MATCH operator invocation",
    sql: "SELECT name FROM customers WHERE name MATCH 'Corp'",
    targetDefenseLayer: "AST validator operator allowlist",
  },
  {
    id: "RT-012",
    name: "Disallowed JSON operator (->) probing unallowlisted functions",
    sql: "SELECT name FROM customers WHERE json_extract('{\"a\":1}', '$.a') = 1",
    targetDefenseLayer: "Strict SQLite function allowlist",
  },
  {
    id: "RT-013",
    name: "COALESCE wrapping non-allowlisted sqlite_version probe",
    sql: "SELECT COALESCE(sqlite_version(), 'safe') FROM customers",
    targetDefenseLayer: "Recursive function allowlist check inside expressions",
  },
  {
    id: "RT-014",
    name: "CASE expression condition wrapping non-allowlisted randomblob function",
    sql: "SELECT CASE WHEN randomblob(8) IS NOT NULL THEN name ELSE 'x' END FROM customers",
    targetDefenseLayer: "Recursive function allowlist check inside CASE expressions",
  },
  {
    id: "RT-015",
    name: "printf formatting call hidden inside safe TRIM function",
    sql: "SELECT TRIM(printf('%s', name)) FROM customers",
    targetDefenseLayer: "Recursive function allowlist check in nested function arguments",
  },
  {
    id: "RT-016",
    name: "CTE hiding non-allowlisted zeroblob function call",
    sql: "WITH blob_maker AS (SELECT zeroblob(100) AS b FROM customers) SELECT 1 FROM blob_maker",
    targetDefenseLayer: "Recursive CTE traversal inspecting function allowlist",
  },
  {
    id: "RT-017",
    name: "CTE attempting to shadow catalog table api_usage",
    sql: "WITH api_usage AS (SELECT 1 AS id) SELECT id FROM api_usage",
    targetDefenseLayer: "CTE name collision and catalog shadowing protection",
  },
  {
    id: "RT-018",
    name: "CTE attempting to shadow system catalog table sqlite_master",
    sql: "WITH sqlite_master AS (SELECT 1 AS id) SELECT id FROM sqlite_master",
    targetDefenseLayer: "CTE name collision and system table shadowing protection",
  },
  {
    id: "RT-019",
    name: "Chained compound SELECT queries exceeding maximum allowed compound depth",
    sql: "SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5",
    targetDefenseLayer: "Compound SELECT count limit (maxCompoundSelects = 4)",
  },
  {
    id: "RT-020",
    name: "Multiple joins exceeding maximum join count limit",
    sql: "SELECT c.id FROM customers c JOIN api_usage u1 ON c.id = u1.customer_id JOIN api_usage u2 ON c.id = u2.customer_id JOIN api_usage u3 ON c.id = u3.customer_id JOIN api_usage u4 ON c.id = u4.customer_id JOIN api_usage u5 ON c.id = u5.customer_id",
    targetDefenseLayer: "Join count limit (maxJoins = 4)",
  },
  {
    id: "RT-021",
    name: "Excessive function argument count DoS attempt",
    sql: "SELECT COALESCE(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) FROM customers",
    targetDefenseLayer: "Function argument count limit (maxFunctionArgs = 8)",
  },
  {
    id: "RT-022",
    name: "Overly long LIKE pattern ReDoS attempt",
    sql: "SELECT name FROM customers WHERE name LIKE 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%'",
    targetDefenseLayer: "LIKE pattern length limit (maxLikePatternLength = 64)",
  },
  {
    id: "RT-023",
    name: "Implicit comma join with alias disguise",
    sql: "SELECT c.id FROM customers c, api_usage u WHERE c.id = u.customer_id",
    targetDefenseLayer: "Implicit comma join rejection",
  },
  {
    id: "RT-024",
    name: "Join condition with tautological OR constant branch",
    sql: "SELECT c.id FROM customers c JOIN api_usage u ON c.id = u.customer_id OR 0 = 0",
    targetDefenseLayer: "Recursive tautology check in join conditions",
  },
  {
    id: "RT-025",
    name: "Join condition with tautological string constant equality",
    sql: "SELECT c.id FROM customers c JOIN api_usage u ON 'a' = 'a'",
    targetDefenseLayer: "Tautological join check rejecting constant comparisons",
  },
  {
    id: "RT-026",
    name: "Aliased PII view query under analyst role",
    sql: "SELECT id, public_contact FROM v_customer_contacts",
    targetDefenseLayer: "SQLite authorizer base column check on views",
  },
  {
    id: "RT-027",
    name: "Wildcard SELECT * on view backed by PII table",
    sql: "SELECT * FROM v_customer_contacts",
    targetDefenseLayer: "Wildcard check on views backed by PII tables",
  },
  {
    id: "RT-028",
    name: "Scalar function LOWER wrapping view PII column",
    sql: "SELECT LOWER(public_contact) FROM v_customer_contacts",
    targetDefenseLayer: "SQLite compile-time authorizer SQLITE_READ event on base table column",
  },
  {
    id: "RT-029",
    name: "SUBSTR partial substring on view PII column",
    sql: "SELECT SUBSTR(public_contact, 1, 4) FROM v_customer_contacts",
    targetDefenseLayer: "SQLite compile-time authorizer SQLITE_READ event on base table column",
  },
  {
    id: "RT-030",
    name: "Derived table subquery aliasing view PII column",
    sql: "SELECT smuggled FROM (SELECT public_contact AS smuggled FROM v_customer_contacts) sub",
    targetDefenseLayer: "Recursive derived table check & SQLite authorizer",
  },
  {
    id: "RT-031",
    name: "Collation clause on sensitive PII column in ORDER BY",
    sql: "SELECT id, name FROM customers ORDER BY billing_email COLLATE NOCASE",
    targetDefenseLayer: "AST validator column check in ORDER BY clauses",
  },
  {
    id: "RT-032",
    name: "HAVING clause referencing sensitive PII column directly",
    sql: "SELECT id, name FROM customers GROUP BY id, name HAVING billing_email IS NOT NULL",
    targetDefenseLayer: "AST validator column check in HAVING clauses",
  },
];

describe("Dedicated Self Red-Team Pass (32 Adversarial Attack Vectors)", () => {
  let engine: SecureDatabaseEngine;

  beforeAll(async () => {
    engine = new SecureDatabaseEngine({
      timeoutMs: 3000,
      extraSeedSql: `
        CREATE VIEW v_public_customers AS SELECT id, name, plan FROM customers;
        CREATE VIEW v_customer_contacts AS SELECT id, name, billing_email AS public_contact FROM customers;
      `,
      extraAllowedViews: ["v_public_customers", "v_customer_contacts"],
    });
    await engine.init();
  });

  afterAll(async () => {
    await engine.close();
  });

  it(`executes ${RED_TEAM_ATTACKS.length} adversarial attacks; verifies 100% fail closed`, async () => {
    expect(RED_TEAM_ATTACKS.length).toBeGreaterThanOrEqual(30);

    for (const attack of RED_TEAM_ATTACKS) {
      // 1. Validator rejection or authorizer rejection
      let caughtByValidator = false;
      const validation = sqlValidator.validate(attack.sql, "analyst");
      if (!validation.valid) {
        caughtByValidator = true;
      }

      // 2. Real engine execution must fail closed
      let caughtByEngine = false;
      try {
        await engine.executeQuery(attack.sql, "analyst", "red-team-agent");
      } catch {
        caughtByEngine = true;
      }

      expect(
        caughtByValidator || caughtByEngine,
        `SECURITY RED-TEAM BYPASS DETECTED on ${attack.id} (${attack.name})`
      ).toBe(true);
      expect(
        caughtByEngine,
        `Expected engine to fail closed on ${attack.id} (${attack.name})`
      ).toBe(true);
    }
  });

  describe.each(RED_TEAM_ATTACKS)("Adversarial Vector $id: $name", (attack) => {
    it(`fails closed against ${attack.targetDefenseLayer}`, async () => {
      await expect(
        engine.executeQuery(attack.sql, "analyst", "red-team-agent")
      ).rejects.toThrow();
    });
  });
});
