import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  loadPolicyFromFile,
  resolvePolicyObject,
} from "../src/policy/loader.js";
import { createSecureMcpServer } from "../src/index.js";

const SCRATCH_DIR = path.resolve(process.cwd(), "tests", "scratch");
const HOSPITAL_DB_PATH = path.join(SCRATCH_DIR, "hospital-byodb.db");
const HOSPITAL_POLICY_PATH = path.join(SCRATCH_DIR, "hospital.policy.yaml");

async function sendRpc(
  srv: { fetch: (req: Request) => Promise<Response> },
  body: Record<string, unknown>,
  headers: Record<string, string> = {}
) {
  const req = new Request("http://localhost/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const res = await srv.fetch(req);
  const text = await res.text();
  if (text.trim().startsWith("{")) return JSON.parse(text);
  const dataLines = text
    .split(/\r?\n/)
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim())
    .filter(Boolean);
  return JSON.parse(dataLines[dataLines.length - 1]);
}

describe("Phase 2: Declarative policy.yaml & Live BYO-DB Schema Introspection", () => {
  beforeAll(() => {
    fs.mkdirSync(SCRATCH_DIR, { recursive: true });
    if (fs.existsSync(HOSPITAL_DB_PATH)) fs.unlinkSync(HOSPITAL_DB_PATH);

    // Build a completely custom database unrelated to built-in demo schemas
    const db = new DatabaseSync(HOSPITAL_DB_PATH);
    db.exec(`
      CREATE TABLE patients (
        id INTEGER PRIMARY KEY,
        full_name TEXT NOT NULL,
        region TEXT NOT NULL,
        medical_record_num TEXT NOT NULL,
        patient_email TEXT NOT NULL,
        ssn_number TEXT NOT NULL
      );
      INSERT INTO patients VALUES
        (1, 'Alice Mercer', 'west', 'MRN-8812', 'alice.mercer@clinic.example.org', '111-22-3333'),
        (2, 'Brian Cho', 'east', 'MRN-9941', 'brian.cho@clinic.example.org', '444-55-6666');

      CREATE TABLE appointments (
        id INTEGER PRIMARY KEY,
        patient_id INTEGER NOT NULL,
        department TEXT NOT NULL,
        visit_date TEXT NOT NULL,
        cost_usd REAL NOT NULL
      );
      INSERT INTO appointments VALUES
        (10, 1, 'cardiology', '2026-11-01', 420.00),
        (11, 2, 'radiology', '2026-11-02', 310.50);

      CREATE TABLE internal_vault (
        id INTEGER PRIMARY KEY,
        service TEXT NOT NULL,
        api_secret TEXT NOT NULL
      );
      INSERT INTO internal_vault VALUES
        (1, 'ehr-sync', 'stripe_mock_secret_1234567890ab');
    `);
    db.close();

    const yamlContent = `
version: 1
engine:
  type: sqlite
  sqlite_path: ./hospital-byodb.db
  statement_timeout_ms: 3000
adhoc_sql:
  enabled: true
  allowed_roles: [analyst, admin]
  default_limit: 50
  max_rows: 500
  max_offset: 5000
roles:
  public_viewer:
    tables: [appointments]
  analyst:
    tables: [patients, appointments]
  admin:
    tables: [patients, appointments, internal_vault]
    allow_pii: true
pii:
  columns:
    patients: [medical_record_num]
templates:
  - name: appointments_by_dept
    description: "Summarize appointment count and cost for a clinical department"
    allowed_roles: [public_viewer, analyst, admin]
    sql: "SELECT department, COUNT(id) AS visits, SUM(cost_usd) AS total_cost FROM appointments WHERE department = :dept GROUP BY department LIMIT 20"
    parameters:
      dept:
        type: string
        description: "Clinical department name"
        max_length: 64
`;
    fs.writeFileSync(HOSPITAL_POLICY_PATH, yamlContent, "utf8");
  });

  afterAll(async () => {
    await new Promise((r) => setTimeout(r, 80));
    for (const p of [HOSPITAL_DB_PATH, HOSPITAL_POLICY_PATH]) {
      if (fs.existsSync(p)) {
        try {
          fs.unlinkSync(p);
        } catch {
          // ignore cleanup lock
        }
      }
    }
  });

  it("introspects an arbitrary SQLite DB at startup, enforces default-deny tables, and merges explicit + regex PII auto-taggers", async () => {
    const policy = loadPolicyFromFile(HOSPITAL_POLICY_PATH);
    const instance = createSecureMcpServer({ policy });
    try {
      await instance.validateTemplates();

      // 1. Default-deny table visibility by role
      const viewerTables = instance.engine.getTables("public_viewer");
      expect(viewerTables.map((t) => t.name)).toEqual(["appointments"]);
      expect(viewerTables[0].rowCount).toBe(2);

      const analystTables = instance.engine.getTables("analyst");
      expect(analystTables.map((t) => t.name).sort()).toEqual([
        "appointments",
        "patients",
      ]);

      // 2. Explicit PII (medical_record_num) AND regex auto-tagged PII (patient_email, ssn_number) are hidden from analyst
      const patientColsForAnalyst =
        analystTables.find((t) => t.name === "patients")?.columns ?? [];
      expect(patientColsForAnalyst).toEqual(["id", "full_name", "region"]);
      expect(patientColsForAnalyst).not.toContain("medical_record_num");
      expect(patientColsForAnalyst).not.toContain("patient_email");
      expect(patientColsForAnalyst).not.toContain("ssn_number");

      const schemaForAnalyst = instance.engine.getTableSchema(
        "patients",
        "analyst"
      );
      expect(schemaForAnalyst?.redactedPiiColumnCount).toBe(3);

      // 3. schema://catalog resource reflects live-introspected BYO-DB tables dynamically
      const catalog = instance.engine.getFilteredCatalog("analyst");
      expect(Object.keys(catalog).sort()).toEqual(["appointments", "patients"]);
      expect(catalog.patients.redactedPiiColumnCount).toBe(3);

      // 4. Safe analytical query succeeds on arbitrary DB tables
      const okRes = await instance.engine.executeQuery(
        "SELECT p.full_name, a.department, a.cost_usd FROM patients p JOIN appointments a ON p.id = a.patient_id ORDER BY p.id ASC",
        "analyst",
        "hospital-analyst"
      );
      expect(okRes.rowCount).toBe(2);
      expect(okRes.limitApplied).toBe(50);
      expect(okRes.rows[0].full_name).toBe("Alice Mercer");

      // 5. Auto-tagged PII column (patient_email / ssn_number) & explicit PII (medical_record_num) fail closed
      for (const col of ["medical_record_num", "patient_email", "ssn_number"]) {
        await expect(
          instance.engine.executeQuery(
            `SELECT id, ${col} FROM patients`,
            "analyst",
            "hospital-analyst"
          )
        ).rejects.toThrow(/PII|denied/i);
      }

      // 6. Unlisted / admin-only table (internal_vault) fails closed for analyst, succeeds for admin
      await expect(
        instance.engine.executeQuery(
          "SELECT service FROM internal_vault",
          "analyst",
          "hospital-analyst"
        )
      ).rejects.toThrow(/admin|denied/i);

      const adminRes = await instance.engine.executeQuery(
        "SELECT service FROM internal_vault",
        "admin",
        "hospital-admin"
      );
      expect(adminRes.rowCount).toBe(1);
      expect(adminRes.rows[0].service).toBe("ehr-sync");

      // 7. Wire-level tools/call invokes the declared BYO-DB template cleanly
      const rpc = await sendRpc(
        instance.server,
        {
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "appointments_by_dept",
            arguments: { dept: "cardiology" },
          },
        },
        { authorization: "Bearer token-viewer-demo" }
      );
      expect(rpc.result.isError).toBeUndefined();
      const body = JSON.parse(rpc.result.content[0].text);
      expect(body.rowCount).toBe(1);
      expect(body.rows[0]).toEqual({
        department: "cardiology",
        visits: 1,
        total_cost: 420,
      });
    } finally {
      await instance.engine.close();
    }
  });

  it("rejects invalid policies: plaintext secrets, ReDoS regexes, and built-in tool name collisions", () => {
    // Rejects unknown plaintext connection_string / password keys (strict Zod schema)
    expect(() =>
      resolvePolicyObject(
        {
          version: 1,
          engine: {
            type: "postgres",
            connection_string: "postgres://user:supersecret@host/db",
          },
          roles: {
            public_viewer: { tables: [] },
            analyst: { tables: [] },
            admin: { tables: [] },
          },
        },
        process.cwd()
      )
    ).toThrow(/PolicyValidationError/);

    // Rejects ReDoS nested-quantifier PII regex
    expect(() =>
      resolvePolicyObject(
        {
          version: 1,
          roles: {
            public_viewer: { tables: [] },
            analyst: { tables: [] },
            admin: { tables: [] },
          },
          pii: {
            auto_tag_patterns: ["(a+)+$"],
          },
        },
        process.cwd()
      )
    ).toThrow(/PolicyValidationError/);

    // Rejects template colliding with built-in tool name
    expect(() =>
      resolvePolicyObject(
        {
          version: 1,
          roles: {
            public_viewer: { tables: [] },
            analyst: { tables: [] },
            admin: { tables: [] },
          },
          templates: [
            {
              name: "list_tables",
              description: "Shadows built-in tool",
              allowed_roles: ["analyst"],
              sql: "SELECT 1",
            },
          ],
        },
        process.cwd()
      )
    ).toThrow(/PolicyValidationError/);
  });
});
