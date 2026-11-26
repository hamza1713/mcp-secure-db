/**
 * Reproducible 60-Second Security & Architecture Showcase (`pnpm run showcase`)
 *
 * Demonstrates end-to-end without any external API keys or Docker requirement:
 *  1. Arbitrary BYO SQLite database loaded via declarative policy + live introspection + regex PII auto-tagging
 *  2. Default-deny RBAC & multi-tenant isolation via unspoofable `:ctx.tenant_id` template binding
 *  3. Multi-layer adversarial attack blocking (SQLi parameter binding, PII AST/DLP block, libpg-query PG WASM blocks)
 *  4. Configurable SQLite worker pool (x2) fault isolation: runaway recursive CTE kills Worker #1 while Worker #2 finishes cleanly
 *  5. Authenticated Prometheus `/metrics` scrape with counters, histograms, and pool gauges
 *  6. Tamper-evident HMAC-SHA256 hash-chained audit log verification + instant detection of 1-byte tampering
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { resolvePolicyObject } from "../src/policy/loader.js";
import { createSecureMcpServer } from "../src/index.js";
import { AuditLogger, verifyAuditLogFile } from "../src/database/audit.js";
import { MetricsRegistry } from "../src/observability/metrics.js";
import { StructuredLogger } from "../src/observability/logger.js";
import { PostgresAstValidator } from "../src/security/pg-ast-validator.js";
import { SecureDatabaseEngine, QueryTimeoutError } from "../src/database/engine.js";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Showcase assertion failed: ${message}`);
  }
}

async function rpc(
  server: { fetch: (req: Request) => Promise<Response> },
  method: string,
  params: Record<string, unknown>,
  token?: string
): Promise<any> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  if (token) headers.authorization = `Bearer ${token}`;

  const res = await server.fetch(
    new Request("http://localhost/mcp", {
      method: "POST",
      headers,
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    })
  );
  const text = await res.text();
  if (text.trim().startsWith("{")) return JSON.parse(text);
  const dataLines = text
    .split(/\r?\n/)
    .filter((l) => l.startsWith("data:"))
    .map((l) => l.slice(5).trim())
    .filter(Boolean);
  return JSON.parse(dataLines[dataLines.length - 1]);
}

export async function runSecurityShowcase(
  options: { quiet?: boolean } = {}
): Promise<{ stagesPassed: number; verifiedAuditEntries: number }> {
  const log = options.quiet ? () => {} : console.log.bind(console);
  const printSection = (num: number, title: string) => {
    log(`\n====================================================================`);
    log(`  [${num}/6] ${title}`);
    log(`====================================================================`);
  };
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-secure-db-showcase-"));
  const dbPath = path.join(tmpDir, "saas_tenants.db");
  const auditPath = path.join(tmpDir, "showcase-audit.jsonl");
  const hmacKey = "showcase-demo-hmac-key-2026";
  const metricsToken = "showcase-metrics-scrape-token";

  const prevApiKeys = process.env.MCP_SECURE_DB_API_KEYS;
  const prevMetricsToken = process.env.MCP_SECURE_DB_METRICS_TOKEN;
  const prevMetricsPublic = process.env.MCP_SECURE_DB_METRICS_PUBLIC;

  process.env.MCP_SECURE_DB_API_KEYS = JSON.stringify([
    {
      token: "key-acme-analyst",
      principal: "alice@acme.example",
      role: "analyst",
      tenantId: "tenant_acme",
    },
    {
      token: "key-globex-analyst",
      principal: "bob@globex.example",
      role: "analyst",
      tenantId: "tenant_globex",
    },
    {
      token: "key-notenant-analyst",
      principal: "unscoped@ops.example",
      role: "analyst",
    },
    {
      token: "key-secops-admin",
      principal: "secops@platform.example",
      role: "admin",
    },
  ]);
  process.env.MCP_SECURE_DB_METRICS_TOKEN = metricsToken;
  process.env.MCP_SECURE_DB_METRICS_PUBLIC = "false";

  // Provision a brand-new arbitrary BYO multi-tenant SQLite database
  const seedDb = new DatabaseSync(dbPath);
  seedDb.exec(`
    CREATE TABLE invoices (
      id INTEGER PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      region TEXT NOT NULL,
      amount_usd REAL NOT NULL,
      customer_email TEXT NOT NULL
    );
    CREATE TABLE internal_vault (
      id INTEGER PRIMARY KEY,
      secret_token TEXT NOT NULL
    );
    INSERT INTO invoices VALUES
      (1, 'tenant_acme', 'us-east', 4200.50, 'ap@acme.example.com'),
      (2, 'tenant_acme', 'eu-west', 1850.00, 'eu@acme.example.com'),
      (3, 'tenant_globex', 'us-east', 9900.00, 'finance@globex.example.com');
    INSERT INTO internal_vault VALUES
      (1, 'sk_live_vault_secret_881234');
  `);
  seedDb.close();

  const policy = resolvePolicyObject(
    {
      version: 1,
      engine: {
        type: "sqlite",
        sqlite_path: dbPath,
        statement_timeout_ms: 400,
        worker_pool_size: 2,
      },
      tenant_isolation: {
        enabled: true,
        require_tenant_id: true,
      },
      adhoc_sql: {
        enabled: true,
        allowed_roles: ["analyst", "admin"],
      },
      roles: {
        public_viewer: { tables: ["invoices"] },
        analyst: { tables: ["invoices"] },
        admin: { tables: ["invoices", "internal_vault"], allow_pii: true },
      },
      pii: {
        columns: {},
        auto_tag_patterns: ["(?:^|_)(?:email|secret|token)(?:$|_)"],
      },
      templates: [
        {
          name: "tenant_invoices_by_region",
          description:
            "Query invoices strictly scoped to the caller's verified tenant",
          allowed_roles: ["analyst", "admin"],
          sql: "SELECT id, tenant_id, region, amount_usd FROM invoices WHERE tenant_id = :ctx.tenant_id AND region = :region ORDER BY id LIMIT 20",
          parameters: {
            region: {
              type: "string",
              description: "Cloud billing region",
              required: true,
            },
          },
        },
      ],
    },
    tmpDir,
    path.join(tmpDir, "policy.yaml")
  );

  const audit = new AuditLogger({ logFilePath: auditPath, hmacKey });
  const metrics = new MetricsRegistry();
  const logger = new StructuredLogger({ enabled: false });
  const engine = new SecureDatabaseEngine({
    policy,
    timeoutMs: 250,
    workerPoolSize: 2,
    metrics,
    audit,
  });

  const instance = createSecureMcpServer({
    policy,
    engine,
    audit,
    metrics,
    logger,
  });

  try {
    // 1. Live BYO-DB Introspection + Regex PII Auto-Tagging
    printSection(1, "BYO-DB Live Schema Introspection & Regex PII Auto-Tagging");
    await instance.validateTemplates();
    const analystTables = engine.getTables("analyst");
    log(
      `  Introspected tables for analyst: ${JSON.stringify(analystTables)}`
    );
    assert(analystTables.length === 1 && analystTables[0].name === "invoices", "default-deny table list");
    assert(
      !analystTables[0].columns.includes("customer_email"),
      "customer_email auto-tagged as PII and hidden from analyst"
    );
    log(
      "  OK: 'internal_vault' hidden by default-deny; 'customer_email' auto-tagged PII via regex."
    );

    // 2. Default-Deny RBAC + Multi-Tenant `:ctx.tenant_id` Isolation
    printSection(2, "Default-Deny RBAC & Unspoofable Multi-Tenant :ctx.tenant_id");
    const unauthTools = await rpc(instance.server, "tools/list", {});
    const unauthNames = unauthTools.result.tools.map((t: any) => t.name);
    log(`  Unauthenticated visible tools: ${JSON.stringify(unauthNames)}`);
    assert(
      unauthNames.length === 1 && unauthNames[0] === "whoami",
      "unauthenticated sees only whoami"
    );

    // Acme analyst attempts to spoof tenant_globex in arguments — server ignores arg and uses verified tenant_acme
    const acmeCall = await rpc(
      instance.server,
      "tools/call",
      {
        name: "tenant_invoices_by_region",
        arguments: {
          region: "us-east",
          tenant_id: "tenant_globex",
          "ctx.tenant_id": "tenant_globex",
        },
      },
      "key-acme-analyst"
    );
    const acmePayload = JSON.parse(acmeCall.result.content[0].text);
    log(
      `  Acme analyst rows (with spoofed tenant_globex arg): ${JSON.stringify(acmePayload.rows)}`
    );
    assert(
      acmePayload.rows.length === 1 && acmePayload.rows[0].tenant_id === "tenant_acme",
      "strictly tenant_acme row returned"
    );

    // Unscoped analyst (no tenantId) fails closed
    const noTenantCall = await rpc(
      instance.server,
      "tools/call",
      {
        name: "tenant_invoices_by_region",
        arguments: { region: "us-east" },
      },
      "key-notenant-analyst"
    );
    assert(noTenantCall.result.isError === true, "missing tenantId must fail closed");
    log(`  Unscoped analyst blocked: ${noTenantCall.result.content[0].text}`);

    // 3. Multi-Layer Attack Blocking (SQLi param + PII AST + libpg-query PG WASM)
    printSection(3, "Multi-Layer Attack Blocking (SQLi, PII AST & libpg-query PG WASM)");
    const sqliParamCall = await rpc(
      instance.server,
      "tools/call",
      {
        name: "tenant_invoices_by_region",
        arguments: { region: "' OR '1'='1" },
      },
      "key-acme-analyst"
    );
    const sqliPayload = JSON.parse(sqliParamCall.result.content[0].text);
    assert(sqliPayload.rowCount === 0, "SQLi string bound safely as literal parameter");
    log("  OK: SQLi payload `' OR '1'='1` bound natively -> 0 rows returned.");

    const piiAttempt = await rpc(
      instance.server,
      "tools/call",
      {
        name: "execute_analytical_sql",
        arguments: { query: "SELECT id, customer_email FROM invoices" },
      },
      "key-acme-analyst"
    );
    assert(piiAttempt.result.isError === true, "PII column blocked by AST validator");
    log(`  OK: PII query blocked -> ${piiAttempt.result.content[0].text}`);

    const pgValidator = new PostgresAstValidator();
    const pgDoBlock = pgValidator.validate("DO $$ BEGIN PERFORM pg_sleep(5); END $$;", "admin");
    const pgCopyBlock = pgValidator.validate("COPY customers TO PROGRAM 'id'", "admin");
    assert(!pgDoBlock.valid && !pgCopyBlock.valid, "libpg-query blocks DO $$ and COPY TO PROGRAM");
    log(`  OK: libpg-query WASM blocked DO $$ -> ${pgDoBlock.violationReason}`);
    log(`  OK: libpg-query WASM blocked COPY TO PROGRAM -> ${pgCopyBlock.violationReason}`);

    // 4. SQLite Worker Pool Fault Isolation (2 Workers)
    printSection(4, "SQLite Worker Pool (x2) Hard-Deadline Fault Isolation");
    const runawaySql =
      "WITH RECURSIVE spin(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM spin WHERE n < 20000000) SELECT SUM(n) AS total FROM spin";
    const fastSql = "SELECT COUNT(*) AS cnt FROM invoices";

    const [runawayOutcome, fastOutcome] = await Promise.allSettled([
      engine.executeQuery(runawaySql, "analyst", "attacker@acme.example", {
        tenantId: "tenant_acme",
      }),
      engine.executeQuery(fastSql, "analyst", "alice@acme.example", {
        tenantId: "tenant_acme",
      }),
    ]);

    assert(
      runawayOutcome.status === "rejected" &&
        runawayOutcome.reason instanceof QueryTimeoutError,
      "runaway recursive CTE terminated at deadline"
    );
    assert(
      fastOutcome.status === "fulfilled" && fastOutcome.value.rows[0].cnt === 3,
      "concurrent fast query survived on sibling worker"
    );
    log(
      `  OK: Worker terminated runaway CTE (${engine.getWorkerTerminationCount()} kill) while sibling worker completed fast query in ${fastOutcome.value.executionTimeMs}ms.`
    );

    // 5. Authenticated Prometheus `/metrics` Scrape
    printSection(5, "Authenticated Prometheus /metrics Exposition");
    const unauthMetrics = await instance.server.fetch(
      new Request("http://localhost/metrics")
    );
    assert(unauthMetrics.status === 401, "unauthenticated /metrics returns 401");

    const authMetrics = await instance.server.fetch(
      new Request("http://localhost/metrics", {
        headers: { authorization: `Bearer ${metricsToken}` },
      })
    );
    assert(authMetrics.status === 200, "token-authenticated /metrics returns 200");
    const metricsBody = await authMetrics.text();
    assert(
      metricsBody.includes("mcp_secure_db_worker_terminations_total 1"),
      "Prometheus /metrics reflects worker termination counter"
    );
    const previewLines = metricsBody
      .split("\n")
      .filter((l) => l && !l.startsWith("#"))
      .slice(0, 12);
    log("  Sample Prometheus metrics:");
    for (const line of previewLines) {
      log(`    ${line}`);
    }

    // 6. Tamper-Evident HMAC-SHA256 Hash-Chained Audit Verification
    printSection(6, "Tamper-Evident HMAC-SHA256 Audit Chain & Tamper Detection");
    // Write a few additional chained entries through the isolated showcase audit logger
    audit.log({
      requestId: "req_showcase_1",
      principal: "alice@acme.example",
      role: "analyst",
      tenantId: "tenant_acme",
      tool: "tenant_invoices_by_region",
      query: "SELECT id, amount_usd FROM invoices WHERE tenant_id = ?",
      status: "SUCCESS",
      rowCount: 1,
    });
    audit.log({
      requestId: "req_showcase_2",
      principal: "attacker@acme.example",
      role: "analyst",
      tenantId: "tenant_acme",
      tool: "execute_analytical_sql",
      query: "SELECT customer_email FROM invoices",
      status: "BLOCKED_AST",
      reason: "PII column blocked",
    });

    const intact = verifyAuditLogFile(auditPath, { hmacKey });
    assert(intact.valid && intact.algorithm === "hmac-sha256", "intact HMAC chain verified");
    log(
      `  Intact verification: valid=${intact.valid}, entries=${intact.totalEntries}, alg=${intact.algorithm}, lastSeq=${intact.lastSeq}`
    );

    // Simulate 1-byte tampering of the persisted audit log
    const originalContent = fs.readFileSync(auditPath, "utf8");
    const tamperedContent = originalContent.replace("BLOCKED_AST", "SUCCESS_ALT");
    fs.writeFileSync(auditPath, tamperedContent, "utf8");

    const tampered = verifyAuditLogFile(auditPath, { hmacKey });
    assert(!tampered.valid && tampered.failureSeq !== undefined, "tampering must be detected");
    log(
      `  After 1-field edit: valid=${tampered.valid}, failureLine=${tampered.failureLine}, failureSeq=${tampered.failureSeq}`
    );
    log(`  Detection detail: ${tampered.error}`);

    log("\nALL 6 SHOWCASE STAGES PASSED.\n");
    return {
      stagesPassed: 6,
      verifiedAuditEntries: intact.totalEntries,
    };
  } finally {
    await instance.engine.close();
    if (prevApiKeys === undefined) delete process.env.MCP_SECURE_DB_API_KEYS;
    else process.env.MCP_SECURE_DB_API_KEYS = prevApiKeys;
    if (prevMetricsToken === undefined) delete process.env.MCP_SECURE_DB_METRICS_TOKEN;
    else process.env.MCP_SECURE_DB_METRICS_TOKEN = prevMetricsToken;
    if (prevMetricsPublic === undefined) delete process.env.MCP_SECURE_DB_METRICS_PUBLIC;
    else process.env.MCP_SECURE_DB_METRICS_PUBLIC = prevMetricsPublic;
    try {
      fs.rmSync(tmpDir, {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 50,
      });
    } catch {
      // Best-effort temp directory cleanup on Windows
    }
  }
}

const isMain =
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

if (isMain) {
  runSecurityShowcase()
    .then(() => {
      process.exit(0);
    })
    .catch((err) => {
      console.error(`[showcase] FAILED: ${err.message}`);
      process.exit(1);
    });
}
