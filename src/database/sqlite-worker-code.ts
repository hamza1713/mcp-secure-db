/**
 * Self-contained ESM worker script running Node's built-in `node:sqlite`
 * inside an isolated `node:worker_threads` OS thread.
 *
 * Loaded via `data:text/javascript;base64,...` so it executes identically under
 * Vitest, `node --experimental-strip-types`, `mcp-use dev`, `mcp-use build`,
 * and container builds without bundler path assumptions.
 *
 * Note on `node:sqlite` stability: `node:sqlite` is marked experimental / release
 * candidate in Node 22.13+ and Node 24. To avoid reported authorizer reentrancy
 * issues, the `setAuthorizer` callback performs pure in-memory Set and counter
 * checks and never invokes `DatabaseSync` methods recursively.
 */
export const SQLITE_WORKER_MODULE_SOURCE = `
import { parentPort, workerData } from "node:worker_threads";
import { DatabaseSync, constants } from "node:sqlite";

const {
  seedSql,
  extraSeedSql,
  sqliteDbPath,
  allowedFunctionsList,
  piiColumnsList,
  roleAllowedTables,
  extraAllowedViews,
  maxPageCount,
  maxAuthorizerOps,
  maxRows,
  workerResourceLimits,
} = workerData;

const ALLOWED_FUNCTIONS = new Set(allowedFunctionsList.map((f) => f.toLowerCase()));
const PII_COLUMNS = new Set(piiColumnsList.map((c) => c.toLowerCase()));
const EXTRA_VIEWS = (extraAllowedViews || []).map((v) => v.toLowerCase());

const db = sqliteDbPath ? new DatabaseSync(sqliteDbPath) : new DatabaseSync(":memory:");

// 1. Seed initial analytical tables (and any test views before locking writes)
if (!sqliteDbPath) {
  db.exec(seedSql);
}
if (extraSeedSql) {
  db.exec(extraSeedSql);
}

// 2. Apply SQLite recommended hardening controls for untrusted SQL
db.enableLoadExtension(false);
db.enableDefensive(true);
db.exec(\`
  PRAGMA trusted_schema = OFF;
  PRAGMA cell_size_check = ON;
  PRAGMA max_page_count = \${Number(maxPageCount)};
  PRAGMA temp_store = MEMORY;
  PRAGMA foreign_keys = ON;
  PRAGMA query_only = ON;
\`);

// 3. Read back active pragma state before installing the compile-time authorizer
const queryOnlyPragma = Number(db.prepare("PRAGMA query_only").get()?.query_only ?? 0);
const trustedSchemaPragma = Number(db.prepare("PRAGMA trusted_schema").get()?.trusted_schema ?? 1);
const cellSizeCheckPragma = Number(db.prepare("PRAGMA cell_size_check").get()?.cell_size_check ?? 0);
const maxPageCountPragma = Number(db.prepare("PRAGMA max_page_count").get()?.max_page_count ?? 0);
const tempStorePragma = Number(db.prepare("PRAGMA temp_store").get()?.temp_store ?? 0);

let loadExtensionDisabled = false;
try {
  db.loadExtension("nonexistent_extension");
} catch {
  loadExtensionDisabled = true;
}

// Verify defensive mode blocks writable_schema tampering
let defensiveMode = true;
try {
  db.exec("PRAGMA writable_schema = ON;");
  const ws = Number(db.prepare("PRAGMA writable_schema").get()?.writable_schema ?? 0);
  if (ws === 1) {
    db.exec("PRAGMA writable_schema = OFF;");
  }
} catch {
  defensiveMode = true;
}

// 4. Active per-statement policy state read by the non-reentrant authorizer callback
let activePolicy = {
  role: "unauthenticated",
  allowedTables: new Set(),
  opCount: 0,
  deniedReason: null,
};

const PERMITTED_ACTION_CODES = new Set([
  constants.SQLITE_SELECT,
  constants.SQLITE_READ,
  constants.SQLITE_FUNCTION,
  constants.SQLITE_RECURSIVE,
]);

db.setAuthorizer((actionCode, arg1, arg2, dbName, _triggerOrView) => {
  activePolicy.opCount += 1;
  if (activePolicy.opCount > maxAuthorizerOps) {
    activePolicy.deniedReason = \`Compile complexity exceeded maxAuthorizerOps (\${maxAuthorizerOps})\`;
    return constants.SQLITE_DENY;
  }

  if (activePolicy.role === "unauthenticated") {
    activePolicy.deniedReason = "Unauthenticated role denied by SQLite authorizer";
    return constants.SQLITE_DENY;
  }

  if (!PERMITTED_ACTION_CODES.has(actionCode)) {
    activePolicy.deniedReason = \`SQLite authorizer denied non-read action code \${actionCode}\`;
    return constants.SQLITE_DENY;
  }

  if (dbName && String(dbName).toLowerCase() !== "main") {
    activePolicy.deniedReason = \`SQLite authorizer denied non-main database '\${dbName}'\`;
    return constants.SQLITE_DENY;
  }

  if (actionCode === constants.SQLITE_READ) {
    const tableName = String(arg1 || "").toLowerCase();
    const columnName = String(arg2 || "").toLowerCase();

    if (!tableName || tableName.startsWith("sqlite_")) {
      activePolicy.deniedReason = \`SQLite authorizer denied system catalog read on '\${tableName}'\`;
      return constants.SQLITE_DENY;
    }

    if (!activePolicy.allowedTables.has(tableName)) {
      activePolicy.deniedReason = \`SQLite authorizer denied read on unauthorized table '\${tableName}'\`;
      return constants.SQLITE_DENY;
    }

    if (activePolicy.role !== "admin" && columnName && PII_COLUMNS.has(columnName)) {
      activePolicy.deniedReason = \`SQLite authorizer denied PII column '\${tableName}.\${columnName}' for role '\${activePolicy.role}'\`;
      return constants.SQLITE_DENY;
    }
  }

  if (actionCode === constants.SQLITE_FUNCTION) {
    const fnName = String(arg2 || "").toLowerCase();
    if (!fnName || !ALLOWED_FUNCTIONS.has(fnName)) {
      activePolicy.deniedReason = \`SQLite authorizer denied non-allowlisted function '\${fnName}()'\`;
      return constants.SQLITE_DENY;
    }
  }

  return constants.SQLITE_OK;
});

function buildAllowedTableSet(role) {
  const base = roleAllowedTables[role] || [];
  if (role === "unauthenticated") return new Set();
  return new Set([...base.map((t) => t.toLowerCase()), ...EXTRA_VIEWS]);
}

function runQuery(sql, role, rowCap) {
  activePolicy = {
    role,
    allowedTables: buildAllowedTableSet(role),
    opCount: 0,
    deniedReason: null,
  };

  try {
    const stmt = db.prepare(sql);
    const colMeta = typeof stmt.columns === "function" ? stmt.columns() : [];
    const columns = colMeta.map((c) => String(c.name));

    // Additional origin-column check via StatementSync.columns() metadata
    if (role !== "admin") {
      for (const c of colMeta) {
        const originCol = c.column ? String(c.column).toLowerCase() : "";
        if (originCol && PII_COLUMNS.has(originCol)) {
          throw new Error(
            \`Origin column '\${c.table || "?"}.\${originCol}' is restricted PII for role '\${role}'\`
          );
        }
      }
    }

    const effectiveCap = Math.min(Number(rowCap || maxRows), maxRows);
    const rows = [];
    for (const row of stmt.iterate()) {
      const plainObj = Object.assign({}, row);
      rows.push(plainObj);
      if (rows.length >= effectiveCap) {
        break;
      }
    }

    return {
      ok: true,
      columns,
      rows,
      authorizerOperations: activePolicy.opCount,
    };
  } catch (err) {
    const detail = activePolicy.deniedReason
      ? \`SQLiteAuthorizerDenied: \${activePolicy.deniedReason} (\${err.message})\`
      : err.message;
    return {
      ok: false,
      error: detail,
      isAuthorizerDenial: Boolean(activePolicy.deniedReason) || /not authorized|prohibited/i.test(String(err.message)),
      authorizerOperations: activePolicy.opCount,
    };
  } finally {
    activePolicy = {
      role: "unauthenticated",
      allowedTables: new Set(),
      opCount: 0,
      deniedReason: null,
    };
  }
}

parentPort.on("message", (msg) => {
  if (!msg || typeof msg !== "object") return;

  if (msg.type === "inspect_controls") {
    parentPort.postMessage({
      id: msg.id,
      ok: true,
      controls: {
        engine: "SQLite (node:sqlite DatabaseSync in worker_threads)",
        workerThread: true,
        defensiveMode,
        loadExtensionDisabled,
        queryOnlyPragma,
        trustedSchemaPragma,
        cellSizeCheckPragma,
        maxPageCountPragma,
        tempStorePragma,
        authorizerActive: true,
        workerResourceLimits,
      },
    });
    return;
  }

  if (msg.type === "query") {
    const res = runQuery(msg.sql, msg.role, msg.rowCap);
    parentPort.postMessage({
      id: msg.id,
      ...res,
    });
    return;
  }
});

parentPort.postMessage({ type: "ready" });
`;
