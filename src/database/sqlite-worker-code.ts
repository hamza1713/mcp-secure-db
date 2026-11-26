/**
 * Self-contained ESM worker script running Node's built-in `node:sqlite`
 * inside an isolated `node:worker_threads` OS thread.
 *
 * Loaded via `data:text/javascript;base64,...` so it executes identically under
 * Vitest, `node --experimental-strip-types`, `mcp-use dev`, `mcp-use build`,
 * `dist/cli.js`, and container builds without bundler path assumptions.
 *
 * Lifecycle:
 * 1. Open `:memory:` (seeded) or file-backed SQLite (`{ readOnly: true }`).
 * 2. Run trusted pre-authorizer schema introspection (`sqlite_master` + `PRAGMA table_info`)
 *    for configured relations and compile explicit + regex-auto-tagged per-table PII rules.
 * 3. Apply SQLite untrusted-SQL hardening pragmas and install non-reentrant `setAuthorizer`.
 * 4. Emit `{ type: "ready", introspectedTables }` to parent thread.
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
  piiColumnsByTable,
  piiAutoTagPatterns,
  roleAllowedTables,
  extraAllowedViews,
  maxPageCount,
  maxAuthorizerOps,
  maxRows,
  workerResourceLimits,
} = workerData;

const ALLOWED_FUNCTIONS = new Set(allowedFunctionsList.map((f) => f.toLowerCase()));
const PII_COLUMNS = new Set((piiColumnsList || []).map((c) => c.toLowerCase()));
const TABLE_PII_MAP = new Map();
if (piiColumnsByTable && typeof piiColumnsByTable === "object") {
  for (const [tbl, cols] of Object.entries(piiColumnsByTable)) {
    TABLE_PII_MAP.set(tbl.toLowerCase(), new Set((cols || []).map((c) => c.toLowerCase())));
  }
}
const AUTO_TAG_REGEXES = (piiAutoTagPatterns || []).map((pat) => new RegExp(pat, "i"));
const EXTRA_VIEWS = (extraAllowedViews || []).map((v) => v.toLowerCase());

const openReadOnly = Boolean(sqliteDbPath && !extraSeedSql);
const db = sqliteDbPath
  ? new DatabaseSync(sqliteDbPath, openReadOnly ? { readOnly: true } : undefined)
  : new DatabaseSync(":memory:");

// 1. Seed initial analytical tables (and any test views before locking writes)
if (!sqliteDbPath) {
  db.exec(seedSql);
}
if (extraSeedSql) {
  db.exec(extraSeedSql);
}

// 2. Trusted startup schema introspection BEFORE installing setAuthorizer
function quoteIdent(name) {
  return '"' + String(name).replace(/"/g, '""') + '"';
}

const allConfiguredTables = new Set();
for (const roleKey of ["public_viewer", "analyst", "admin"]) {
  for (const tbl of (roleAllowedTables[roleKey] || [])) {
    allConfiguredTables.add(String(tbl).toLowerCase());
  }
}
for (const viewName of EXTRA_VIEWS) {
  allConfiguredTables.add(viewName);
}

const introspectedTables = [];
try {
  const rawObjects = db
    .prepare(
      "SELECT name, type FROM sqlite_master WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    .all();

  for (const obj of rawObjects) {
    const rawName = String(obj.name || "");
    const lowerName = rawName.toLowerCase();
    if (!lowerName) continue;
    if (allConfiguredTables.size > 0 && !allConfiguredTables.has(lowerName)) {
      continue;
    }

    const colRows = db.prepare(\`PRAGMA table_info(\${quoteIdent(rawName)})\`).all();
    const columns = colRows.map((c) => ({
      name: String(c.name || ""),
      type: String(c.type || "TEXT"),
    }));

    // Merge regex-auto-tagged PII columns into worker-side authorizer enforcement
    let tblPiiSet = TABLE_PII_MAP.get(lowerName);
    for (const col of columns) {
      const lowerCol = col.name.toLowerCase();
      if (AUTO_TAG_REGEXES.some((re) => re.test(lowerCol))) {
        if (!tblPiiSet) {
          tblPiiSet = new Set();
          TABLE_PII_MAP.set(lowerName, tblPiiSet);
        }
        tblPiiSet.add(lowerCol);
        PII_COLUMNS.add(lowerCol);
      }
    }

    let rowCount = 0;
    try {
      const cntRow = db.prepare(\`SELECT COUNT(*) AS cnt FROM \${quoteIdent(rawName)}\`).get();
      rowCount = Number(cntRow?.cnt ?? 0);
    } catch {
      rowCount = 0;
    }

    introspectedTables.push({
      name: lowerName,
      rowCount,
      columns,
    });
  }
} catch {
  // Non-fatal fallback if introspection is unavailable
}

// 3. Apply SQLite recommended hardening controls for untrusted SQL
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

// 4. Read back active pragma state before installing the compile-time authorizer
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

// Actively verify defensive mode blocks PRAGMA writable_schema = ON
let defensiveMode = false;
try {
  db.exec("PRAGMA writable_schema = ON;");
  const ws = Number(db.prepare("PRAGMA writable_schema").get()?.writable_schema ?? 0);
  if (ws === 1) {
    db.exec("PRAGMA writable_schema = OFF;");
    defensiveMode = false;
  } else {
    defensiveMode = true;
  }
} catch {
  defensiveMode = true;
}

function disambiguateColumnNames(rawColumns) {
  const seen = new Set();
  const result = [];
  for (let i = 0; i < rawColumns.length; i++) {
    const base = rawColumns[i] || \`col_\${i + 1}\`;
    if (!seen.has(base)) {
      seen.add(base);
      result.push(base);
      continue;
    }
    let suffix = 2;
    let candidate = \`\${base}_\${suffix}\`;
    while (seen.has(candidate)) {
      suffix += 1;
      candidate = \`\${base}_\${suffix}\`;
    }
    seen.add(candidate);
    result.push(candidate);
  }
  return result;
}

function isPiiColumnForTable(tableName, columnName) {
  if (!columnName) return false;
  const tblSet = TABLE_PII_MAP.get(tableName);
  if (tblSet && tblSet.has(columnName)) return true;
  return PII_COLUMNS.has(columnName);
}

// 5. Active per-statement policy state read by the non-reentrant authorizer callback
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

    if (activePolicy.role !== "admin" && isPiiColumnForTable(tableName, columnName)) {
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

function runQuery(sql, role, rowCap, params) {
  activePolicy = {
    role,
    allowedTables: buildAllowedTableSet(role),
    opCount: 0,
    deniedReason: null,
  };

  try {
    const stmt = db.prepare(sql);
    const colMeta = typeof stmt.columns === "function" ? stmt.columns() : [];
    const rawColumns = colMeta.map((c) => String(c.name));
    const columns = disambiguateColumnNames(rawColumns);

    // Additional origin-column check via StatementSync.columns() metadata
    if (role !== "admin") {
      for (const c of colMeta) {
        const originTbl = c.table ? String(c.table).toLowerCase() : "";
        const originCol = c.column ? String(c.column).toLowerCase() : "";
        if (originCol && isPiiColumnForTable(originTbl, originCol)) {
          throw new Error(
            \`Origin column '\${originTbl || "?"}.\${originCol}' is restricted PII for role '\${role}'\`
          );
        }
      }
    }

    const numericCap =
      rowCap === undefined || rowCap === null ? maxRows : Number(rowCap);
    const effectiveCap = Math.min(
      Math.max(0, Number.isFinite(numericCap) ? numericCap : maxRows),
      maxRows
    );

    if (effectiveCap === 0) {
      return {
        ok: true,
        columns,
        rows: [],
        authorizerOperations: activePolicy.opCount,
      };
    }

    const useArrayMode = typeof stmt.setReturnArrays === "function";
    if (useArrayMode) {
      stmt.setReturnArrays(true);
    }

    const bindParams = Array.isArray(params) ? params : [];
    const iterator = bindParams.length > 0 ? stmt.iterate(...bindParams) : stmt.iterate();
    const rows = [];
    for (const row of iterator) {
      if (useArrayMode && Array.isArray(row)) {
        const plainObj = {};
        for (let i = 0; i < columns.length; i++) {
          plainObj[columns[i]] = row[i];
        }
        rows.push(plainObj);
      } else {
        rows.push(Object.assign({}, row));
      }
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

  if (msg.type === "ping") {
    parentPort.postMessage({ id: msg.id, ok: true });
    return;
  }

  if (msg.type === "inspect_controls") {
    parentPort.postMessage({
      id: msg.id,
      ok: true,
      controls: {
        engine: "SQLite (node:sqlite DatabaseSync in worker_threads)",
        workerThread: true,
        readOnlyOpen: openReadOnly,
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
    const res = runQuery(msg.sql, msg.role, msg.rowCap, msg.params);
    parentPort.postMessage({
      id: msg.id,
      ...res,
    });
    return;
  }
});

parentPort.postMessage({ type: "ready", introspectedTables });
`;
