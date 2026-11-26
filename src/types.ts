/**
 * Core types and interfaces for mcp-secure-db
 */

export type UserRole =
  | "unauthenticated"
  | "public_viewer"
  | "analyst"
  | "admin";

export type AuthSource = "oauth" | "token" | "stdio_local" | "insecure_demo" | "none";

export interface SecurityContext {
  principal: string;
  role: UserRole;
  authenticated: boolean;
  authSource: AuthSource;
  scopes: string[];
  allowedTools: string[];
  tenantId?: string;
  denialReason?: string;
}

export interface ColumnMetadata {
  name: string;
  type: string;
  isPII: boolean;
  description: string;
}

export interface TableMetadata {
  name: string;
  description: string;
  adminOnly: boolean;
  rowCount: number;
  columns: ColumnMetadata[];
}

export interface SqliteSecurityControlsReport {
  engine: string;
  workerThread: boolean;
  readOnlyOpen?: boolean;
  defensiveMode: boolean;
  loadExtensionDisabled: boolean;
  queryOnlyPragma: number;
  trustedSchemaPragma: number;
  cellSizeCheckPragma: number;
  maxPageCountPragma: number;
  tempStorePragma: number;
  authorizerActive: boolean;
  workerResourceLimits: {
    maxOldGenerationSizeMb: number;
    maxYoungGenerationSizeMb: number;
    codeRangeSizeMb: number;
    stackSizeMb: number;
  };
}

export interface QueryExecutionResult {
  query: string;
  executionTimeMs: number;
  rowCount: number;
  limitApplied: number;
  columns: string[];
  rows: Record<string, unknown>[];
  authorizerOperations: number;
  untrustedData: boolean;
  untrustedDataNotice: string;
  sandbox: {
    engine: string;
    workerThread: boolean;
    workerMaxOldGenMb: number;
    sqliteMaxPageCount: number;
    timeoutMs: number;
    externalAccess: boolean;
    role: UserRole;
  };
}

export interface SqliteWorkerPoolStats {
  poolSize: number;
  activeWorkers: number;
  busyWorkers: number;
  queuedQueries: number;
  totalTerminations: number;
}

export type AuditStatus =
  | "SUCCESS"
  | "BLOCKED_AUTH"
  | "BLOCKED_RBAC"
  | "BLOCKED_AST"
  | "BLOCKED_AUTHORIZER"
  | "BLOCKED_RESULT_POLICY"
  | "BLOCKED_RATE_LIMIT"
  | "TIMEOUT"
  | "ERROR"
  | "ROTATION_ANCHOR";

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  requestId?: string;
  principal: string;
  role: UserRole;
  tenantId?: string;
  tool?: string;
  query: string;
  status: AuditStatus;
  executionTimeMs?: number;
  rowCount?: number;
  reason?: string;
  ruleFired?: string;
  persisted?: boolean;
  seq?: number;
  prevHash?: string;
  entryHash?: string;
  hashAlg?: "sha256" | "hmac-sha256";
}

export interface ValidationResult {
  valid: boolean;
  sanitizedQuery?: string;
  astType?: string;
  tablesAccessed: string[];
  columnsAccessed: string[];
  functionsUsed?: string[];
  limitInjected?: number;
  violationReason?: string;
}
