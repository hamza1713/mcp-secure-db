/**
 * Core types and interfaces for mcp-secure-db
 */

export type UserRole =
  | "unauthenticated"
  | "public_viewer"
  | "analyst"
  | "admin";

export type AuthSource = "oauth" | "token" | "insecure_demo" | "none";

export interface SecurityContext {
  principal: string;
  role: UserRole;
  authenticated: boolean;
  authSource: AuthSource;
  scopes: string[];
  allowedTools: string[];
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

export type AuditStatus =
  | "SUCCESS"
  | "BLOCKED_AUTH"
  | "BLOCKED_RBAC"
  | "BLOCKED_AST"
  | "BLOCKED_AUTHORIZER"
  | "BLOCKED_RESULT_POLICY"
  | "TIMEOUT"
  | "ERROR";

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  principal: string;
  role: UserRole;
  tool?: string;
  query: string;
  status: AuditStatus;
  executionTimeMs?: number;
  rowCount?: number;
  reason?: string;
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
