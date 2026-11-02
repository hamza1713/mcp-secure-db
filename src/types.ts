/**
 * Types and interfaces for mcp-secure-db
 */

export type UserRole = "public_viewer" | "analyst" | "admin";

export interface SecurityContext {
  principal: string;
  role: UserRole;
  scopes: string[];
  allowedTools: string[];
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

export interface QueryExecutionResult {
  query: string;
  executionTimeMs: number;
  rowCount: number;
  limitApplied: number;
  columns: string[];
  rows: Record<string, unknown>[];
  sandbox: {
    engine: string;
    memoryLimit: string;
    timeoutSeconds: number;
    externalAccess: boolean;
    role: UserRole;
  };
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  principal: string;
  role: UserRole;
  query: string;
  status: "SUCCESS" | "BLOCKED_RBAC" | "BLOCKED_AST" | "TIMEOUT" | "ERROR";
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
  limitInjected?: number;
  violationReason?: string;
}
