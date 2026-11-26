import { UserRole } from "../types.js";
import { PII_COLUMNS } from "./policy.js";

/**
 * Result-level policy checks providing defense in depth behind the AST validator
 * and database-native authorizer / role permissions.
 *
 * Even if an unexpected alias, view, expression, or adapter bug allowed a sensitive
 * value to reach query output for a non-admin caller, `enforceResultPolicy` fails
 * closed and refuses to return the result set.
 */

const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const SSN_PATTERN = /\b\d{3}-\d{2}-\d{4}\b/;
const JWT_PATTERN =
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/;
const STRIPE_CUSTOMER_PATTERN = /\bcus_[A-Za-z0-9_]{4,}\b/i;
const WEBHOOK_SECRET_PATTERN = /\bwhsec_[A-Za-z0-9_]{4,}\b/i;
const API_KEY_PATTERN = /\b(?:pk|sk)_(?:live|test)_[A-Za-z0-9_]{4,}\b/i;
const GENERIC_SECRET_PATTERN =
  /\b(?:(?:stripe|gemini|aws|redis|gcp|azure|openai|anthropic)[-_](?:mock[-_])?(?:secret|key|token)[-_][A-Za-z0-9_-]{4,}|gh[po]_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b/i;
const IPV4_PATTERN =
  /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/;
const VERSION_COLUMN_PATTERN =
  /(?:^|_)(?:version|ver|semver|release|build)$/i;
const VERSION_PREFIX_PATTERN = /^v\d+\.\d+\.\d+\.\d+$/i;

export class SecurityResultPolicyViolation extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecurityResultPolicyViolation";
  }
}

export interface ResultPolicyInput {
  role: UserRole;
  columns: string[];
  rows: Record<string, unknown>[];
  extraSensitiveSubstrings?: string[];
}

export function enforceResultPolicy(input: ResultPolicyInput): void {
  const { role, columns, rows, extraSensitiveSubstrings = [] } = input;

  if (role === "unauthenticated") {
    throw new SecurityResultPolicyViolation(
      "ResultPolicyViolation: unauthenticated callers may not receive query results."
    );
  }

  // Admin holds explicit db:pii:access scope
  if (role === "admin") {
    return;
  }

  // 1. Fail closed on output column names matching protected PII identifiers
  for (const col of columns) {
    const normalizedCol = col.trim().toLowerCase();
    if (PII_COLUMNS.has(normalizedCol)) {
      throw new SecurityResultPolicyViolation(
        `ResultPolicyViolation: output column '${col}' is restricted PII for role '${role}'.`
      );
    }
  }

  const substrings = extraSensitiveSubstrings
    .map((s) => s.toLowerCase())
    .filter((s) => s.length >= 6);

  // 2. Fail closed on cell values matching PII patterns or caller-supplied fingerprints
  for (let rowIdx = 0; rowIdx < rows.length; rowIdx++) {
    const row = rows[rowIdx];
    for (const [col, val] of Object.entries(row)) {
      if (val === null || val === undefined) continue;
      const strVal =
        typeof val === "string"
          ? val
          : val instanceof Uint8Array
            ? Buffer.from(val).toString("utf8")
            : String(val);

      if (!strVal) continue;

      if (EMAIL_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: email value detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }
      if (SSN_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: SSN pattern detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }
      if (JWT_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: JWT credential detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }
      if (STRIPE_CUSTOMER_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: payment customer identifier detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }
      if (WEBHOOK_SECRET_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: webhook signing secret detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }
      if (API_KEY_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: API key value detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }
      if (GENERIC_SECRET_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: secret token value detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }

      const trimmedCol = col.trim();
      const trimmedVal = strVal.trim();
      const isVersionContext =
        VERSION_COLUMN_PATTERN.test(trimmedCol) ||
        VERSION_PREFIX_PATTERN.test(trimmedVal);
      if (!isVersionContext && IPV4_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: client IPv4 address detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }

      if (substrings.length > 0) {
        const lowerVal = strVal.toLowerCase();
        for (const token of substrings) {
          if (lowerVal.includes(token)) {
            throw new SecurityResultPolicyViolation(
              `ResultPolicyViolation: restricted PII substring detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
            );
          }
        }
      }
    }
  }
}
