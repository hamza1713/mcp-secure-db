import { UserRole } from "../types.js";
import { PII_COLUMNS } from "./policy.js";

/**
 * Result-level policy checks providing defense in depth behind the AST validator
 * and SQLite compile-time authorizer.
 *
 * Even if an unexpected alias, view, expression, or adapter bug allowed a sensitive
 * value to reach query output for a non-admin caller, `enforceResultPolicy` fails
 * closed and refuses to return the result set.
 */

const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i;
const STRIPE_CUSTOMER_PATTERN = /\bcus_[A-Za-z0-9_]{4,}\b/i;
const WEBHOOK_SECRET_PATTERN = /\bwhsec_[A-Za-z0-9_]{4,}\b/i;
const API_KEY_PATTERN = /\b(?:pk|sk)_(?:live|test)_[A-Za-z0-9_]{4,}\b/i;
const IPV4_PATTERN =
  /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/;

/**
 * Canonical sensitive seed tokens (case-folded) used to catch partial/transformed
 * leaks (e.g. SUBSTR(billing_email, 1, 10), UPPER(...), REPLACE(..., '@', '#')).
 */
const DEFAULT_SENSITIVE_SUBSTRINGS = [
  "billing@acme",
  "finance@globex",
  "accounts@soylent",
  "peter@initech",
  "redqueen@umbrella",
  "cus_9921",
  "cus_3341",
  "cus_1120",
  "cus_8874",
  "cus_6652",
  "whsec_9872",
  "whsec_4412",
  "whsec_5541",
  "whsec_6654",
  "198.51.100.44",
  "203.0.113.89",
  "192.0.2.110",
];

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

  const substrings = [
    ...DEFAULT_SENSITIVE_SUBSTRINGS,
    ...extraSensitiveSubstrings.map((s) => s.toLowerCase()),
  ];

  // 2. Fail closed on cell values matching PII patterns or sensitive value fingerprints
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
      if (IPV4_PATTERN.test(strVal)) {
        throw new SecurityResultPolicyViolation(
          `ResultPolicyViolation: client IPv4 address detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
        );
      }

      const lowerVal = strVal.toLowerCase();
      for (const token of substrings) {
        if (token.length >= 6 && lowerVal.includes(token)) {
          throw new SecurityResultPolicyViolation(
            `ResultPolicyViolation: restricted PII substring detected in column '${col}' (row ${rowIdx}) for role '${role}'.`
          );
        }
      }
    }
  }
}
