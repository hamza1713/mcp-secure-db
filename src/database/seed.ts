import { TableMetadata } from "../types.js";

export const TABLE_METADATA: Record<string, TableMetadata> = {
  customers: {
    name: "customers",
    description: "Enterprise SaaS customer accounts and plan tiers",
    adminOnly: false,
    rowCount: 5,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Customer unique ID" },
      { name: "name", type: "TEXT", isPII: false, description: "Organization name" },
      { name: "billing_email", type: "TEXT", isPII: true, description: "Confidential billing email address" },
      { name: "stripe_customer_id", type: "TEXT", isPII: true, description: "Stripe payment identifier" },
      { name: "plan", type: "TEXT", isPII: false, description: "Subscription tier (starter, pro, enterprise)" },
      { name: "created_at", type: "TEXT", isPII: false, description: "Registration timestamp" },
    ],
  },
  api_usage: {
    name: "api_usage",
    description: "Daily aggregated API endpoint calls and compute duration",
    adminOnly: false,
    rowCount: 10,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Usage event record ID" },
      { name: "customer_id", type: "INTEGER", isPII: false, description: "Foreign key referencing customers.id" },
      { name: "endpoint", type: "TEXT", isPII: false, description: "Invoked API endpoint" },
      { name: "request_count", type: "INTEGER", isPII: false, description: "Total HTTP requests in window" },
      { name: "compute_ms", type: "INTEGER", isPII: false, description: "Aggregate server compute milliseconds" },
      { name: "date", type: "TEXT", isPII: false, description: "Date of record (YYYY-MM-DD)" },
    ],
  },
  security_incidents: {
    name: "security_incidents",
    description: "CONFIDENTIAL: Security alerts, anomaly triggers, and client IPs",
    adminOnly: true,
    rowCount: 3,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Incident ID" },
      { name: "incident_type", type: "TEXT", isPII: false, description: "Anomaly classification" },
      { name: "severity", type: "TEXT", isPII: false, description: "Severity rank (low, medium, high, critical)" },
      { name: "client_ip", type: "TEXT", isPII: true, description: "Originating client IP address" },
      { name: "details", type: "TEXT", isPII: false, description: "Incident analysis note" },
      { name: "detected_at", type: "TEXT", isPII: false, description: "Detection timestamp" },
    ],
  },
  api_keys: {
    name: "api_keys",
    description: "CONFIDENTIAL: Client API keys and webhook signing secrets",
    adminOnly: true,
    rowCount: 4,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Key ID" },
      { name: "customer_id", type: "INTEGER", isPII: false, description: "Customer account ID" },
      { name: "key_prefix", type: "TEXT", isPII: false, description: "Key identifier prefix" },
      { name: "webhook_secret", type: "TEXT", isPII: true, description: "HMAC webhook signing secret" },
      { name: "is_active", type: "INTEGER", isPII: false, description: "1 if active, 0 if revoked" },
      { name: "created_at", type: "TEXT", isPII: false, description: "Key creation timestamp" },
    ],
  },
};

export const SEED_SQL = `
CREATE TABLE customers (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  billing_email TEXT NOT NULL,
  stripe_customer_id TEXT NOT NULL,
  plan TEXT NOT NULL,
  created_at TEXT NOT NULL
);

INSERT INTO customers VALUES
  (1, 'Acme Corp', 'billing@acme.example.com', 'cus_9921_acme', 'enterprise', '2026-01-15T08:00:00Z'),
  (2, 'Globex Int', 'finance@globex.example.com', 'cus_3341_globex', 'pro', '2026-02-01T10:30:00Z'),
  (3, 'Soylent Inc', 'accounts@soylent.example.com', 'cus_1120_soylent', 'starter', '2026-03-10T14:15:00Z'),
  (4, 'Initech LLC', 'peter@initech.example.com', 'cus_8874_initech', 'enterprise', '2026-04-05T09:20:00Z'),
  (5, 'Umbrella Labs', 'redqueen@umbrella.example.com', 'cus_6652_umbrella', 'pro', '2026-05-18T16:45:00Z');

CREATE TABLE api_usage (
  id INTEGER PRIMARY KEY,
  customer_id INTEGER NOT NULL,
  endpoint TEXT NOT NULL,
  request_count INTEGER NOT NULL,
  compute_ms INTEGER NOT NULL,
  date TEXT NOT NULL
);

INSERT INTO api_usage VALUES
  (1, 1, '/v1/inference/agent', 145000, 890000, '2026-10-25'),
  (2, 1, '/v1/embeddings/create', 320000, 420000, '2026-10-25'),
  (3, 2, '/v1/inference/agent', 54000, 310000, '2026-10-25'),
  (4, 2, '/v1/database/query', 12000, 95000, '2026-10-25'),
  (5, 3, '/v1/inference/agent', 8500, 52000, '2026-10-25'),
  (6, 4, '/v1/inference/agent', 210000, 1450000, '2026-10-25'),
  (7, 4, '/v1/embeddings/create', 580000, 780000, '2026-10-25'),
  (8, 4, '/v1/database/query', 94000, 620000, '2026-10-25'),
  (9, 5, '/v1/inference/agent', 42000, 280000, '2026-10-25'),
  (10, 5, '/v1/database/query', 31000, 190000, '2026-10-25');

CREATE TABLE security_incidents (
  id INTEGER PRIMARY KEY,
  incident_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  details TEXT NOT NULL,
  detected_at TEXT NOT NULL
);

INSERT INTO security_incidents VALUES
  (1, 'SUSPICIOUS_JOIN', 'high', '198.51.100.44', 'Blocked unconstrained Cartesian product attempt', '2026-10-26T03:12:00Z'),
  (2, 'MUTATION_BLOCKED', 'critical', '203.0.113.89', 'Blocked DROP TABLE injection payload in agent context', '2026-10-26T08:44:00Z'),
  (3, 'PII_EXFIL_ATTEMPT', 'medium', '192.0.2.110', 'Blocked SELECT * on customer billing table for viewer role', '2026-10-26T12:05:00Z');

CREATE TABLE api_keys (
  id INTEGER PRIMARY KEY,
  customer_id INTEGER NOT NULL,
  key_prefix TEXT NOT NULL,
  webhook_secret TEXT NOT NULL,
  is_active INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

INSERT INTO api_keys VALUES
  (1, 1, 'pk_live_acme_9281', 'whsec_987216345abcdef', 1, '2026-01-15T08:00:00Z'),
  (2, 2, 'pk_live_glob_1109', 'whsec_441298712fedcba', 1, '2026-02-01T10:30:00Z'),
  (3, 4, 'pk_live_init_7761', 'whsec_554129881aabbcc', 1, '2026-04-05T09:20:00Z'),
  (4, 5, 'pk_live_umbr_3321', 'whsec_665412998ddeeff', 0, '2026-05-18T16:45:00Z');
`;
