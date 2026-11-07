import { TableMetadata } from "../types.js";

export const DEFAULT_TABLE_METADATA: Record<string, TableMetadata> = {
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

export const COMPANY_TABLE_METADATA: Record<string, TableMetadata> = {
  departments: {
    name: "departments",
    description: "Corporate organizational departments and budget allocations",
    adminOnly: false,
    rowCount: 5,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Department unique ID" },
      { name: "name", type: "TEXT", isPII: false, description: "Department name" },
      { name: "budget_usd", type: "REAL", isPII: false, description: "Annual operational budget in USD" },
      { name: "location", type: "TEXT", isPII: false, description: "Campus facility and floor" },
    ],
  },
  products: {
    name: "products",
    description: "Commercial software platforms, hardware appliances, and service tiers",
    adminOnly: false,
    rowCount: 8,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Product unique ID" },
      { name: "sku", type: "TEXT", isPII: false, description: "Stock keeping unit code" },
      { name: "title", type: "TEXT", isPII: false, description: "Product title" },
      { name: "price_usd", type: "REAL", isPII: false, description: "Unit price in USD" },
      { name: "stock_qty", type: "INTEGER", isPII: false, description: "Available inventory quantity" },
    ],
  },
  orders: {
    name: "orders",
    description: "Customer purchasing transactions and fulfillment statuses",
    adminOnly: false,
    rowCount: 20,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Order unique ID" },
      { name: "customer_name", type: "TEXT", isPII: false, description: "Purchasing enterprise customer name" },
      { name: "product_id", type: "INTEGER", isPII: false, description: "Foreign key referencing products.id" },
      { name: "amount_usd", type: "REAL", isPII: false, description: "Transaction amount in USD" },
      { name: "status", type: "TEXT", isPII: false, description: "Fulfillment status (completed, pending, processing, shipped)" },
      { name: "order_date", type: "TEXT", isPII: false, description: "ISO 8601 transaction timestamp" },
    ],
  },
  employees: {
    name: "employees",
    description: "Internal staff records with sensitive compensation and identifiers",
    adminOnly: false,
    rowCount: 12,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Employee badge ID" },
      { name: "name", type: "TEXT", isPII: false, description: "Full employee name" },
      { name: "dept_id", type: "INTEGER", isPII: false, description: "Foreign key referencing departments.id" },
      { name: "role", type: "TEXT", isPII: false, description: "Job title and seniority" },
      { name: "salary_usd", type: "REAL", isPII: true, description: "Base annual compensation" },
      { name: "ssn", type: "TEXT", isPII: true, description: "Social Security Number" },
      { name: "personal_email", type: "TEXT", isPII: true, description: "Personal email address" },
    ],
  },
  api_secrets: {
    name: "api_secrets",
    description: "Production infrastructure API credentials and signing keys",
    adminOnly: true,
    rowCount: 4,
    columns: [
      { name: "id", type: "INTEGER", isPII: false, description: "Secret identifier ID" },
      { name: "service_name", type: "TEXT", isPII: false, description: "Associated cloud or vendor service" },
      { name: "secret_token", type: "TEXT", isPII: true, description: "High-entropy secret token" },
      { name: "environment", type: "TEXT", isPII: false, description: "Deployment tier (production, staging)" },
    ],
  },
};

export function getActiveTableMetadata(): Record<string, TableMetadata> {
  if (process.env.MCP_SECURE_DB_SQLITE_PATH) {
    return COMPANY_TABLE_METADATA;
  }
  return DEFAULT_TABLE_METADATA;
}

export const TABLE_METADATA: Record<string, TableMetadata> = new Proxy(
  {} as Record<string, TableMetadata>,
  {
    get(_target, prop: string | symbol) {
      if (typeof prop !== "string") return undefined;
      const lower = prop.toLowerCase();
      const active = getActiveTableMetadata();
      if (lower in active) {
        return active[lower];
      }
      if (lower in COMPANY_TABLE_METADATA) {
        return COMPANY_TABLE_METADATA[lower];
      }
      return DEFAULT_TABLE_METADATA[lower];
    },
    has(_target, prop: string | symbol) {
      if (typeof prop !== "string") return false;
      const lower = prop.toLowerCase();
      const active = getActiveTableMetadata();
      return (
        lower in active ||
        lower in COMPANY_TABLE_METADATA ||
        lower in DEFAULT_TABLE_METADATA
      );
    },
    ownKeys() {
      const active = getActiveTableMetadata();
      return Reflect.ownKeys(active);
    },
    getOwnPropertyDescriptor(_target, prop: string | symbol) {
      const active = getActiveTableMetadata();
      const desc = Object.getOwnPropertyDescriptor(active, prop);
      if (desc) {
        desc.configurable = true;
      }
      return desc;
    },
  }
);

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

export const COMPANY_SEED_SQL = `
CREATE TABLE departments (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  budget_usd REAL NOT NULL,
  location TEXT NOT NULL
);

INSERT INTO departments VALUES
  (1, 'Engineering', 2500000.0, 'Building A, Floor 3'),
  (2, 'Sales & Marketing', 1800000.0, 'Building B, Floor 1'),
  (3, 'Product & Design', 1200000.0, 'Building A, Floor 2'),
  (4, 'Human Resources', 650000.0, 'Building C, Floor 1'),
  (5, 'Finance & Legal', 950000.0, 'Building C, Floor 2');

CREATE TABLE products (
  id INTEGER PRIMARY KEY,
  sku TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  price_usd REAL NOT NULL,
  stock_qty INTEGER NOT NULL
);

INSERT INTO products VALUES
  (1, 'PRD-ENT-001', 'Enterprise Cloud Platform Subscription', 4999.00, 9999),
  (2, 'PRD-SEC-002', 'Autonomous Security Gateway Appliance', 12499.00, 45),
  (3, 'PRD-DAT-003', 'Real-Time Streaming Analytics Node', 2999.00, 120),
  (4, 'PRD-AI-004', 'Gemini Agent Orchestration License', 1999.00, 250),
  (5, 'PRD-LOG-005', 'High-Throughput Audit Logger Pro', 899.00, 500),
  (6, 'PRD-API-006', 'Developer API Rate Shield Module', 499.00, 1000),
  (7, 'PRD-BAK-007', 'Immutable Vault Backup Appliance', 7499.00, 30),
  (8, 'PRD-CON-008', 'Enterprise 24/7 Support Contract', 3500.00, 100);

CREATE TABLE orders (
  id INTEGER PRIMARY KEY,
  customer_name TEXT NOT NULL,
  product_id INTEGER NOT NULL,
  amount_usd REAL NOT NULL,
  status TEXT NOT NULL,
  order_date TEXT NOT NULL
);

INSERT INTO orders VALUES
  (1, 'Acme Global Corp', 1, 4999.00, 'completed', '2026-10-01T10:15:00Z'),
  (2, 'Nexus Tech Labs', 2, 12499.00, 'completed', '2026-10-02T14:30:00Z'),
  (3, 'OmniCorp Systems', 4, 1999.00, 'completed', '2026-10-03T09:00:00Z'),
  (4, 'CyberDyne Industries', 3, 2999.00, 'completed', '2026-10-04T16:20:00Z'),
  (5, 'Stark Dynamics', 1, 9998.00, 'completed', '2026-10-05T11:45:00Z'),
  (6, 'Wayne Enterprises', 7, 7499.00, 'completed', '2026-10-06T13:10:00Z'),
  (7, 'Initech Corporation', 6, 499.00, 'completed', '2026-10-07T15:00:00Z'),
  (8, 'Massive Dynamic', 2, 24998.00, 'completed', '2026-10-08T08:30:00Z'),
  (9, 'Soylent Health', 5, 899.00, 'completed', '2026-10-09T12:00:00Z'),
  (10, 'Hooli Networks', 4, 3998.00, 'completed', '2026-10-10T17:40:00Z'),
  (11, 'Pied Piper Tech', 3, 5998.00, 'completed', '2026-10-11T10:05:00Z'),
  (12, 'Acme Global Corp', 8, 3500.00, 'completed', '2026-10-12T11:20:00Z'),
  (13, 'Tyrell Automation', 2, 12499.00, 'pending', '2026-10-13T14:50:00Z'),
  (14, 'Globex Regional', 1, 4999.00, 'completed', '2026-10-14T09:15:00Z'),
  (15, 'CyberDyne Industries', 5, 1798.00, 'completed', '2026-10-15T16:00:00Z'),
  (16, 'Umbrella Biologicals', 7, 14998.00, 'shipped', '2026-10-16T13:25:00Z'),
  (17, 'Nexus Tech Labs', 4, 1999.00, 'completed', '2026-10-17T15:30:00Z'),
  (18, 'Wayne Enterprises', 8, 7000.00, 'completed', '2026-10-18T18:00:00Z'),
  (19, 'Soylent Health', 6, 998.00, 'processing', '2026-10-19T08:45:00Z'),
  (20, 'Stark Dynamics', 2, 12499.00, 'pending', '2026-10-20T10:30:00Z');

CREATE TABLE employees (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  dept_id INTEGER NOT NULL,
  role TEXT NOT NULL,
  salary_usd REAL NOT NULL,
  ssn TEXT NOT NULL,
  personal_email TEXT NOT NULL
);

INSERT INTO employees VALUES
  (1, 'Sarah Chen', 1, 'Principal Infrastructure Architect', 185000.00, '982-41-1029', 'sarah.chen.personal@example.net'),
  (2, 'Marcus Vance', 1, 'Senior Security Research Engineer', 162000.00, '441-20-8874', 'marcus.vance88@example.org'),
  (3, 'Elena Rostova', 1, 'Staff Database Engine Specialist', 174000.00, '319-88-4421', 'elena.rostova@personalmail.org'),
  (4, 'David Kim', 2, 'VP of Global Enterprise Sales', 210000.00, '120-45-9982', 'dkim.investments@example.com'),
  (5, 'Jessica Morales', 2, 'Senior Account Executive', 135000.00, '552-19-3321', 'jess.morales@homemail.net'),
  (6, 'Tariq Al-Mansoor', 3, 'Head of Product Management', 190000.00, '883-92-6612', 'tariq.almansoor@example.com'),
  (7, 'Chloe Bennett', 3, 'Lead UI/UX Security Designer', 140000.00, '229-38-7714', 'chloe.bennett.art@example.org'),
  (8, 'Arthur Pendelton', 4, 'Director of Human Resources', 155000.00, '671-50-2219', 'arthur.pendelton@familypost.com'),
  (9, 'Sophia Wu', 4, 'HR Operations & People Lead', 110000.00, '904-11-5582', 'sophia.wu92@example.net'),
  (10, 'Robert Taylor', 5, 'Chief Financial Officer', 260000.00, '731-84-9031', 'robert.taylor.private@example.com'),
  (11, 'Amira Patel', 5, 'Senior Corporate Legal Counsel', 178000.00, '418-62-3390', 'amira.patel.law@example.org'),
  (12, 'James Wilson', 1, 'Site Reliability Engineer II', 128000.00, '519-73-6641', 'jwilson.cloud@example.com');

CREATE TABLE api_secrets (
  id INTEGER PRIMARY KEY,
  service_name TEXT NOT NULL,
  secret_token TEXT NOT NULL,
  environment TEXT NOT NULL
);

INSERT INTO api_secrets VALUES
  (1, 'Stripe Payment Gateway', 'stripe_mock_secret_998124018274', 'production'),
  (2, 'Gemini 3.8 Flash AI API', 'gemini_mock_key_871239102381', 'production'),
  (3, 'AWS Cold Storage Glacier S3', 'aws_mock_secret_889920192837', 'production'),
  (4, 'Internal Redis Cache Cluster', 'redis_mock_token_981237198273', 'staging');
`;
