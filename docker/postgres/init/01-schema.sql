-- PostgreSQL Schema & Seed Data for mcp-secure-db
-- Identical table structure and row data to SQLite seed for differential parity

CREATE TABLE IF NOT EXISTS customers (
  id INT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  billing_email VARCHAR(255) NOT NULL,
  stripe_customer_id VARCHAR(255) NOT NULL,
  plan VARCHAR(50) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

INSERT INTO customers VALUES
  (1, 'Acme Corp', 'billing@acme.example.com', 'cus_9921_acme', 'enterprise', '2026-01-15 08:00:00+00'),
  (2, 'Globex Int', 'finance@globex.example.com', 'cus_3341_globex', 'pro', '2026-02-01 10:30:00+00'),
  (3, 'Soylent Inc', 'accounts@soylent.example.com', 'cus_1120_soylent', 'starter', '2026-03-10 14:15:00+00'),
  (4, 'Initech LLC', 'peter@initech.example.com', 'cus_8874_initech', 'enterprise', '2026-04-05 09:20:00+00'),
  (5, 'Umbrella Labs', 'redqueen@umbrella.example.com', 'cus_6652_umbrella', 'pro', '2026-05-18 16:45:00+00')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS api_usage (
  id INT PRIMARY KEY,
  customer_id INT NOT NULL REFERENCES customers(id),
  endpoint VARCHAR(255) NOT NULL,
  request_count INT NOT NULL,
  compute_ms INT NOT NULL,
  date DATE NOT NULL
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
  (10, 5, '/v1/database/query', 31000, 190000, '2026-10-25')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS security_incidents (
  id INT PRIMARY KEY,
  incident_type VARCHAR(100) NOT NULL,
  severity VARCHAR(50) NOT NULL,
  client_ip VARCHAR(50) NOT NULL,
  details TEXT NOT NULL,
  detected_at TIMESTAMPTZ NOT NULL
);

INSERT INTO security_incidents VALUES
  (1, 'SUSPICIOUS_JOIN', 'high', '198.51.100.44', 'Blocked unconstrained Cartesian product attempt', '2026-10-26 03:12:00+00'),
  (2, 'MUTATION_BLOCKED', 'critical', '203.0.113.89', 'Blocked DROP TABLE injection payload in agent context', '2026-10-26 08:44:00+00'),
  (3, 'PII_EXFIL_ATTEMPT', 'medium', '192.0.2.110', 'Blocked SELECT * on customer billing table for viewer role', '2026-10-26 12:05:00+00')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS api_keys (
  id INT PRIMARY KEY,
  customer_id INT NOT NULL REFERENCES customers(id),
  key_prefix VARCHAR(100) NOT NULL,
  webhook_secret VARCHAR(255) NOT NULL,
  is_active INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL
);

INSERT INTO api_keys VALUES
  (1, 1, 'pk_live_acme_9281', 'whsec_987216345abcdef', 1, '2026-01-15 08:00:00+00'),
  (2, 2, 'pk_live_glob_1109', 'whsec_441298712fedcba', 1, '2026-02-01 10:30:00+00'),
  (3, 4, 'pk_live_init_7761', 'whsec_554129881aabbcc', 1, '2026-04-05 09:20:00+00'),
  (4, 5, 'pk_live_umbr_3321', 'whsec_665412998ddeeff', 0, '2026-05-18 16:45:00+00')
ON CONFLICT (id) DO NOTHING;
