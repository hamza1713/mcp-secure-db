-- PostgreSQL Row-Level Security (RLS) Multi-Tenant Demonstration Table
-- Uses transaction-local `app.tenant_id` set via parameterized `set_config('app.tenant_id', $1, true)`
-- by PostgresQueryEngine before switching to `SET LOCAL ROLE mcp_analyst`.

CREATE TABLE IF NOT EXISTS tenant_reports (
  id INT PRIMARY KEY,
  tenant_id VARCHAR(128) NOT NULL,
  title VARCHAR(255) NOT NULL,
  metric_value NUMERIC(12, 2) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO tenant_reports (id, tenant_id, title, metric_value, created_at) VALUES
  (1, 'tenant_acme', 'Acme Q1 API Compute Summary', 142500.00, '2026-01-31 00:00:00+00'),
  (2, 'tenant_acme', 'Acme Q2 Latency SLA Report', 99.94, '2026-04-30 00:00:00+00'),
  (3, 'tenant_globex', 'Globex Q1 API Compute Summary', 88420.50, '2026-01-31 00:00:00+00'),
  (4, 'tenant_globex', 'Globex Enterprise Usage Rollup', 310200.00, '2026-05-15 00:00:00+00')
ON CONFLICT (id) DO NOTHING;

GRANT SELECT ON tenant_reports TO mcp_analyst, mcp_admin;

ALTER TABLE tenant_reports ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_analyst ON tenant_reports;
CREATE POLICY tenant_isolation_analyst
  ON tenant_reports
  FOR SELECT
  TO mcp_analyst
  USING (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS tenant_isolation_admin ON tenant_reports;
CREATE POLICY tenant_isolation_admin
  ON tenant_reports
  FOR SELECT
  TO mcp_admin
  USING (true);
