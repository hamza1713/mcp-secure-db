-- PostgreSQL Role Provisioning and Column-Level Least Privilege for mcp-secure-db
-- Enforces true database-level least privilege matching MCP security context roles

-- Revoke default public schema permissions
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- Create application roles if they do not exist
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_viewer') THEN
    CREATE ROLE mcp_viewer NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_analyst') THEN
    CREATE ROLE mcp_analyst NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_admin') THEN
    CREATE ROLE mcp_admin NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mcp_gateway') THEN
    CREATE ROLE mcp_gateway WITH LOGIN NOINHERIT PASSWORD 'mcp_gateway_test_pw' CONNECTION LIMIT 20;
  END IF;
END $$;

-- Schema usage grants
GRANT USAGE ON SCHEMA public TO mcp_viewer, mcp_analyst, mcp_admin, mcp_gateway;

-- Role 1: mcp_viewer (metadata only, no table SELECT grants)
-- No table SELECT granted to mcp_viewer

-- Role 2: mcp_analyst (column-level least privilege on customers; excludes PII columns)
GRANT SELECT (id, name, plan, created_at) ON customers TO mcp_analyst;
GRANT SELECT ON api_usage TO mcp_analyst;
-- Restricted tables security_incidents and api_keys have NO grant to mcp_analyst

-- Role 3: mcp_admin (full read access across all analytical tables; zero write permissions)
GRANT SELECT ON customers, api_usage, security_incidents, api_keys TO mcp_admin;

-- Role 4: mcp_gateway (connection pool identity; NOINHERIT means 0 direct privileges)
GRANT mcp_viewer, mcp_analyst, mcp_admin TO mcp_gateway;
ALTER ROLE mcp_gateway SET default_transaction_read_only = on;
ALTER ROLE mcp_gateway SET statement_timeout = '3000ms';
ALTER ROLE mcp_gateway SET idle_in_transaction_session_timeout = '5000ms';
