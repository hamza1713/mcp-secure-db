import pg from "pg";

export async function setup() {
  const url = process.env.PG_TEST_URL;
  if (!url) {
    throw new Error(
      "MissingPGTestUrl: PG_TEST_URL environment variable is required for integration tests. Start PostgreSQL via 'pnpm run pg:up' or set PG_TEST_URL."
    );
  }

  const client = new pg.Client({
    connectionString: url,
    connectionTimeoutMillis: 3000,
  });

  try {
    await client.connect();
    await client.query("SELECT 1");
  } catch (err: any) {
    throw new Error(
      `PostgreSQLIntegrationUnavailable: Unable to connect to PostgreSQL at ${url} (${err.message}). Integration tests fail closed and will not silently skip.`
    );
  } finally {
    await client.end().catch(() => {});
  }
}
