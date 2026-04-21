import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export type TestDB = {
  container: StartedPostgreSqlContainer;
  pool: pg.Pool;
  db: NodePgDatabase;
  url: string;
};

export async function createTestDb(): Promise<TestDB> {
  const container = await new PostgreSqlContainer('postgres:16-alpine').start();
  const url = container.getConnectionUri();
  const pool = new pg.Pool({ connectionString: url });

  const migration = readFileSync(
    join(process.cwd(), 'drizzle', '0000_init.sql'),
    'utf8'
  );
  await pool.query(migration);

  const db = drizzle(pool);
  return { container, pool, db, url };
}

export async function destroyTestDb(handle: TestDB) {
  await handle.pool.end();
  await handle.container.stop();
}
