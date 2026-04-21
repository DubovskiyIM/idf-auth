import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import { readFileSync, readdirSync } from 'node:fs';
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

  const drizzleDir = join(process.cwd(), 'drizzle');
  const files = readdirSync(drizzleDir).filter(f => f.endsWith('.sql')).sort();
  for (const f of files) {
    const sql = readFileSync(join(drizzleDir, f), 'utf8');
    await pool.query(sql);
  }

  const db = drizzle(pool);
  return { container, pool, db, url };
}

export async function destroyTestDb(handle: TestDB) {
  await handle.pool.end();
  await handle.container.stop();
}
