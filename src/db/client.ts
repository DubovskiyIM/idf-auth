// src/db/client.ts
import pg from 'pg';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from './schema.js';

export type DB = NodePgDatabase<typeof schema>;

export function createDb(url: string): { db: DB; pool: pg.Pool } {
  const pool = new pg.Pool({ connectionString: url, max: 10 });
  const db = drizzle(pool, { schema });
  return { db, pool };
}

export { schema };
