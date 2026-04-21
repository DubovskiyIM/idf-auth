// src/db/client.ts
import pg from 'pg';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from './schema.js';
import { logger } from '../logger.js';

export type DB = NodePgDatabase<typeof schema>;

export function createDb(url: string): { db: DB; pool: pg.Pool } {
  const pool = new pg.Pool({ connectionString: url, max: 10 });
  // Без этого подписчика любая idle-client ошибка pg.Pool уходит в unhandled rejection
  // и процесс падает (critical для prod: DNS flap, transient DB restart).
  pool.on('error', (err) => {
    logger.error({ err }, 'pg pool error');
  });
  const db = drizzle(pool, { schema });
  return { db, pool };
}

export { schema };
