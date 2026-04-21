// scripts/migrate.mjs
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';

const url = process.env.DATABASE_URL;
if (!url) {
  console.error('DATABASE_URL required');
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: url });
const files = readdirSync('drizzle').filter(f => f.endsWith('.sql')).sort();

for (const f of files) {
  const sql = readFileSync(join('drizzle', f), 'utf8');
  console.log(`Applying ${f}...`);
  await pool.query(sql);
}

console.log('Done.');
await pool.end();
