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
  // drizzle-kit генерирует файлы с --> statement-breakpoint разделителями;
  // разбиваем на отдельные statement'ы, чтобы pg.Pool.query() корректно обработал каждый
  const statements = sql
    .split('--> statement-breakpoint')
    .map(s => s.trim())
    .filter(Boolean);
  for (const stmt of statements) {
    await pool.query(stmt);
  }
}

console.log('Done.');
await pool.end();
