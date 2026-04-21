import { spawn } from 'node:child_process';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createHmac, createHash } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

async function main() {
  console.log('[smoke] starting Postgres...');
  const pg = await new PostgreSqlContainer('postgres:16-alpine').start();
  const dbUrl = pg.getConnectionUri();

  console.log('[smoke] applying migrations...');
  const pgModule = await import('pg');
  const Client = pgModule.default.Client;
  const c1 = new Client({ connectionString: dbUrl });
  await c1.connect();
  const drizzleDir = join(process.cwd(), 'drizzle');
  const sqlFiles = readdirSync(drizzleDir).filter(f => f.endsWith('.sql')).sort();
  for (const f of sqlFiles) {
    await c1.query(readFileSync(join(drizzleDir, f), 'utf8'));
  }
  await c1.end();

  console.log('[smoke] generating keys...');
  const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
  const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
  const pub = await exportSPKI(publicKey);
  const priv = await exportPKCS8(privateKey);
  const hmacSecret = randomBytes(32).toString('hex');

  console.log('[smoke] starting server...');
  const server = spawn(
    'node',
    ['--import=tsx', 'src/index.ts'],
    {
      env: {
        ...process.env,
        DATABASE_URL: dbUrl,
        JWT_PRIVATE_KEY_PEM: priv,
        JWT_PUBLIC_KEY_PEM: pub,
        TENANT_HMAC_SECRET: hmacSecret,
        RESEND_API_KEY: 'x',
        APP_BASE_URL: 'http://localhost:4321',
        PORT: '4321',
        EMAIL_DEV_MODE: 'true',
      },
      stdio: 'inherit',
    }
  );

  await sleep(2500);

  try {
    const h = await fetch('http://localhost:4321/health').then(r => r.json());
    console.log('[smoke] /health →', h);
    if (h.status !== 'ok') throw new Error('health failed');

    const jwks = await fetch('http://localhost:4321/.well-known/jwks.json').then(r => r.json());
    console.log('[smoke] jwks →', jwks.keys[0].kid);

    const ml = await fetch('http://localhost:4321/magic-link', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'smoke@idf.dev' }),
    }).then(r => r.json());
    console.log('[smoke] /magic-link →', ml);

    const c2 = new Client({ connectionString: dbUrl });
    await c2.connect();
    const { rows } = await c2.query('SELECT * FROM magic_links ORDER BY created_at DESC LIMIT 1');
    await c2.end();
    console.log('[smoke] magic_link row stored, hash =', rows[0].nonce_hash.slice(0, 8));

    // В prod nonce приходит юзеру в email; smoke читает БД → не знает raw nonce.
    // Инжектим известный nonce напрямую чтобы проверить callback machinery.
    const knownNonce = 'smoke-test-nonce-' + randomBytes(16).toString('hex');
    const hash = createHash('sha256').update(knownNonce).digest('hex');
    const c3 = new Client({ connectionString: dbUrl });
    await c3.connect();
    await c3.query(
      `INSERT INTO magic_links(nonce_hash, email, expires_at) VALUES($1, 'injected@idf.dev', NOW() + INTERVAL '1 hour')`,
      [hash]
    );
    await c3.end();

    const cb = await fetch(`http://localhost:4321/magic-link/callback?token=${knownNonce}`).then(r => r.json());
    console.log('[smoke] callback →', { user: cb.user, memberships: cb.memberships, jwt_len: cb.jwt?.length });
    if (!cb.jwt) throw new Error('no JWT returned');

    const body = JSON.stringify({
      email: 'invited@idf.dev',
      domainSlug: 'smoke-app',
      role: 'viewer',
      inviterEmail: 'smoke@idf.dev',
    });
    const ts = Math.floor(Date.now() / 1000);
    const sig = createHmac('sha256', hmacSecret)
      .update(`POST\n/invites\n${body}\n${ts}`)
      .digest('hex');
    const inv = await fetch('http://localhost:4321/invites', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-idf-ts': String(ts),
        'x-idf-sig': sig,
      },
      body,
    }).then(r => r.json());
    console.log('[smoke] /invites →', inv);
    if (inv.status !== 'sent') throw new Error('invite failed');

    console.log('\n✓ SMOKE OK');
  } catch (e) {
    console.error('\n✗ SMOKE FAILED:', e);
    process.exitCode = 1;
  } finally {
    server.kill();
    await pg.stop();
  }
}

main();
