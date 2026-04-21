import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { createTestDb, destroyTestDb, TestDB } from '../setup.js';
import { createMagicLinkRouter } from '../../src/magic-link/routes.js';
import { loadKeys, JwtKeys } from '../../src/jwt/keys.js';
import { createOutboxSender, EmailOutbox } from '../../src/magic-link/email.js';
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from '../../src/db/schema.js';

describe('POST /magic-link', () => {
  let handle: TestDB;
  let app: express.Express;
  let keys: JwtKeys;
  let outbox: EmailOutbox;

  beforeAll(async () => {
    handle = await createTestDb();
    const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
    keys = await loadKeys(await exportSPKI(publicKey), await exportPKCS8(privateKey));
  });

  afterAll(async () => {
    await destroyTestDb(handle);
  });

  beforeEach(async () => {
    outbox = [];
    app = express();
    app.use(express.json());
    app.use(
      createMagicLinkRouter({
        db: drizzle(handle.pool, { schema }),
        keys,
        email: createOutboxSender(outbox),
        baseUrl: 'http://localhost:4000',
        ttlMinutes: 15,
        jwtTtlDays: 30,
      })
    );
    await handle.pool.query('DELETE FROM magic_links; DELETE FROM users; DELETE FROM memberships');
  });

  it('creates magic_link row + sends email', async () => {
    const res = await request(app)
      .post('/magic-link')
      .send({ email: 'alice@acme.com', domainSlug: 'my-app' });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'sent' });
    expect(outbox).toHaveLength(1);
    expect(outbox[0].kind).toBe('magic');
    expect(outbox[0].to).toBe('alice@acme.com');
    expect(outbox[0].link).toMatch(/\/magic-link\/callback\?token=[A-Za-z0-9_-]+/);

    const rows = await handle.pool.query('SELECT * FROM magic_links');
    expect(rows.rows).toHaveLength(1);
    expect(rows.rows[0].email).toBe('alice@acme.com');
  });

  it('rejects invalid email', async () => {
    const res = await request(app)
      .post('/magic-link')
      .send({ email: 'not-an-email' });
    expect(res.status).toBe(400);
  });
});
