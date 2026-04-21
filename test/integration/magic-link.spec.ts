import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { createTestDb, destroyTestDb, TestDB } from '../setup.js';
import { createMagicLinkRouter } from '../../src/magic-link/routes.js';
import { hashNonce } from '../../src/magic-link/nonce.js';
import { loadKeys, JwtKeys } from '../../src/jwt/keys.js';
import { verifyJwt } from '../../src/jwt/verify.js';
import { createOutboxSender, EmailOutbox } from '../../src/magic-link/email.js';
import { drizzle } from 'drizzle-orm/node-postgres';
import * as schema from '../../src/db/schema.js';

describe('magic-link routes', () => {
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
    // Порядок важен: memberships ссылается на users через FK → сначала дочерние.
    await handle.pool.query('DELETE FROM memberships; DELETE FROM users; DELETE FROM magic_links');
  });

  describe('POST /magic-link', () => {
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

  describe('GET /magic-link/callback', () => {
    it('verifies nonce, creates user, issues JWT with memberships', async () => {
      const [userRow] = await handle.pool
        .query(`INSERT INTO users(email) VALUES('bob@acme.com') RETURNING id`)
        .then((r) => r.rows);
      await handle.pool.query(
        `INSERT INTO memberships(user_id, domain_slug, role) VALUES($1, 'my-app', 'csm')`,
        [userRow.id]
      );

      await request(app).post('/magic-link').send({ email: 'bob@acme.com' });
      const link = outbox[0].link;
      const token = new URL(link).searchParams.get('token')!;

      const res = await request(app).get(`/magic-link/callback?token=${encodeURIComponent(token)}`);
      expect(res.status).toBe(200);
      expect(res.body.jwt).toMatch(/^eyJ/);
      expect(res.body.user.email).toBe('bob@acme.com');

      const claims = await verifyJwt(keys, res.body.jwt);
      expect(claims.sub).toBe(userRow.id);
      expect(claims.memberships).toEqual([{ domainSlug: 'my-app', role: 'csm' }]);
    });

    it('creates user on first login (no existing user)', async () => {
      await request(app).post('/magic-link').send({ email: 'new@acme.com' });
      const token = new URL(outbox[0].link).searchParams.get('token')!;
      const res = await request(app).get(`/magic-link/callback?token=${encodeURIComponent(token)}`);
      expect(res.status).toBe(200);
      const claims = await verifyJwt(keys, res.body.jwt);
      expect(claims.memberships).toEqual([]);
    });

    it('rejects unknown nonce', async () => {
      const res = await request(app).get('/magic-link/callback?token=fake');
      expect(res.status).toBe(400);
    });

    it('rejects already-used nonce', async () => {
      await request(app).post('/magic-link').send({ email: 'once@acme.com' });
      const token = new URL(outbox[0].link).searchParams.get('token')!;
      await request(app).get(`/magic-link/callback?token=${encodeURIComponent(token)}`);
      const res2 = await request(app).get(`/magic-link/callback?token=${encodeURIComponent(token)}`);
      expect(res2.status).toBe(400);
    });

    it('rejects expired nonce', async () => {
      await handle.pool.query(
        `INSERT INTO magic_links(nonce_hash, email, expires_at) VALUES($1, 'exp@acme.com', NOW() - INTERVAL '1 hour')`,
        [await hashNonce('expired-nonce')]
      );
      const res = await request(app).get('/magic-link/callback?token=expired-nonce');
      expect(res.status).toBe(400);
    });
  });
});
