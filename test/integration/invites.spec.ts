import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { drizzle } from 'drizzle-orm/node-postgres';
import { createTestDb, destroyTestDb, TestDB } from '../setup.js';
import { createInvitesRouter } from '../../src/invites/routes.js';
import { signTenantRequest } from '../../src/invites/hmac.js';
import { loadKeys, JwtKeys } from '../../src/jwt/keys.js';
import { createOutboxSender, EmailOutbox } from '../../src/magic-link/email.js';
import { verifyJwt } from '../../src/jwt/verify.js';
import * as schema from '../../src/db/schema.js';

const SECRET = 'a'.repeat(64);

describe('invites', () => {
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

  afterAll(() => destroyTestDb(handle));

  beforeEach(async () => {
    outbox = [];
    app = express();
    app.use(express.json({ verify: (req: any, _res, buf) => { req.rawBody = buf.toString('utf8'); } }));
    app.use(
      createInvitesRouter({
        db: drizzle(handle.pool, { schema }),
        keys,
        email: createOutboxSender(outbox),
        tenantSecret: SECRET,
        baseUrl: 'http://localhost:4000',
        ttlHours: 24,
        jwtTtlDays: 30,
      })
    );
    await handle.pool.query(
      'DELETE FROM invites; DELETE FROM memberships; DELETE FROM users'
    );
  });

  function signed(body: object) {
    const raw = JSON.stringify(body);
    const ts = Math.floor(Date.now() / 1000);
    const sig = signTenantRequest(SECRET, 'POST', '/invites', raw, ts);
    return { raw, ts, sig };
  }

  it('POST /invites creates row + sends email', async () => {
    const body = { email: 'alice@acme.com', domainSlug: 'my-app', role: 'csm', inviterEmail: 'pm@acme.com' };
    const { raw, ts, sig } = signed(body);

    const res = await request(app)
      .post('/invites')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', sig)
      .set('content-type', 'application/json')
      .send(raw);

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'sent' });
    expect(outbox).toHaveLength(1);
    expect(outbox[0].kind).toBe('invite');
    expect(outbox[0].to).toBe('alice@acme.com');
  });

  it('POST /invites rejects bad signature', async () => {
    const body = { email: 'x@y.z', domainSlug: 'a', role: 'b', inviterEmail: 'i@y.z' };
    const raw = JSON.stringify(body);
    const ts = Math.floor(Date.now() / 1000);

    const res = await request(app)
      .post('/invites')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', 'deadbeef')
      .set('content-type', 'application/json')
      .send(raw);

    expect(res.status).toBe(401);
  });

  it('GET /invites/accept creates membership + issues JWT', async () => {
    const body = { email: 'newbie@acme.com', domainSlug: 'my-app', role: 'viewer', inviterEmail: 'pm@acme.com' };
    const { raw, ts, sig } = signed(body);
    await request(app)
      .post('/invites')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', sig)
      .set('content-type', 'application/json')
      .send(raw);

    const token = new URL(outbox[0].link).searchParams.get('token')!;

    const res = await request(app).get(`/invites/accept?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(200);
    expect(res.body.jwt).toMatch(/^eyJ/);

    const claims = await verifyJwt(keys, res.body.jwt);
    expect(claims.memberships).toEqual([{ domainSlug: 'my-app', role: 'viewer' }]);

    const rows = await handle.pool.query('SELECT * FROM memberships');
    expect(rows.rowCount).toBe(1);
  });

  it('GET /invites/accept rejects used token', async () => {
    const body = { email: 'twice@acme.com', domainSlug: 'x', role: 'y', inviterEmail: 'p@a.co' };
    const { raw, ts, sig } = signed(body);
    await request(app)
      .post('/invites')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', sig)
      .set('content-type', 'application/json')
      .send(raw);

    const token = new URL(outbox[0].link).searchParams.get('token')!;
    await request(app).get(`/invites/accept?token=${encodeURIComponent(token)}`);
    const res = await request(app).get(`/invites/accept?token=${encodeURIComponent(token)}`);
    expect(res.status).toBe(400);
  });
});
