import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { drizzle } from 'drizzle-orm/node-postgres';
import { createTestDb, destroyTestDb, TestDB } from '../setup.js';
import { createRevocationRouter } from '../../src/revocation/routes.js';
import { signTenantRequest } from '../../src/invites/hmac.js';
import * as schema from '../../src/db/schema.js';

const SECRET = 'a'.repeat(64);

describe('revocation', () => {
  let handle: TestDB;
  let app: express.Express;

  beforeAll(async () => {
    handle = await createTestDb();
  });
  afterAll(() => destroyTestDb(handle));

  beforeEach(async () => {
    app = express();
    app.use(express.json({ verify: (req: any, _res, buf) => { req.rawBody = buf.toString('utf8'); } }));
    app.use(
      createRevocationRouter({
        db: drizzle(handle.pool, { schema }),
        tenantSecret: SECRET,
      })
    );
    await handle.pool.query('DELETE FROM memberships; DELETE FROM users');
  });

  it('POST /revoke marks membership revoked', async () => {
    const [u] = await handle.pool.query(`INSERT INTO users(email) VALUES('x@y.z') RETURNING id`).then(r => r.rows);
    const [m] = await handle.pool.query(
      `INSERT INTO memberships(user_id, domain_slug, role) VALUES($1, 'acme', 'csm') RETURNING id`,
      [u.id]
    ).then(r => r.rows);

    const body = { membershipId: m.id };
    const raw = JSON.stringify(body);
    const ts = Math.floor(Date.now() / 1000);
    const sig = signTenantRequest(SECRET, 'POST', '/revoke', raw, ts);

    const res = await request(app)
      .post('/revoke')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', sig)
      .set('content-type', 'application/json')
      .send(raw);

    expect(res.status).toBe(200);
    const check = await handle.pool.query('SELECT revoked, revoked_at FROM memberships WHERE id=$1', [m.id]);
    expect(check.rows[0].revoked).toBe(true);
    expect(check.rows[0].revoked_at).toBeTruthy();
  });

  it('GET /revocations?since=<iso> returns revoked memberships', async () => {
    const [u] = await handle.pool.query(`INSERT INTO users(email) VALUES('a@b.c') RETURNING id`).then(r => r.rows);
    const [m] = await handle.pool.query(
      `INSERT INTO memberships(user_id, domain_slug, role, revoked, revoked_at) VALUES($1, 'acme', 'csm', true, NOW()) RETURNING id`,
      [u.id]
    ).then(r => r.rows);

    const since = new Date(Date.now() - 60_000).toISOString();
    const res = await request(app).get(`/revocations?since=${encodeURIComponent(since)}&domainSlug=acme`);

    expect(res.status).toBe(200);
    expect(res.body.revocations).toHaveLength(1);
    expect(res.body.revocations[0]).toMatchObject({
      membershipId: m.id,
      userId: u.id,
      domainSlug: 'acme',
    });
  });

  it('GET /revocations filters by domainSlug', async () => {
    const [u] = await handle.pool.query(`INSERT INTO users(email) VALUES('a@b.c') RETURNING id`).then(r => r.rows);
    await handle.pool.query(
      `INSERT INTO memberships(user_id, domain_slug, role, revoked, revoked_at) VALUES
        ($1, 'acme', 'csm', true, NOW()),
        ($1, 'other', 'csm', true, NOW())`,
      [u.id]
    );
    const since = new Date(Date.now() - 60_000).toISOString();
    const res = await request(app).get(`/revocations?since=${encodeURIComponent(since)}&domainSlug=acme`);
    expect(res.body.revocations).toHaveLength(1);
    expect(res.body.revocations[0].domainSlug).toBe('acme');
  });
});
