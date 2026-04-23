import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import express from 'express';
import { drizzle } from 'drizzle-orm/node-postgres';
import { createTestDb, destroyTestDb, TestDB } from '../setup.js';
import { createAdminRouter } from '../../src/admin/routes.js';
import { signTenantRequest } from '../../src/invites/hmac.js';
import { loadKeys, JwtKeys } from '../../src/jwt/keys.js';
import { verifyJwt } from '../../src/jwt/verify.js';
import * as schema from '../../src/db/schema.js';

const SECRET = 'b'.repeat(64);

describe('admin memberships', () => {
  let handle: TestDB;
  let app: express.Express;
  let keys: JwtKeys;

  beforeAll(async () => {
    handle = await createTestDb();
    const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
    keys = await loadKeys(await exportSPKI(publicKey), await exportPKCS8(privateKey));
  });

  afterAll(() => destroyTestDb(handle));

  beforeEach(async () => {
    app = express();
    app.use(express.json({ verify: (req: any, _res, buf) => { req.rawBody = buf.toString('utf8'); } }));
    app.use(
      createAdminRouter({
        db: drizzle(handle.pool, { schema }),
        keys,
        tenantSecret: SECRET,
        jwtTtlDays: 30,
      }),
    );
    await handle.pool.query('DELETE FROM memberships; DELETE FROM users');
  });

  function signed(body: object, path = '/admin/memberships') {
    const raw = JSON.stringify(body);
    const ts = Math.floor(Date.now() / 1000);
    const sig = signTenantRequest(SECRET, 'POST', path, raw, ts);
    return { raw, ts, sig };
  }

  it('без HMAC-подписи → 401', async () => {
    const r = await request(app)
      .post('/admin/memberships')
      .send({ email: 'a@b.c', domainSlug: 'acme', role: 'owner' });
    expect(r.status).toBe(401);
  });

  it('создаёт user + membership + возвращает JWT со slug\'ом', async () => {
    const body = { email: 'owner@acme.com', domainSlug: 'acme', role: 'owner' };
    const { raw, ts, sig } = signed(body);
    const r = await request(app)
      .post('/admin/memberships')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', sig)
      .set('content-type', 'application/json')
      .send(raw);

    expect(r.status).toBe(200);
    expect(r.body.memberships).toEqual([{ domainSlug: 'acme', role: 'owner' }]);

    const claims = await verifyJwt(keys, r.body.jwt);
    expect(claims.memberships).toEqual([{ domainSlug: 'acme', role: 'owner' }]);
  });

  it('идемпотентно — повторный вызов не создаёт дубль', async () => {
    const body = { email: 'owner@acme.com', domainSlug: 'acme', role: 'owner' };

    const first = signed(body);
    await request(app)
      .post('/admin/memberships')
      .set('x-idf-ts', String(first.ts))
      .set('x-idf-sig', first.sig)
      .set('content-type', 'application/json')
      .send(first.raw);

    const second = signed(body);
    const r = await request(app)
      .post('/admin/memberships')
      .set('x-idf-ts', String(second.ts))
      .set('x-idf-sig', second.sig)
      .set('content-type', 'application/json')
      .send(second.raw);

    expect(r.status).toBe(200);
    expect(r.body.memberships).toHaveLength(1);

    const rows = await handle.pool.query('SELECT * FROM memberships');
    expect(rows.rows).toHaveLength(1);
  });

  it('реактивирует revoked membership', async () => {
    const body = { email: 'owner@acme.com', domainSlug: 'acme', role: 'owner' };
    const first = signed(body);
    await request(app)
      .post('/admin/memberships')
      .set('x-idf-ts', String(first.ts))
      .set('x-idf-sig', first.sig)
      .set('content-type', 'application/json')
      .send(first.raw);

    await handle.pool.query(
      "UPDATE memberships SET revoked = true, revoked_at = now() WHERE domain_slug = 'acme'",
    );

    const second = signed(body);
    const r = await request(app)
      .post('/admin/memberships')
      .set('x-idf-ts', String(second.ts))
      .set('x-idf-sig', second.sig)
      .set('content-type', 'application/json')
      .send(second.raw);

    expect(r.status).toBe(200);
    expect(r.body.memberships).toEqual([{ domainSlug: 'acme', role: 'owner' }]);
  });

  it('несколько tenant\'ов для одного user — все в JWT', async () => {
    const mk = (slug: string) => {
      const body = { email: 'owner@acme.com', domainSlug: slug, role: 'owner' };
      const { raw, ts, sig } = signed(body);
      return { body, raw, ts, sig };
    };

    for (const slug of ['acme', 'globex', 'initech']) {
      const { raw, ts, sig } = mk(slug);
      await request(app)
        .post('/admin/memberships')
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig)
        .set('content-type', 'application/json')
        .send(raw);
    }

    const { raw, ts, sig } = mk('acme');
    const r = await request(app)
      .post('/admin/memberships')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', sig)
      .set('content-type', 'application/json')
      .send(raw);

    expect(r.body.memberships.map((m: any) => m.domainSlug).sort()).toEqual(['acme', 'globex', 'initech']);
  });

  it('invalid email → 400', async () => {
    const body = { email: 'not-email', domainSlug: 'acme', role: 'owner' };
    const { raw, ts, sig } = signed(body);
    const r = await request(app)
      .post('/admin/memberships')
      .set('x-idf-ts', String(ts))
      .set('x-idf-sig', sig)
      .set('content-type', 'application/json')
      .send(raw);
    expect(r.status).toBe(400);
  });
});
