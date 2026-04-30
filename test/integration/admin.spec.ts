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

  describe('GET /admin/memberships', () => {
    function signedGet(domainSlug: string) {
      const path = `/admin/memberships?domainSlug=${domainSlug}`;
      const ts = Math.floor(Date.now() / 1000);
      const sig = signTenantRequest(SECRET, 'GET', path, '', ts);
      return { path, ts, sig };
    }

    it('возвращает пустой список для unknown slug', async () => {
      const { path, ts, sig } = signedGet('nobody');
      const r = await request(app)
        .get(path)
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig);
      expect(r.status).toBe(200);
      expect(r.body.memberships).toEqual([]);
    });

    it('возвращает members с email + role после upsert', async () => {
      const upsertSign = (body: object) => {
        const raw = JSON.stringify(body);
        const ts = Math.floor(Date.now() / 1000);
        const sig = signTenantRequest(SECRET, 'POST', '/admin/memberships', raw, ts);
        return { raw, ts, sig };
      };

      const alice = upsertSign({ email: 'alice@a.co', domainSlug: 'team', role: 'owner' });
      const r1 = await request(app)
        .post('/admin/memberships')
        .set('x-idf-ts', String(alice.ts))
        .set('x-idf-sig', alice.sig)
        .set('content-type', 'application/json')
        .send(alice.raw);
      expect(r1.status).toBe(200);

      const bob = upsertSign({ email: 'bob@a.co', domainSlug: 'team', role: 'sdr' });
      const r2 = await request(app)
        .post('/admin/memberships')
        .set('x-idf-ts', String(bob.ts))
        .set('x-idf-sig', bob.sig)
        .set('content-type', 'application/json')
        .send(bob.raw);
      expect(r2.status).toBe(200);

      const { path, ts, sig } = signedGet('team');
      const r = await request(app)
        .get(path)
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig);

      expect(r.status).toBe(200);
      expect(r.body.memberships).toHaveLength(2);
      const emails = r.body.memberships.map((m: { email: string }) => m.email).sort();
      expect(emails).toEqual(['alice@a.co', 'bob@a.co']);
      const bobRow = r.body.memberships.find((m: { email: string }) => m.email === 'bob@a.co');
      expect(bobRow.role).toBe('sdr');
      expect(bobRow.revoked).toBe(false);
    });

    it('GET без подписи → 401', async () => {
      const r = await request(app).get('/admin/memberships?domainSlug=any');
      expect(r.status).toBe(401);
    });
  });

  describe('GET /admin/invites', () => {
    function signedGet(domainSlug: string) {
      const path = `/admin/invites?domainSlug=${domainSlug}`;
      const ts = Math.floor(Date.now() / 1000);
      const sig = signTenantRequest(SECRET, 'GET', path, '', ts);
      return { path, ts, sig };
    }

    beforeEach(async () => {
      await handle.pool.query('DELETE FROM invites');
    });

    it('возвращает пустой список для unknown slug', async () => {
      const { path, ts, sig } = signedGet('nobody');
      const r = await request(app)
        .get(path)
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig);
      expect(r.status).toBe(200);
      expect(r.body.invites).toEqual([]);
    });

    it('возвращает pending invite с email + role', async () => {
      await handle.pool.query(
        `INSERT INTO invites (nonce_hash, email, domain_slug, role, expires_at)
         VALUES ('hash1', 'pending@a.co', 'team', 'sdr', now() + interval '24 hours')`,
      );

      const { path, ts, sig } = signedGet('team');
      const r = await request(app)
        .get(path)
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig);

      expect(r.status).toBe(200);
      expect(r.body.invites).toHaveLength(1);
      expect(r.body.invites[0].email).toBe('pending@a.co');
      expect(r.body.invites[0].role).toBe('sdr');
    });

    it('фильтрует accepted / revoked / expired', async () => {
      await handle.pool.query(`
        INSERT INTO invites (nonce_hash, email, domain_slug, role, expires_at, accepted_at)
          VALUES ('hash_accepted', 'accepted@a.co', 'team', 'sdr', now() + interval '24 hours', now());
        INSERT INTO invites (nonce_hash, email, domain_slug, role, expires_at, revoked_at)
          VALUES ('hash_revoked', 'revoked@a.co', 'team', 'sdr', now() + interval '24 hours', now());
        INSERT INTO invites (nonce_hash, email, domain_slug, role, expires_at)
          VALUES ('hash_expired', 'expired@a.co', 'team', 'sdr', now() - interval '1 hour');
        INSERT INTO invites (nonce_hash, email, domain_slug, role, expires_at)
          VALUES ('hash_pending', 'pending@a.co', 'team', 'sdr', now() + interval '24 hours');
      `);

      const { path, ts, sig } = signedGet('team');
      const r = await request(app)
        .get(path)
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig);

      expect(r.status).toBe(200);
      expect(r.body.invites).toHaveLength(1);
      expect(r.body.invites[0].email).toBe('pending@a.co');
    });

    it('GET без подписи → 401', async () => {
      const r = await request(app).get('/admin/invites?domainSlug=any');
      expect(r.status).toBe(401);
    });

    it('invalid domainSlug → 400', async () => {
      const path = '/admin/invites?domainSlug=BAD_UPPER';
      const ts = Math.floor(Date.now() / 1000);
      const sig = signTenantRequest(SECRET, 'GET', path, '', ts);
      const r = await request(app)
        .get(path)
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig);
      expect(r.status).toBe(400);
    });
  });

  describe('POST /admin/agent-tokens/issue', () => {
    function signedIssue(body: object) {
      const raw = JSON.stringify(body);
      const ts = Math.floor(Date.now() / 1000);
      const sig = signTenantRequest(SECRET, 'POST', '/admin/agent-tokens/issue', raw, ts);
      return { raw, ts, sig };
    }

    it('без HMAC → 401', async () => {
      const r = await request(app)
        .post('/admin/agent-tokens/issue')
        .send({ sub: 'agent:abc12345', domainSlug: 'acme', role: 'agent' });
      expect(r.status).toBe(401);
    });

    it('issues JWT с aud=agent + memberships single-slug', async () => {
      const body = { sub: 'agent:abc12345', domainSlug: 'acme', role: 'agent' };
      const { raw, ts, sig } = signedIssue(body);
      const r = await request(app)
        .post('/admin/agent-tokens/issue')
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig)
        .set('content-type', 'application/json')
        .send(raw);
      expect(r.status).toBe(200);
      expect(r.body.sub).toBe('agent:abc12345');
      expect(typeof r.body.jwt).toBe('string');
      expect(r.body.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));

      const claims = await verifyJwt(keys, r.body.jwt);
      expect(claims.memberships).toEqual([{ domainSlug: 'acme', role: 'agent' }]);
      expect((claims as { aud?: string | string[] }).aud).toBe('agent');
      expect(claims.sub).toBe('agent:abc12345');
    });

    it('default ttl = 365 days', async () => {
      const body = { sub: 'agent:longlived01', domainSlug: 'acme', role: 'agent' };
      const { raw, ts, sig } = signedIssue(body);
      const r = await request(app)
        .post('/admin/agent-tokens/issue')
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig)
        .set('content-type', 'application/json')
        .send(raw);
      expect(r.status).toBe(200);
      const expectedExp = Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60;
      // допуск ±10s на test-clock skew
      expect(Math.abs(r.body.exp - expectedExp)).toBeLessThan(10);
    });

    it('кастомный ttlDays + preapproval — claims проброшены в JWT', async () => {
      const body = {
        sub: 'agent:scoped12',
        domainSlug: 'acme',
        role: 'agent',
        ttlDays: 30,
        preapproval: { maxAmount: 5000, dailySum: 50000, active: true },
      };
      const { raw, ts, sig } = signedIssue(body);
      const r = await request(app)
        .post('/admin/agent-tokens/issue')
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig)
        .set('content-type', 'application/json')
        .send(raw);
      expect(r.status).toBe(200);

      const claims = await verifyJwt(keys, r.body.jwt) as {
        preapproval?: Record<string, unknown>;
      };
      expect(claims.preapproval).toEqual({ maxAmount: 5000, dailySum: 50000, active: true });
      // ttl=30 дней
      const expectedExp = Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60;
      expect(Math.abs(r.body.exp - expectedExp)).toBeLessThan(10);
    });

    it('invalid body → 400 с issues', async () => {
      const body = { sub: 'short', domainSlug: 'BAD-CASE', role: '' };
      const { raw, ts, sig } = signedIssue(body);
      const r = await request(app)
        .post('/admin/agent-tokens/issue')
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig)
        .set('content-type', 'application/json')
        .send(raw);
      expect(r.status).toBe(400);
      expect(r.body.error).toBe('invalid_body');
      expect(Array.isArray(r.body.issues)).toBe(true);
      expect(r.body.issues.length).toBeGreaterThan(0);
    });

    it('ttlDays > 3650 (10 лет) — 400', async () => {
      const body = { sub: 'agent:tooLong01', domainSlug: 'acme', role: 'agent', ttlDays: 99999 };
      const { raw, ts, sig } = signedIssue(body);
      const r = await request(app)
        .post('/admin/agent-tokens/issue')
        .set('x-idf-ts', String(ts))
        .set('x-idf-sig', sig)
        .set('content-type', 'application/json')
        .send(raw);
      expect(r.status).toBe(400);
    });
  });
});
