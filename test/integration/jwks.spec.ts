// test/integration/jwks.spec.ts
import { describe, it, expect, beforeAll } from 'vitest';
import express from 'express';
import request from 'supertest';
import { loadKeys } from '../../src/jwt/keys.js';
import { createJwksRouter } from '../../src/jwks/routes.js';

describe('GET /.well-known/jwks.json', () => {
  let app: express.Express;

  beforeAll(async () => {
    const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
    const keys = await loadKeys(await exportSPKI(publicKey), await exportPKCS8(privateKey));
    app = express();
    app.use(createJwksRouter(keys));
  });

  it('returns JWKs with single RSA key', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
    expect(res.body.keys[0]).toMatchObject({
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
    });
    expect(res.body.keys[0].kid).toMatch(/^[0-9a-f]{16}$/);
  });

  it('sets cache headers', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.headers['cache-control']).toMatch(/max-age=\d+/);
  });

  it('contains RSA public key material (n + e)', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    expect(res.body.keys[0]).toHaveProperty('n');
    expect(res.body.keys[0]).toHaveProperty('e');
  });

  it('does not leak private key material', async () => {
    const res = await request(app).get('/.well-known/jwks.json');
    const jwk = res.body.keys[0];
    for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(jwk).not.toHaveProperty(field);
    }
  });
});
