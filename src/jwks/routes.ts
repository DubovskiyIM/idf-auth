// src/jwks/routes.ts
// Публичный JWKs endpoint — отдаёт набор публичных ключей для верификации JWT.
// Используется внешними сервисами (resource servers) для проверки подписи.
import { Router } from 'express';
import { exportJWK } from 'jose';
import type { JwtKeys } from '../jwt/keys.js';

export function createJwksRouter(keys: JwtKeys): Router {
  const router = Router();

  router.get('/.well-known/jwks.json', async (_req, res) => {
    const jwk = await exportJWK(keys.publicKey);
    res.set('Cache-Control', 'public, max-age=3600');
    res.json({
      keys: [{ ...jwk, kid: keys.kid, alg: 'RS256', use: 'sig' }],
    });
  });

  return router;
}
