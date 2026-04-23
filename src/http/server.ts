import express from 'express';
import { pinoHttp } from 'pino-http';
import { logger } from '../logger.js';
import type { Env } from '../env.js';
import { createDb } from '../db/client.js';
import { loadKeys } from '../jwt/keys.js';
import { createEmailSender } from '../magic-link/email.js';
import { createJwksRouter } from '../jwks/routes.js';
import { createMagicLinkRouter } from '../magic-link/routes.js';
import { createInvitesRouter } from '../invites/routes.js';
import { createRevocationRouter } from '../revocation/routes.js';
import { createAdminRouter } from '../admin/routes.js';
import { createHealthRouter } from '../health/routes.js';
import { createMagicLinkLimiter, createInviteLimiter } from '../rate-limit/middleware.js';
import { errorMiddleware } from './errors.js';

export async function createServer(env: Env) {
  const { db, pool } = createDb(env.DATABASE_URL);
  const keys = await loadKeys(env.JWT_PUBLIC_KEY_PEM, env.JWT_PRIVATE_KEY_PEM);
  const email = createEmailSender(env);
  const magicLimiter = createMagicLinkLimiter(pool);
  const inviteLimiter = createInviteLimiter(pool);

  const app = express();
  app.use(pinoHttp({ logger }));
  app.use(express.json({ verify: (req: any, _res, buf) => { req.rawBody = buf.toString('utf8'); } }));

  app.use(createHealthRouter({ pool }));
  app.use(createJwksRouter(keys));
  app.use(
    createMagicLinkRouter({
      db,
      keys,
      email,
      baseUrl: env.APP_BASE_URL,
      ttlMinutes: env.MAGIC_LINK_TTL_MINUTES,
      jwtTtlDays: env.JWT_TTL_DAYS,
      limiter: magicLimiter,
    })
  );
  app.use(
    createInvitesRouter({
      db,
      keys,
      email,
      tenantSecret: env.TENANT_HMAC_SECRET,
      baseUrl: env.APP_BASE_URL,
      ttlHours: 24,
      jwtTtlDays: env.JWT_TTL_DAYS,
      limiter: inviteLimiter,
    })
  );
  app.use(
    createRevocationRouter({
      db,
      tenantSecret: env.TENANT_HMAC_SECRET,
    })
  );
  app.use(
    createAdminRouter({
      db,
      keys,
      tenantSecret: env.TENANT_HMAC_SECRET,
      jwtTtlDays: env.JWT_TTL_DAYS,
    })
  );
  app.use(errorMiddleware);

  return { app, pool };
}
