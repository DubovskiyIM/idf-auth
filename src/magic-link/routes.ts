import { Router } from 'express';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { generateNonce, hashNonce } from './nonce.js';
import { magicLinks, users, memberships } from '../db/schema.js';
import type { DB } from '../db/client.js';
import type { EmailSender } from './email.js';
import type { JwtKeys } from '../jwt/keys.js';
import { issueJwt } from '../jwt/issue.js';

const IssueSchema = z.object({
  email: z.string().email().transform(s => s.toLowerCase()),
  domainSlug: z.string().regex(/^[a-z0-9-]+$/).optional(),
});

export type MagicLinkRouterDeps = {
  db: DB;
  keys: JwtKeys;
  email: EmailSender;
  baseUrl: string;
  ttlMinutes: number;
  jwtTtlDays: number;
};

export function createMagicLinkRouter(deps: MagicLinkRouterDeps): Router {
  const router = Router();

  router.post('/magic-link', async (req, res, next) => {
    try {
      const parsed = IssueSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'invalid_request', details: parsed.error.issues });
      }
      const { email, domainSlug } = parsed.data;
      const nonce = generateNonce();
      const nonceHash = await hashNonce(nonce);
      const expiresAt = new Date(Date.now() + deps.ttlMinutes * 60 * 1000);

      await deps.db.insert(magicLinks).values({ nonceHash, email, domainSlug, expiresAt });

      const link = `${deps.baseUrl}/magic-link/callback?token=${encodeURIComponent(nonce)}`;
      await deps.email.sendMagicLink(email, link);

      res.json({ status: 'sent' });
    } catch (e) {
      next(e);
    }
  });

  // GET /magic-link/callback — добавится в Task 13
  return router;
}
