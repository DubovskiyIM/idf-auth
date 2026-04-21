import { Router } from 'express';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import type { RateLimiterPostgres } from 'rate-limiter-flexible';
import { generateNonce, hashNonce } from './nonce.js';
import { magicLinks, users } from '../db/schema.js';
import type { DB } from '../db/client.js';
import type { EmailSender } from './email.js';
import type { JwtKeys } from '../jwt/keys.js';
import { issueJwt } from '../jwt/issue.js';
import { limitByEmail } from '../rate-limit/middleware.js';

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
  limiter?: RateLimiterPostgres;
};

export function createMagicLinkRouter(deps: MagicLinkRouterDeps): Router {
  const router = Router();

  const mwares = deps.limiter ? [limitByEmail(deps.limiter)] : [];
  router.post('/magic-link', ...mwares, async (req, res, next) => {
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

  router.get('/magic-link/callback', async (req, res, next) => {
    try {
      const tokenParam = String(req.query.token ?? '');
      if (!tokenParam) return res.status(400).json({ error: 'missing_token' });

      const nonceHash = await hashNonce(tokenParam);
      const row = await deps.db.query.magicLinks.findFirst({
        where: (t, { eq }) => eq(t.nonceHash, nonceHash),
      });

      if (!row) return res.status(400).json({ error: 'unknown_token' });
      if (row.usedAt) return res.status(400).json({ error: 'already_used' });
      if (row.expiresAt.getTime() < Date.now()) return res.status(400).json({ error: 'expired' });

      await deps.db.update(magicLinks).set({ usedAt: new Date() }).where(eq(magicLinks.id, row.id));

      let user = await deps.db.query.users.findFirst({
        where: (u, { sql }) => sql`lower(${u.email}) = ${row.email.toLowerCase()}`,
      });
      if (!user) {
        const [inserted] = await deps.db.insert(users).values({ email: row.email }).returning();
        user = inserted;
      } else {
        await deps.db.update(users).set({ lastActiveAt: new Date() }).where(eq(users.id, user.id));
      }

      const rows = await deps.db.query.memberships.findMany({
        where: (m, { and, eq }) => and(eq(m.userId, user!.id), eq(m.revoked, false)),
      });
      const memberships = rows.map((r) => ({ domainSlug: r.domainSlug, role: r.role }));

      const jwt = await issueJwt(deps.keys, { sub: user.id, memberships, ttlDays: deps.jwtTtlDays });

      res.json({ jwt, user: { id: user.id, email: user.email }, memberships });
    } catch (e) {
      next(e);
    }
  });

  return router;
}
