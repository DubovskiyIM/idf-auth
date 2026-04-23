import { Router } from 'express';
import { z } from 'zod';
import { eq, sql } from 'drizzle-orm';
import type { RateLimiterPostgres } from 'rate-limiter-flexible';
import { invites, users, memberships } from '../db/schema.js';
import { generateNonce, hashNonce } from '../magic-link/nonce.js';
import { verifyTenantRequest } from './hmac.js';
import { issueJwt } from '../jwt/issue.js';
import { limitByIp } from '../rate-limit/middleware.js';
import type { DB } from '../db/client.js';
import type { JwtKeys } from '../jwt/keys.js';
import type { EmailSender } from '../magic-link/email.js';

const InviteSchema = z.object({
  email: z.string().email().transform(s => s.toLowerCase()),
  domainSlug: z.string().regex(/^[a-z0-9-]+$/),
  role: z.string().min(1),
  inviterEmail: z.string().email(),
  /** Cookie-setter URL в studio/control-plane. После accept'а invitee redirect'ится сюда с JWT в query. */
  redirectTo: z.string().url().optional(),
});

export type InvitesRouterDeps = {
  db: DB;
  keys: JwtKeys;
  email: EmailSender;
  tenantSecret: string;
  baseUrl: string;
  ttlHours: number;
  jwtTtlDays: number;
  limiter?: RateLimiterPostgres;
};

export function createInvitesRouter(deps: InvitesRouterDeps): Router {
  const router = Router();

  const mwares = deps.limiter ? [limitByIp(deps.limiter)] : [];
  router.post('/invites', ...mwares, async (req: any, res, next) => {
    try {
      const ts = Number(req.get('x-idf-ts') ?? '0');
      const sig = req.get('x-idf-sig') ?? '';
      const raw: string = req.rawBody ?? JSON.stringify(req.body);
      const now = Math.floor(Date.now() / 1000);

      if (!verifyTenantRequest(deps.tenantSecret, 'POST', '/invites', raw, ts, sig, now)) {
        return res.status(401).json({ error: 'bad_signature' });
      }

      const parsed = InviteSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

      const nonce = generateNonce();
      const nonceHash = await hashNonce(nonce);
      const expiresAt = new Date(Date.now() + deps.ttlHours * 60 * 60 * 1000);

      await deps.db.insert(invites).values({
        nonceHash,
        email: parsed.data.email,
        domainSlug: parsed.data.domainSlug,
        role: parsed.data.role,
        expiresAt,
      });

      // Если control plane передал redirectTo — прокидываем в link. invites/accept
      // после нажатия прочитает его из query и сделает 302 на studio cookie-setter.
      const qs = new URLSearchParams({ token: nonce });
      if (parsed.data.redirectTo) qs.set('redirectTo', parsed.data.redirectTo);
      const link = `${deps.baseUrl}/invites/accept?${qs.toString()}`;
      await deps.email.sendInvite(
        parsed.data.email,
        link,
        parsed.data.inviterEmail,
        parsed.data.domainSlug
      );

      res.json({ status: 'sent' });
    } catch (e) {
      next(e);
    }
  });

  router.get('/invites/accept', async (req, res, next) => {
    try {
      const tokenParam = String(req.query.token ?? '');
      if (!tokenParam) return res.status(400).json({ error: 'missing_token' });

      const nonceHash = await hashNonce(tokenParam);
      const invite = await deps.db.query.invites.findFirst({
        where: (t, { eq }) => eq(t.nonceHash, nonceHash),
      });
      if (!invite) return res.status(400).json({ error: 'unknown_token' });
      if (invite.acceptedAt) return res.status(400).json({ error: 'already_used' });
      if (invite.revokedAt) return res.status(400).json({ error: 'revoked' });
      if (invite.expiresAt.getTime() < Date.now()) return res.status(400).json({ error: 'expired' });

      let user = await deps.db.query.users.findFirst({
        where: (u) => sql`lower(${u.email}) = ${invite.email.toLowerCase()}`,
      });
      if (!user) {
        const [inserted] = await deps.db.insert(users).values({ email: invite.email }).returning();
        user = inserted;
      }

      const existing = await deps.db.query.memberships.findFirst({
        where: (m, { and, eq }) => and(eq(m.userId, user!.id), eq(m.domainSlug, invite.domainSlug)),
      });
      if (!existing) {
        await deps.db.insert(memberships).values({
          userId: user.id,
          domainSlug: invite.domainSlug,
          role: invite.role,
        });
      } else if (existing.revoked) {
        await deps.db
          .update(memberships)
          .set({ revoked: false, revokedAt: null, role: invite.role })
          .where(eq(memberships.id, existing.id));
      }

      await deps.db
        .update(invites)
        .set({ acceptedAt: new Date() })
        .where(eq(invites.id, invite.id));

      const allMemberships = await deps.db.query.memberships.findMany({
        where: (m, { and, eq }) => and(eq(m.userId, user!.id), eq(m.revoked, false)),
      });

      const jwt = await issueJwt(deps.keys, {
        sub: user.id,
        memberships: allMemberships.map(m => ({ domainSlug: m.domainSlug, role: m.role })),
        ttlDays: deps.jwtTtlDays,
      });

      // Invitee click'ает email-link и должен попасть в studio cookie-setter.
      // Без redirect'а они получают raw JSON и теряются. Берём redirectTo из
      // query (studio шлёт его в POST /invites payload → invite link строит
      // его → возвращает сюда), fallback на APP_BASE_URL (который в prod ==
      // studio.intent-design.tech).
      const redirectTo = String(req.query.redirectTo ?? '');
      if (redirectTo) {
        try {
          const u = new URL(redirectTo);
          u.searchParams.set('jwt', jwt);
          u.searchParams.set('email', user.email);
          return res.redirect(u.toString());
        } catch {
          // невалидный URL — JSON fallback
        }
      }

      res.json({ jwt, user: { id: user.id, email: user.email } });
    } catch (e) {
      next(e);
    }
  });

  return router;
}
