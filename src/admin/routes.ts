import { Router } from 'express';
import { z } from 'zod';
import { eq, and } from 'drizzle-orm';
import { sql } from 'drizzle-orm';
import { users, memberships } from '../db/schema.js';
import { verifyTenantRequest } from '../invites/hmac.js';
import { issueJwt } from '../jwt/issue.js';
import type { DB } from '../db/client.js';
import type { JwtKeys } from '../jwt/keys.js';

const MembershipSchema = z.object({
  email: z.string().email().transform((s) => s.toLowerCase()),
  domainSlug: z.string().regex(/^[a-z0-9-]+$/),
  role: z.string().min(1),
});

export type AdminRouterDeps = {
  db: DB;
  keys: JwtKeys;
  tenantSecret: string;
  jwtTtlDays: number;
};

/**
 * Admin endpoint для direct upsert membership'ов без email-invite-flow.
 * Используется control plane'ом (studio) при создании project'а: owner
 * автоматически получает membership role="owner" на новый tenant slug.
 *
 * HMAC-signed по той же схеме, что /invites — только auth'rized каллер
 * (studio с tenantSecret) может вызвать.
 *
 * Идемпотентно: повторный вызов с тем же (user, slug) — upsert без
 * дубликатов, revoked-membership реактивируется.
 *
 * Returns {jwt, memberships} — caller (studio) выставит свежий cookie,
 * чтобы user не релогинился вручную.
 */
export function createAdminRouter(deps: AdminRouterDeps): Router {
  const router = Router();

  router.post('/admin/memberships', async (req: any, res, next) => {
    try {
      const ts = Number(req.get('x-idf-ts') ?? '0');
      const sig = req.get('x-idf-sig') ?? '';
      const raw: string = req.rawBody ?? JSON.stringify(req.body);
      const now = Math.floor(Date.now() / 1000);

      if (!verifyTenantRequest(deps.tenantSecret, 'POST', '/admin/memberships', raw, ts, sig, now)) {
        return res.status(401).json({ error: 'bad_signature' });
      }

      const parsed = MembershipSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

      // Upsert user по email (lower-case)
      let user = await deps.db.query.users.findFirst({
        where: (u) => sql`lower(${u.email}) = ${parsed.data.email}`,
      });
      if (!user) {
        const [inserted] = await deps.db.insert(users).values({ email: parsed.data.email }).returning();
        user = inserted;
      }

      // Upsert membership
      const existing = await deps.db.query.memberships.findFirst({
        where: (m, { and, eq }) => and(eq(m.userId, user!.id), eq(m.domainSlug, parsed.data.domainSlug)),
      });
      if (!existing) {
        await deps.db.insert(memberships).values({
          userId: user.id,
          domainSlug: parsed.data.domainSlug,
          role: parsed.data.role,
        });
      } else if (existing.revoked) {
        await deps.db
          .update(memberships)
          .set({ revoked: false, revokedAt: null, role: parsed.data.role })
          .where(eq(memberships.id, existing.id));
      } else if (existing.role !== parsed.data.role) {
        await deps.db
          .update(memberships)
          .set({ role: parsed.data.role })
          .where(eq(memberships.id, existing.id));
      }

      const active = await deps.db.query.memberships.findMany({
        where: (m, { and, eq }) => and(eq(m.userId, user!.id), eq(m.revoked, false)),
      });
      const membershipList = active.map((m) => ({ domainSlug: m.domainSlug, role: m.role }));

      const jwt = await issueJwt(deps.keys, {
        sub: user.id,
        memberships: membershipList,
        ttlDays: deps.jwtTtlDays,
      });

      res.json({ jwt, memberships: membershipList });
    } catch (e) {
      next(e);
    }
  });

  return router;
}
