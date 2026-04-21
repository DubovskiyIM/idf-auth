import { Router } from 'express';
import { z } from 'zod';
import { and, eq, gte } from 'drizzle-orm';
import { memberships } from '../db/schema.js';
import { verifyTenantRequest } from '../invites/hmac.js';
import type { DB } from '../db/client.js';

const RevokeSchema = z.object({
  membershipId: z.string().uuid(),
});

export type RevocationRouterDeps = {
  db: DB;
  tenantSecret: string;
};

export function createRevocationRouter(deps: RevocationRouterDeps): Router {
  const router = Router();

  router.post('/revoke', async (req: any, res, next) => {
    try {
      const ts = Number(req.get('x-idf-ts') ?? '0');
      const sig = req.get('x-idf-sig') ?? '';
      const raw: string = req.rawBody ?? JSON.stringify(req.body);
      const now = Math.floor(Date.now() / 1000);
      if (!verifyTenantRequest(deps.tenantSecret, 'POST', '/revoke', raw, ts, sig, now)) {
        return res.status(401).json({ error: 'bad_signature' });
      }
      const parsed = RevokeSchema.safeParse(req.body);
      if (!parsed.success) return res.status(400).json({ error: 'invalid_body' });

      await deps.db
        .update(memberships)
        .set({ revoked: true, revokedAt: new Date() })
        .where(eq(memberships.id, parsed.data.membershipId));

      res.json({ status: 'revoked' });
    } catch (e) {
      next(e);
    }
  });

  router.get('/revocations', async (req, res, next) => {
    try {
      const since = new Date(String(req.query.since ?? new Date(0).toISOString()));
      const slug = String(req.query.domainSlug ?? '');
      if (!slug) return res.status(400).json({ error: 'domainSlug required' });

      const rows = await deps.db.query.memberships.findMany({
        where: (m, { and, eq, gte }) =>
          and(eq(m.revoked, true), eq(m.domainSlug, slug), gte(m.revokedAt, since)),
      });

      res.json({
        revocations: rows.map(r => ({
          membershipId: r.id,
          userId: r.userId,
          domainSlug: r.domainSlug,
          revokedAt: r.revokedAt,
        })),
      });
    } catch (e) {
      next(e);
    }
  });

  return router;
}
