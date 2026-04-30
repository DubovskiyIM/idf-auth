import { Router } from 'express';
import { z } from 'zod';
import { eq, and, desc, isNull, gt } from 'drizzle-orm';
import { sql } from 'drizzle-orm';
import { users, memberships, invites } from '../db/schema.js';
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

  /**
   * GET /admin/memberships?domainSlug=X — список members tenant'а для control
   * plane'а (team management UI). HMAC-signed на query-params + empty body.
   *
   * Возвращает active + revoked (для audit); studio фильтрует по нужде.
   */
  router.get('/admin/memberships', async (req: any, res, next) => {
    try {
      const ts = Number(req.get('x-idf-ts') ?? '0');
      const sig = req.get('x-idf-sig') ?? '';
      // GET с query-params — signer должен подписать pathname+search.
      const path = req.originalUrl;
      const now = Math.floor(Date.now() / 1000);

      if (!verifyTenantRequest(deps.tenantSecret, 'GET', path, '', ts, sig, now)) {
        return res.status(401).json({ error: 'bad_signature' });
      }

      const parsed = z.object({ domainSlug: z.string().regex(/^[a-z0-9-]+$/) }).safeParse(req.query);
      if (!parsed.success) return res.status(400).json({ error: 'invalid_query' });

      const rows = await deps.db
        .select({
          id: memberships.id,
          userId: memberships.userId,
          role: memberships.role,
          revoked: memberships.revoked,
          createdAt: memberships.createdAt,
          email: users.email,
        })
        .from(memberships)
        .innerJoin(users, eq(memberships.userId, users.id))
        .where(eq(memberships.domainSlug, parsed.data.domainSlug))
        .orderBy(desc(memberships.createdAt));

      res.json({ memberships: rows });
    } catch (e) {
      next(e);
    }
  });

  /**
   * GET /admin/invites?domainSlug=X — pending invites (не accept'нутые, не revoked,
   * не expired) для tenant'а. HMAC-signed по тому же pattern'у, что /admin/memberships.
   *
   * Owner не видит list'а «кого пригласил» в UI без этого endpoint'а — после POST
   * /invites email ушёл, но в tenant manage нет обратной связи до первого accept'а.
   */
  router.get('/admin/invites', async (req: any, res, next) => {
    try {
      const ts = Number(req.get('x-idf-ts') ?? '0');
      const sig = req.get('x-idf-sig') ?? '';
      const path = req.originalUrl;
      const now = Math.floor(Date.now() / 1000);

      if (!verifyTenantRequest(deps.tenantSecret, 'GET', path, '', ts, sig, now)) {
        return res.status(401).json({ error: 'bad_signature' });
      }

      const parsed = z.object({ domainSlug: z.string().regex(/^[a-z0-9-]+$/) }).safeParse(req.query);
      if (!parsed.success) return res.status(400).json({ error: 'invalid_query' });

      const rows = await deps.db
        .select({
          id: invites.id,
          email: invites.email,
          role: invites.role,
          createdAt: invites.createdAt,
          expiresAt: invites.expiresAt,
        })
        .from(invites)
        .where(
          and(
            eq(invites.domainSlug, parsed.data.domainSlug),
            isNull(invites.acceptedAt),
            isNull(invites.revokedAt),
            gt(invites.expiresAt, new Date()),
          ),
        )
        .orderBy(desc(invites.createdAt));

      res.json({ invites: rows });
    } catch (e) {
      next(e);
    }
  });

  /**
   * POST /admin/agent-tokens/issue — выпуск long-lived JWT для agent.
   *
   * Используется control plane'ом (studio) при создании agent-token'а —
   * отдаёт JWT, который agent (LLM/bot) присылает в Authorization. Studio
   * хранит метаданные (label, tokenHash, preapprovalJson, revokedAt);
   * idf-auth — только signing-side (он держит keys + revocation).
   *
   * HMAC-signed по той же схеме, что /admin/memberships.
   *
   * Body:
   *   sub: string         — стабильный agent-id (например, `agent:<uuid>`).
   *                          Он же попадёт в JWT.sub и в audit log как actor.
   *   domainSlug: string  — tenant slug.
   *   role: string        — agent-role в ontology (canExecute / preapproval).
   *   ttlDays?: number    — TTL, default 365.
   *   preapproval?: object — per-token override поверх ontology preapproval.
   *
   * Returns: { jwt, sub, exp } — exp как unix-timestamp для UI.
   */
  router.post('/admin/agent-tokens/issue', async (req: any, res, next) => {
    try {
      const ts = Number(req.get('x-idf-ts') ?? '0');
      const sig = req.get('x-idf-sig') ?? '';
      const raw: string = req.rawBody ?? JSON.stringify(req.body);
      const now = Math.floor(Date.now() / 1000);

      if (!verifyTenantRequest(deps.tenantSecret, 'POST', '/admin/agent-tokens/issue', raw, ts, sig, now)) {
        return res.status(401).json({ error: 'bad_signature' });
      }

      const parsed = AgentTokenIssueSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({
          error: 'invalid_body',
          issues: parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`),
        });
      }

      const ttlDays = parsed.data.ttlDays ?? 365;
      const sub = parsed.data.sub;
      const exp = Math.floor(Date.now() / 1000) + ttlDays * 24 * 60 * 60;

      const jwt = await issueJwt(deps.keys, {
        sub,
        memberships: [{ domainSlug: parsed.data.domainSlug, role: parsed.data.role }],
        ttlDays,
        aud: 'agent',
        preapproval: parsed.data.preapproval,
      });

      res.json({ jwt, sub, exp });
    } catch (e) {
      next(e);
    }
  });

  return router;
}

/**
 * Зод-схема для /admin/agent-tokens/issue body.
 *
 * sub — agent-id, должен быть стабильным (caller storing). Format:
 * `agent:<token-uuid>` рекомендуется (отличает от обычного user UUID в audit
 * log как actor).
 *
 * preapproval — opaque dict (любые predicate ключи). Не валидируем shape тут,
 * runtime + SDK preapprovalGuard сами разберутся (active/notExpired/maxAmount/
 * csvInclude/dailySum).
 */
const AgentTokenIssueSchema = z.object({
  sub: z.string().min(8).max(128),
  domainSlug: z.string().regex(/^[a-z0-9-]+$/),
  role: z.string().min(1),
  ttlDays: z.number().int().min(1).max(3650).optional(),
  preapproval: z.record(z.unknown()).optional(),
});
