// src/jwt/issue.ts
// Выпуск RS256 JWT с claims sub + memberships (+ optional aud + preapproval
// для agent-tokens). Issuer зафиксирован как 'auth.idf.dev' — параметризация
// в M2.
import { SignJWT } from 'jose';
import type { JwtKeys } from './keys.js';

export type Membership = { domainSlug: string; role: string };

export type IssueInput = {
  sub: string;
  memberships: Membership[];
  ttlDays: number;
  /**
   * Audience claim. Для обычных user JWT — undefined (legacy default).
   * Для agent-tokens — 'agent', чтобы runtime мог отличить и применить
   * per-token preapproval claims.
   */
  aud?: string;
  /**
   * Per-token preapproval limits для agent-tokens. Накладываются поверх
   * ontology.roles[role].preapproval в runtime'е. Shape — те же predicates:
   * active / notExpired / maxAmount / csvInclude / dailySum (см. SDK
   * preapprovalGuard). Применяется только когда aud='agent'.
   */
  preapproval?: Record<string, unknown>;
};

export async function issueJwt(keys: JwtKeys, input: IssueInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + input.ttlDays * 24 * 60 * 60;
  const claims: Record<string, unknown> = { memberships: input.memberships };
  if (input.preapproval) claims.preapproval = input.preapproval;
  let builder = new SignJWT(claims)
    .setProtectedHeader({ alg: 'RS256', kid: keys.kid, typ: 'JWT' })
    .setSubject(input.sub)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setIssuer('auth.idf.dev');
  if (input.aud) builder = builder.setAudience(input.aud);
  return await builder.sign(keys.privateKey);
}
