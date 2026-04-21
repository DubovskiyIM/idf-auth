// src/jwt/issue.ts
// Выпуск RS256 JWT с claims sub + memberships.
// Issuer зафиксирован как 'auth.idf.dev' — параметризация в M2.
import { SignJWT } from 'jose';
import type { JwtKeys } from './keys.js';

export type Membership = { domainSlug: string; role: string };

export type IssueInput = {
  sub: string;
  memberships: Membership[];
  ttlDays: number;
};

export async function issueJwt(keys: JwtKeys, input: IssueInput): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + input.ttlDays * 24 * 60 * 60;
  return await new SignJWT({ memberships: input.memberships })
    .setProtectedHeader({ alg: 'RS256', kid: keys.kid, typ: 'JWT' })
    .setSubject(input.sub)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setIssuer('auth.idf.dev')
    .sign(keys.privateKey);
}
