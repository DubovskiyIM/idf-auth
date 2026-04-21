// src/jwt/verify.ts
// Верификация RS256 JWT с проверкой issuer и алгоритма.
import { jwtVerify } from 'jose';
import type { JwtKeys } from './keys.js';
import type { Membership } from './issue.js';

export type JwtClaims = {
  sub: string;
  memberships: Membership[];
  iat: number;
  exp: number;
  iss: string;
};

export async function verifyJwt(keys: JwtKeys, token: string): Promise<JwtClaims> {
  const { payload } = await jwtVerify(token, keys.publicKey, {
    issuer: 'auth.idf.dev',
    algorithms: ['RS256'],
  });
  return payload as unknown as JwtClaims;
}
