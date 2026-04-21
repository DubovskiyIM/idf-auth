// src/jwt/keys.ts
// Загрузка RS256 keypair из PEM-строк (берутся из env).
// kid — детерминированный 16-символьный hex SHA-256 от публичного ключа.
// Rotation в M2 введёт versioning; для M1 достаточно single-key setup.
import { importSPKI, importPKCS8 } from 'jose';
import type { KeyLike } from 'jose';

export type JwtKeys = {
  publicKey: KeyLike;
  privateKey: KeyLike;
  kid: string;
};

export async function loadKeys(publicPem: string, privatePem: string): Promise<JwtKeys> {
  const publicKey = await importSPKI(publicPem, 'RS256');
  const privateKey = await importPKCS8(privatePem, 'RS256');

  // Детерминированный kid из первых 16 hex-символов SHA-256 от публичного ключа.
  const kidBuf = new TextEncoder().encode(publicPem);
  const hash = await crypto.subtle.digest('SHA-256', kidBuf);
  const kid = Buffer.from(hash).toString('hex').slice(0, 16);

  return { publicKey, privateKey, kid };
}
