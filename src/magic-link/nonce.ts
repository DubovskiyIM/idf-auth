import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

export function generateNonce(): string {
  return randomBytes(32).toString('base64url');
}

export async function hashNonce(nonce: string): Promise<string> {
  return createHash('sha256').update(nonce).digest('hex');
}

export async function verifyNonce(nonce: string, hash: string): Promise<boolean> {
  const candidate = await hashNonce(nonce);
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
