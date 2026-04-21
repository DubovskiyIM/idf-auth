import { createHmac, timingSafeEqual } from 'node:crypto';

const MAX_SKEW_SECONDS = 5 * 60;

function canonical(method: string, path: string, body: string, ts: number): string {
  return `${method.toUpperCase()}\n${path}\n${body}\n${ts}`;
}

export function signTenantRequest(
  secret: string,
  method: string,
  path: string,
  body: string,
  ts: number
): string {
  return createHmac('sha256', secret).update(canonical(method, path, body, ts)).digest('hex');
}

export function verifyTenantRequest(
  secret: string,
  method: string,
  path: string,
  body: string,
  ts: number,
  providedSig: string,
  nowSec: number
): boolean {
  if (Math.abs(nowSec - ts) > MAX_SKEW_SECONDS) return false;
  const expected = signTenantRequest(secret, method, path, body, ts);
  const a = Buffer.from(expected, 'hex');
  const b = Buffer.from(providedSig, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
