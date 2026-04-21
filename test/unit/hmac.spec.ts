import { describe, it, expect } from 'vitest';
import { signTenantRequest, verifyTenantRequest } from '../../src/invites/hmac.js';

const SECRET = 'a'.repeat(64);

describe('hmac tenant signatures', () => {
  it('roundtrip sign/verify', () => {
    const sig = signTenantRequest(SECRET, 'POST', '/invites', '{"email":"x@y.z"}', 1700000000);
    const ok = verifyTenantRequest(SECRET, 'POST', '/invites', '{"email":"x@y.z"}', 1700000000, sig, 1700000100);
    expect(ok).toBe(true);
  });

  it('rejects wrong secret', () => {
    const sig = signTenantRequest(SECRET, 'POST', '/invites', '', 1700000000);
    const ok = verifyTenantRequest('wrong'.repeat(16), 'POST', '/invites', '', 1700000000, sig, 1700000100);
    expect(ok).toBe(false);
  });

  it('rejects tampered body', () => {
    const sig = signTenantRequest(SECRET, 'POST', '/invites', '{"a":1}', 1700000000);
    const ok = verifyTenantRequest(SECRET, 'POST', '/invites', '{"a":2}', 1700000000, sig, 1700000100);
    expect(ok).toBe(false);
  });

  it('rejects stale timestamp (>5 min skew)', () => {
    const sig = signTenantRequest(SECRET, 'POST', '/invites', '', 1700000000);
    const ok = verifyTenantRequest(SECRET, 'POST', '/invites', '', 1700000000, sig, 1700000000 + 10 * 60);
    expect(ok).toBe(false);
  });
});
