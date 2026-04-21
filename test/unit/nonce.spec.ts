import { describe, it, expect } from 'vitest';
import { generateNonce, hashNonce, verifyNonce } from '../../src/magic-link/nonce.js';

describe('nonce', () => {
  it('generates base64url nonce ≥32 bytes entropy', () => {
    const n = generateNonce();
    expect(n).toMatch(/^[A-Za-z0-9_-]{43,}$/);
    expect(n.length).toBeGreaterThanOrEqual(43);
  });

  it('generates unique nonces', () => {
    const set = new Set(Array.from({ length: 1000 }, () => generateNonce()));
    expect(set.size).toBe(1000);
  });

  it('hashes deterministically', async () => {
    const n = 'test-nonce';
    const h1 = await hashNonce(n);
    const h2 = await hashNonce(n);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('verifies matching nonce against its hash', async () => {
    const n = generateNonce();
    const h = await hashNonce(n);
    expect(await verifyNonce(n, h)).toBe(true);
    expect(await verifyNonce('wrong', h)).toBe(false);
  });
});
