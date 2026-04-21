// test/integration/jwt.spec.ts
// Task 7: sanity-проверка загрузки keypair.
// Task 8: roundtrip / tamper / expire тесты + issue.ts + verify.ts.
import { describe, it, expect, beforeAll } from 'vitest';
import { loadKeys } from '../../src/jwt/keys.js';
import { issueJwt } from '../../src/jwt/issue.js';
import { verifyJwt } from '../../src/jwt/verify.js';

describe('jwt keys', () => {
  it('loads generated keypair', async () => {
    // Генерируем ad-hoc keypair прямо в тесте — не зависим от env.
    const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
    const pubPem = await exportSPKI(publicKey);
    const privPem = await exportPKCS8(privateKey);

    const keys = await loadKeys(pubPem, privPem);

    expect(keys.kid).toMatch(/^[0-9a-f]{16}$/);
    expect(keys.publicKey).toBeTruthy();
    expect(keys.privateKey).toBeTruthy();
  });

  it('kid детерминирован для одинакового pubkey', async () => {
    const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
    const pubPem = await exportSPKI(publicKey);
    const privPem = await exportPKCS8(privateKey);
    const a = await loadKeys(pubPem, privPem);
    const b = await loadKeys(pubPem, privPem);
    expect(a.kid).toBe(b.kid);
  });

  it('разные keypair → разные kid', async () => {
    const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
    const kp1 = await generateKeyPair('RS256', { extractable: true });
    const kp2 = await generateKeyPair('RS256', { extractable: true });
    const k1 = await loadKeys(await exportSPKI(kp1.publicKey), await exportPKCS8(kp1.privateKey));
    const k2 = await loadKeys(await exportSPKI(kp2.publicKey), await exportPKCS8(kp2.privateKey));
    expect(k1.kid).not.toBe(k2.kid);
  });

  it('падает на некорректном PEM', async () => {
    await expect(loadKeys('garbage', 'nonsense')).rejects.toThrow();
  });
});

describe('jwt issue/verify', () => {
  let keys: Awaited<ReturnType<typeof loadKeys>>;

  beforeAll(async () => {
    const { generateKeyPair, exportSPKI, exportPKCS8 } = await import('jose');
    const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });
    keys = await loadKeys(await exportSPKI(publicKey), await exportPKCS8(privateKey));
  });

  it('roundtrips claims', async () => {
    const token = await issueJwt(keys, {
      sub: 'user-123',
      memberships: [{ domainSlug: 'acme', role: 'csm' }],
      ttlDays: 30,
    });
    const claims = await verifyJwt(keys, token);
    expect(claims.sub).toBe('user-123');
    expect(claims.memberships).toEqual([{ domainSlug: 'acme', role: 'csm' }]);
  });

  it('rejects tampered token', async () => {
    const token = await issueJwt(keys, { sub: 'u1', memberships: [], ttlDays: 30 });
    const tampered = token.slice(0, -5) + 'xxxxx';
    await expect(verifyJwt(keys, tampered)).rejects.toThrow();
  });

  it('rejects expired token', async () => {
    const token = await issueJwt(keys, { sub: 'u1', memberships: [], ttlDays: -1 });
    await expect(verifyJwt(keys, token)).rejects.toThrow(/expired|exp/i);
  });
});
