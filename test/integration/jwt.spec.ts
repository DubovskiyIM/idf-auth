// test/integration/jwt.spec.ts
// Task 7: sanity-проверка загрузки keypair.
// Task 8 добавит roundtrip / tamper / expire тесты + issue.ts + verify.ts.
import { describe, it, expect } from 'vitest';
import { loadKeys } from '../../src/jwt/keys.js';

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
