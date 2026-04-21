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
});
