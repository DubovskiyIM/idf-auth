import { describe, it, expect } from 'vitest';
import { loadEnv } from '../../src/env.js';

describe('env', () => {
  it('rejects missing DATABASE_URL', () => {
    expect(() => loadEnv({})).toThrow(/DATABASE_URL/);
  });

  it('accepts complete env', () => {
    const env = loadEnv({
      DATABASE_URL: 'postgres://localhost/test',
      JWT_PRIVATE_KEY_PEM: '-----BEGIN PRIVATE KEY-----\nXX\n-----END PRIVATE KEY-----',
      JWT_PUBLIC_KEY_PEM: '-----BEGIN PUBLIC KEY-----\nXX\n-----END PUBLIC KEY-----',
      TENANT_HMAC_SECRET: 'a'.repeat(64),
      RESEND_API_KEY: 're_test',
      APP_BASE_URL: 'https://auth.idf.dev',
      PORT: '4000',
    });
    expect(env.PORT).toBe(4000);
    expect(env.MAGIC_LINK_TTL_MINUTES).toBe(15); // default
    expect(env.JWT_TTL_DAYS).toBe(30);
  });

  it('rejects short TENANT_HMAC_SECRET', () => {
    expect(() =>
      loadEnv({
        DATABASE_URL: 'postgres://localhost/test',
        JWT_PRIVATE_KEY_PEM: 'x',
        JWT_PUBLIC_KEY_PEM: 'x',
        TENANT_HMAC_SECRET: 'short',
        RESEND_API_KEY: 're_test',
        APP_BASE_URL: 'https://auth.idf.dev',
      })
    ).toThrow(/TENANT_HMAC_SECRET/);
  });
});
