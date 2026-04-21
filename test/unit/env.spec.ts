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

  it('декодирует \\n в JWT_*_PEM для one-line storage в .env/Fly secrets', () => {
    const env = loadEnv({
      DATABASE_URL: 'postgres://user:pass@localhost:5432/db',
      JWT_PRIVATE_KEY_PEM: '-----BEGIN PRIVATE KEY-----\\nLINE1\\nLINE2\\n-----END PRIVATE KEY-----\\n',
      JWT_PUBLIC_KEY_PEM: '-----BEGIN PUBLIC KEY-----\\nLINE1\\n-----END PUBLIC KEY-----\\n',
      TENANT_HMAC_SECRET: 'a'.repeat(32),
      RESEND_API_KEY: 'x',
      APP_BASE_URL: 'http://localhost:4000',
    });
    expect(env.JWT_PRIVATE_KEY_PEM).toContain('\n'); // real newline
    expect(env.JWT_PRIVATE_KEY_PEM).not.toContain('\\n'); // no literal backslash-n
    expect(env.JWT_PUBLIC_KEY_PEM.split('\n')).toHaveLength(4); // header + LINE1 + footer + trailing
  });

  it('raw multiline PEM не ломается (идемпотентность)', () => {
    const multilinePem = '-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----\n';
    const env = loadEnv({
      DATABASE_URL: 'postgres://user:pass@localhost:5432/db',
      JWT_PRIVATE_KEY_PEM: multilinePem,
      JWT_PUBLIC_KEY_PEM: multilinePem,
      TENANT_HMAC_SECRET: 'a'.repeat(32),
      RESEND_API_KEY: 'x',
      APP_BASE_URL: 'http://localhost:4000',
    });
    expect(env.JWT_PRIVATE_KEY_PEM).toBe(multilinePem);
  });
});
