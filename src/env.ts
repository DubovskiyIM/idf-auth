import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().min(1),
  JWT_PRIVATE_KEY_PEM: z.string().min(1).transform(s => s.replace(/\\n/g, '\n')),
  JWT_PUBLIC_KEY_PEM: z.string().min(1).transform(s => s.replace(/\\n/g, '\n')),
  TENANT_HMAC_SECRET: z.string().min(32),
  RESEND_API_KEY: z.string().min(1),
  APP_BASE_URL: z.string().url(),
  PORT: z.coerce.number().default(4000),
  MAGIC_LINK_TTL_MINUTES: z.coerce.number().default(15),
  JWT_TTL_DAYS: z.coerce.number().default(30),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  // z.coerce.boolean трактует любую непустую строку как true (Boolean("false") === true),
  // поэтому парсим "true"/"false" явно — иначе EMAIL_DEV_MODE=false остаётся dev-режимом.
  EMAIL_DEV_MODE: z
    .union([z.boolean(), z.enum(['true', 'false', '0', '1']).transform((v) => v === 'true' || v === '1')])
    .default(false),
  /**
   * Адрес отправителя для Resend. Должен быть на домене, который верифицирован
   * в Resend (SPF + DKIM records в DNS), иначе send вернёт 403/422.
   * Формат RFC 5322: "Name <email@domain>".
   */
  EMAIL_FROM: z.string().default('IDF <no-reply@intent-design.tech>'),
});

export type Env = z.infer<typeof schema>;

export function loadEnv(raw: Record<string, string | undefined> = process.env): Env {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) {
    const msg = parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid env: ${msg}`);
  }
  return parsed.data;
}
