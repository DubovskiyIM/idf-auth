import { z } from 'zod';

const schema = z.object({
  DATABASE_URL: z.string().min(1),
  JWT_PRIVATE_KEY_PEM: z.string().min(1),
  JWT_PUBLIC_KEY_PEM: z.string().min(1),
  TENANT_HMAC_SECRET: z.string().min(32),
  RESEND_API_KEY: z.string().min(1),
  APP_BASE_URL: z.string().url(),
  PORT: z.coerce.number().default(4000),
  MAGIC_LINK_TTL_MINUTES: z.coerce.number().default(15),
  JWT_TTL_DAYS: z.coerce.number().default(30),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  EMAIL_DEV_MODE: z.coerce.boolean().default(false),
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
