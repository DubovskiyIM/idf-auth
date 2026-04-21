import { pgTable, uuid, text, timestamp, boolean, index, uniqueIndex, integer, bigint } from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';

export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: text('email').notNull(),
    createdAt: timestamp('created_at').notNull().defaultNow(),
    lastActiveAt: timestamp('last_active_at'),
  },
  (t) => ({
    emailIdx: uniqueIndex('users_email_lower_idx').on(sql`lower(${t.email})`),
  })
);

export const memberships = pgTable(
  'memberships',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    domainSlug: text('domain_slug').notNull(),
    role: text('role').notNull(),
    revoked: boolean('revoked').notNull().default(false),
    revokedAt: timestamp('revoked_at'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (t) => ({
    userDomainIdx: uniqueIndex('memberships_user_domain_idx').on(t.userId, t.domainSlug),
    slugIdx: index('memberships_slug_idx').on(t.domainSlug),
    revokedAtIdx: index('memberships_revoked_at_idx').on(t.revokedAt),
  })
);

export const magicLinks = pgTable(
  'magic_links',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    nonceHash: text('nonce_hash').notNull(),
    email: text('email').notNull(),
    domainSlug: text('domain_slug'),
    expiresAt: timestamp('expires_at').notNull(),
    usedAt: timestamp('used_at'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (t) => ({
    nonceIdx: uniqueIndex('magic_links_nonce_hash_idx').on(t.nonceHash),
    expiresIdx: index('magic_links_expires_idx').on(t.expiresAt),
  })
);

export const invites = pgTable(
  'invites',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    nonceHash: text('nonce_hash').notNull(),
    email: text('email').notNull(),
    domainSlug: text('domain_slug').notNull(),
    role: text('role').notNull(),
    inviterUserId: uuid('inviter_user_id'),
    expiresAt: timestamp('expires_at').notNull(),
    acceptedAt: timestamp('accepted_at'),
    revokedAt: timestamp('revoked_at'),
    createdAt: timestamp('created_at').notNull().defaultNow(),
  },
  (t) => ({
    nonceIdx: uniqueIndex('invites_nonce_hash_idx').on(t.nonceHash),
    domainIdx: index('invites_domain_idx').on(t.domainSlug),
  })
);

export const rateLimitLog = pgTable(
  'rate_limit_log',
  {
    key: text('key').primaryKey(),
    points: integer('points').notNull().default(0),
    expire: bigint('expire', { mode: 'number' }),
  }
);
