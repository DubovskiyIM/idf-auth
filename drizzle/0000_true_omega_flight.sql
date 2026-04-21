CREATE TABLE "invites" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"nonce_hash" text NOT NULL,
	"email" text NOT NULL,
	"domain_slug" text NOT NULL,
	"role" text NOT NULL,
	"inviter_user_id" uuid,
	"expires_at" timestamp NOT NULL,
	"accepted_at" timestamp,
	"revoked_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "magic_links" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"nonce_hash" text NOT NULL,
	"email" text NOT NULL,
	"domain_slug" text,
	"expires_at" timestamp NOT NULL,
	"used_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "memberships" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"domain_slug" text NOT NULL,
	"role" text NOT NULL,
	"revoked" boolean DEFAULT false NOT NULL,
	"revoked_at" timestamp,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rate_limit_log" (
	"key" text PRIMARY KEY NOT NULL,
	"points" integer DEFAULT 0 NOT NULL,
	"expire" bigint
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"last_active_at" timestamp
);
--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "invites_nonce_hash_idx" ON "invites" USING btree ("nonce_hash");--> statement-breakpoint
CREATE INDEX "invites_domain_idx" ON "invites" USING btree ("domain_slug");--> statement-breakpoint
CREATE UNIQUE INDEX "magic_links_nonce_hash_idx" ON "magic_links" USING btree ("nonce_hash");--> statement-breakpoint
CREATE INDEX "magic_links_expires_idx" ON "magic_links" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "memberships_user_domain_idx" ON "memberships" USING btree ("user_id","domain_slug");--> statement-breakpoint
CREATE INDEX "memberships_slug_idx" ON "memberships" USING btree ("domain_slug");--> statement-breakpoint
CREATE INDEX "memberships_revoked_at_idx" ON "memberships" USING btree ("revoked_at");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_lower_idx" ON "users" USING btree (lower("email"));