ALTER TABLE "auth_accounts" ADD COLUMN "provider_access_token" text;--> statement-breakpoint
ALTER TABLE "auth_accounts" ADD COLUMN "provider_refresh_token" text;--> statement-breakpoint
ALTER TABLE "auth_accounts" ADD COLUMN "provider_id_token" text;--> statement-breakpoint
ALTER TABLE "auth_accounts" ADD COLUMN "provider_token_type" text;--> statement-breakpoint
ALTER TABLE "auth_accounts" ADD COLUMN "provider_token_scope" text;--> statement-breakpoint
ALTER TABLE "auth_accounts" ADD COLUMN "provider_access_token_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "auth_accounts" ADD COLUMN "provider_refresh_token_expires_at" timestamp with time zone;