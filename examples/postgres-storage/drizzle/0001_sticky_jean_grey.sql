CREATE TABLE "auth_oauth_states" (
	"id" text PRIMARY KEY NOT NULL,
	"state_hash" text NOT NULL,
	"provider_id" text NOT NULL,
	"flow" text NOT NULL,
	"redirect_uri" text NOT NULL,
	"scopes" text[] NOT NULL,
	"allow_sign_up" boolean NOT NULL,
	"link_user_id" text,
	"encrypted_code_verifier" text,
	"encrypted_nonce" text,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "auth_oauth_states" ADD CONSTRAINT "auth_oauth_states_link_user_id_auth_users_id_fk" FOREIGN KEY ("link_user_id") REFERENCES "public"."auth_users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "auth_oauth_states_state_hash_unique" ON "auth_oauth_states" USING btree ("state_hash");--> statement-breakpoint
CREATE INDEX "auth_oauth_states_provider_flow_idx" ON "auth_oauth_states" USING btree ("provider_id","flow");--> statement-breakpoint
CREATE INDEX "auth_oauth_states_expires_at_idx" ON "auth_oauth_states" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "auth_oauth_states_link_user_id_idx" ON "auth_oauth_states" USING btree ("link_user_id");