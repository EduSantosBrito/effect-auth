import { PgClient } from "@effect/sql-pg";
import { Layer, Redacted } from "effect";
import { AuthLive } from "effect-auth";
import { DrizzlePg } from "effect-auth/storage/drizzle-pg";

export const auth = DrizzlePg.schema({ prefix: "auth_" });

export const PgLive = PgClient.layer({
  url: Redacted.make(process.env.DATABASE_URL ?? ""),
});

export const PostgresAuthStorage = DrizzlePg.layer({ schema: auth });

export const PostgresAuthLive = Layer.mergeAll(AuthLive.production, PostgresAuthStorage).pipe(
  Layer.provide(PgLive),
);
