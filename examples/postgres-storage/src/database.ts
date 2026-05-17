import { PgClient } from "@effect/sql-pg";
import { Layer, Redacted } from "effect";
import { DrizzlePg } from "effect-auth/storage/drizzle-pg";
import { authSchema } from "./schema.js";

export const makePostgresLive = (databaseUrl: string) => {
  const PgLive = PgClient.layer({ url: Redacted.make(databaseUrl) });
  const PostgresAuthStorage = DrizzlePg.layer({ schema: authSchema }).pipe(Layer.provide(PgLive));
  return Layer.merge(PgLive, PostgresAuthStorage);
};
