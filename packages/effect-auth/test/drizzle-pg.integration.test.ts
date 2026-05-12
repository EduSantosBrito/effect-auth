import { PgClient } from "@effect/sql-pg";
import { assert, it } from "@effect/vitest";
import { Config, ConfigProvider, Effect, Layer, Option, Predicate, Redacted, Schema } from "effect";
import * as SqlClient from "effect/unstable/sql/SqlClient";
import { DrizzlePg } from "../src/storage/drizzle-pg/index";
import { AuthStorage } from "../src/storage/index";
import { NormalizedEmail } from "../src/domain/index";
import { PasswordHash } from "../src/password/index";
import { TokenHash } from "../src/token/index";

const auth = DrizzlePg.schema();

const decodeEmail = Schema.decodeUnknownEffect(NormalizedEmail);
const decodePasswordHash = Schema.decodeUnknownEffect(PasswordHash);
const decodeTokenHash = Schema.decodeUnknownEffect(TokenHash);
const postgresUrl = Config.option(Config.string("EFFECT_AUTH_POSTGRES_URL")).parse(
  ConfigProvider.fromEnv(),
);

const live = (url: string) => {
  const PgLive = PgClient.layer({ url: Redacted.make(url) });
  return Layer.merge(PgLive, DrizzlePg.layer({ schema: auth }).pipe(Layer.provide(PgLive)));
};

const setupSchema = Effect.fn("setupSchema")(function* () {
  const sql = yield* SqlClient.SqlClient;
  yield* sql.unsafe(`
    DROP TABLE IF EXISTS auth_verifications;
    DROP TABLE IF EXISTS auth_sessions;
    DROP TABLE IF EXISTS auth_accounts;
    DROP TABLE IF EXISTS auth_users;
    CREATE TABLE auth_users (
      id text PRIMARY KEY,
      email text NOT NULL UNIQUE,
      name text NOT NULL,
      image text,
      email_verified boolean NOT NULL,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL
    );
    CREATE TABLE auth_accounts (
      id text PRIMARY KEY,
      provider_id text NOT NULL,
      account_id text NOT NULL,
      user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      scopes text[] NOT NULL,
      password_hash text,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL,
      UNIQUE (provider_id, account_id)
    );
    CREATE INDEX auth_accounts_user_id_idx ON auth_accounts(user_id);
    CREATE TABLE auth_sessions (
      id text PRIMARY KEY,
      user_id text NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
      token_hash text NOT NULL UNIQUE,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      revoked_at timestamptz,
      ip_address text,
      user_agent text
    );
    CREATE INDEX auth_sessions_user_id_idx ON auth_sessions(user_id);
    CREATE TABLE auth_verifications (
      id text PRIMARY KEY,
      identifier text NOT NULL UNIQUE,
      value text NOT NULL,
      purpose text NOT NULL,
      consumed_at timestamptz,
      expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL,
      updated_at timestamptz NOT NULL
    );
    CREATE INDEX auth_verifications_value_purpose_idx ON auth_verifications(value, purpose);
  `);
});

const countRows = Effect.fn("countRows")(function* (table: string) {
  const sql = yield* SqlClient.SqlClient;
  const rows = yield* sql.unsafe<{ readonly count: string }>(
    `SELECT count(*)::text AS count FROM ${table}`,
  );
  return Number(rows[0]?.count ?? "0");
});

const storageInvariants = Effect.gen(function* () {
  yield* setupSchema();
  const storage = yield* AuthStorage;
  const sql = yield* SqlClient.SqlClient;
  const email = yield* decodeEmail("live@example.com");
  const passwordHash = yield* decodePasswordHash("hash:old");
  const changedHash = yield* decodePasswordHash("hash:changed");
  const resetHash = yield* decodePasswordHash("hash:reset");
  const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
  const activeUntil = now + 60_000;
  const tokenA = yield* decodeTokenHash("session-a");
  const tokenB = yield* decodeTokenHash("session-b");
  const tokenC = yield* decodeTokenHash("session-c");
  const tokenD = yield* decodeTokenHash("session-d");
  const tokenE = yield* decodeTokenHash("session-e");
  const tokenF = yield* decodeTokenHash("session-f");
  const verifyToken = yield* decodeTokenHash("verify-token");
  const resetToken = yield* decodeTokenHash("reset-token");

  const user = yield* storage.createUserWithCredentialAccount({
    email,
    name: "Live User",
    image: null,
    passwordHash,
    now,
  });
  assert.strictEqual(user.createdAt, now);

  const duplicate = yield* Effect.flip(
    storage.createUserWithCredentialAccount({
      email,
      name: "Duplicate",
      image: null,
      passwordHash,
      now,
    }),
  );
  assert.strictEqual(duplicate.reason, "Conflict");

  const first = yield* storage.createSession({
    userId: user.id,
    tokenHash: tokenA,
    expiresAt: activeUntil,
    now,
  });
  const second = yield* storage.createSession({
    userId: user.id,
    tokenHash: tokenB,
    expiresAt: activeUntil,
    now: now + 1,
  });
  const listed = yield* storage.listUserSessions({ userId: user.id, now });
  assert.deepStrictEqual(
    listed.map((session) => session.id),
    [second.id, first.id],
  );

  const expired = yield* storage.createSession({
    userId: user.id,
    tokenHash: tokenC,
    expiresAt: now - 1,
    now: now - 2,
  });
  const expiredRotation = yield* Effect.flip(
    storage.rotateSessionToken({
      previousHash: expired.tokenHash,
      nextHash: tokenD,
      expiresAt: activeUntil,
      now,
    }),
  );
  assert.strictEqual(expiredRotation.reason, "NotFound");

  const rotationResults = yield* Effect.all(
    [
      Effect.exit(
        storage.rotateSessionToken({
          previousHash: first.tokenHash,
          nextHash: tokenD,
          expiresAt: activeUntil,
          now: now + 2,
        }),
      ),
      Effect.exit(
        storage.rotateSessionToken({
          previousHash: first.tokenHash,
          nextHash: tokenE,
          expiresAt: activeUntil,
          now: now + 2,
        }),
      ),
    ],
    { concurrency: "unbounded" },
  );
  assert.strictEqual(
    rotationResults.filter((exit) => Predicate.isTagged(exit, "Success")).length,
    1,
  );
  assert.strictEqual(
    rotationResults.filter((exit) => Predicate.isTagged(exit, "Failure")).length,
    1,
  );

  yield* storage.storeVerificationToken({
    userId: user.id,
    email,
    purpose: "EmailVerification",
    tokenHash: verifyToken,
    expiresAt: activeUntil,
    now,
  });
  const consumed = yield* storage.consumeVerificationToken({
    purpose: "EmailVerification",
    tokenHash: verifyToken,
    now,
  });
  assert.strictEqual(consumed.user.emailVerified, true);
  const consumedAgain = yield* Effect.flip(
    storage.consumeVerificationToken({ purpose: "EmailVerification", tokenHash: verifyToken, now }),
  );
  assert.strictEqual(consumedAgain.reason, "TokenConsumed");

  yield* storage.storeVerificationToken({
    userId: user.id,
    email,
    purpose: "PasswordReset",
    tokenHash: resetToken,
    expiresAt: activeUntil,
    now,
  });
  yield* storage.createSession({
    userId: user.id,
    tokenHash: tokenF,
    expiresAt: activeUntil,
    now: now + 3,
  });
  const rollback = yield* Effect.flip(
    storage.changePasswordSession({
      password: { userId: user.id, passwordHash: changedHash, now: now + 4 },
      currentSessionId: second.id,
      previousSessionTokenHash: second.tokenHash,
      nextSessionTokenHash: tokenF,
      sessionExpiresAt: activeUntil,
    }),
  );
  assert.strictEqual(rollback.reason, "Conflict");
  const afterRollback = yield* sql.unsafe<{
    readonly passwordHash: string | null;
    readonly revokedCount: string;
  }>(
    `SELECT a.password_hash AS "passwordHash",
              (SELECT count(*)::text FROM auth_sessions WHERE user_id = $1 AND revoked_at IS NOT NULL) AS "revokedCount"
       FROM auth_accounts a
       WHERE a.user_id = $1`,
    [user.id],
  );
  assert.strictEqual(afterRollback[0]?.passwordHash, Redacted.value(passwordHash));
  assert.strictEqual(afterRollback[0]?.revokedCount, "0");

  yield* storage.completePasswordReset({
    token: { purpose: "PasswordReset", tokenHash: resetToken, now: now + 5 },
    passwordHash: resetHash,
  });
  const resetRows = yield* sql.unsafe<{ readonly passwordHash: string | null }>(
    `SELECT password_hash AS "passwordHash" FROM auth_accounts WHERE user_id = $1`,
    [user.id],
  );
  assert.strictEqual(resetRows[0]?.passwordHash, Redacted.value(resetHash));
  assert.strictEqual(yield* countRows("auth_sessions WHERE revoked_at IS NOT NULL"), 4);

  yield* storage.deleteUser({ userId: user.id });
  assert.strictEqual(yield* countRows("auth_users"), 0);
  assert.strictEqual(yield* countRows("auth_accounts"), 0);
  assert.strictEqual(yield* countRows("auth_sessions"), 0);
  assert.strictEqual(yield* countRows("auth_verifications"), 0);
});

it.effect(
  "DrizzlePg storage satisfies live Postgres storage invariants",
  () =>
    postgresUrl.pipe(
      Effect.flatMap(
        Option.match({
          onNone: () => Effect.void,
          onSome: (url) => storageInvariants.pipe(Effect.provide(live(url))),
        }),
      ),
    ),
  30_000,
);
