import { PgClient } from "@effect/sql-pg";
import { assert, it } from "@effect/vitest";
import { Config, ConfigProvider, Effect, Layer, Option, Predicate, Redacted, Schema } from "effect";
import * as SqlClient from "effect/unstable/sql/SqlClient";
import { OAuthProviderId, OAuthStateHash, ProtectedProviderToken } from "../src/oauth/index";
import { DrizzlePg } from "../src/storage/drizzle-pg/index";
import { AuthStorage } from "../src/storage/index";
import { NormalizedEmail } from "../src/domain/index";
import { PasswordHash } from "../src/password/index";
import { TokenHash } from "../src/token/index";

const auth = DrizzlePg.schema();

const decodeEmail = Schema.decodeUnknownEffect(NormalizedEmail);
const decodePasswordHash = Schema.decodeUnknownEffect(PasswordHash);
const decodeOAuthProviderId = Schema.decodeUnknownEffect(OAuthProviderId);
const decodeOAuthStateHash = Schema.decodeUnknownEffect(OAuthStateHash);
const decodeProtectedProviderToken = Schema.decodeUnknownEffect(ProtectedProviderToken);
const decodeTokenHash = Schema.decodeUnknownEffect(TokenHash);
const postgresUrl = Config.option(Config.string("EFFECT_AUTH_POSTGRES_URL")).parse(
  ConfigProvider.fromEnv(),
);

const live = (url: string) => {
  const PgLive = PgClient.layer({ url: Redacted.make(url) });
  return DrizzlePg.layer({ schema: auth }).pipe(Layer.provideMerge(PgLive));
};

const setupSchema = Effect.fn("setupSchema")(function* () {
  const sql = yield* SqlClient.SqlClient;
  yield* sql.unsafe(`
    DROP TABLE IF EXISTS auth_oauth_states;
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
      provider_access_token text,
      provider_refresh_token text,
      provider_id_token text,
      provider_token_type text,
      provider_token_scope text,
      provider_access_token_expires_at timestamptz,
      provider_refresh_token_expires_at timestamptz,
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
    CREATE TABLE auth_oauth_states (
      id text PRIMARY KEY,
      state_hash text NOT NULL UNIQUE,
      provider_id text NOT NULL,
      flow text NOT NULL,
      redirect_uri text NOT NULL,
      scopes text[] NOT NULL,
      allow_sign_up boolean NOT NULL,
      link_user_id text REFERENCES auth_users(id) ON DELETE CASCADE,
      encrypted_code_verifier text,
      encrypted_nonce text,
      created_at timestamptz NOT NULL,
      expires_at timestamptz NOT NULL,
      consumed_at timestamptz
    );
    CREATE INDEX auth_oauth_states_provider_flow_idx ON auth_oauth_states(provider_id, flow);
    CREATE INDEX auth_oauth_states_expires_at_idx ON auth_oauth_states(expires_at);
    CREATE INDEX auth_oauth_states_link_user_id_idx ON auth_oauth_states(link_user_id);
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

  const github = yield* decodeOAuthProviderId("github");
  const stateHash = yield* decodeOAuthStateHash("oauth-state-hash");
  const expiredStateHash = yield* decodeOAuthStateHash("expired-oauth-state-hash");
  const accessToken = yield* decodeProtectedProviderToken("protected-access-token-v1");
  const nextAccessToken = yield* decodeProtectedProviderToken("protected-access-token-v2");
  const refreshToken = yield* decodeProtectedProviderToken("protected-refresh-token-v1");
  const idToken = yield* decodeProtectedProviderToken("protected-id-token-v1");
  const oauthEmail = yield* decodeEmail("oauth-live@example.com");

  const storedState = yield* storage.storeOAuthState({
    stateHash,
    providerId: github,
    flow: "SignIn",
    redirectUri: new URL("https://app.example.com/callback/github"),
    scopes: ["read:user"],
    allowSignUp: true,
    encryptedCodeVerifier: "encrypted-code-verifier",
    encryptedNonce: "encrypted-nonce",
    expiresAt: activeUntil,
    now,
  });
  assert.strictEqual(storedState.encryptedCodeVerifier, "encrypted-code-verifier");
  const consumedState = yield* storage.consumeOAuthState({
    stateHash,
    providerId: github,
    flow: "SignIn",
    now,
  });
  assert.strictEqual(consumedState.consumedAt, now);
  const consumedStateAgain = yield* Effect.flip(
    storage.consumeOAuthState({ stateHash, providerId: github, flow: "SignIn", now }),
  );
  assert.strictEqual(consumedStateAgain.reason, "TokenConsumed");
  yield* storage.storeOAuthState({
    stateHash: expiredStateHash,
    providerId: github,
    flow: "SignIn",
    redirectUri: new URL("https://app.example.com/callback/github"),
    scopes: [],
    allowSignUp: true,
    expiresAt: now - 1,
    now: now - 2,
  });
  const expiredState = yield* Effect.flip(
    storage.consumeOAuthState({
      stateHash: expiredStateHash,
      providerId: github,
      flow: "SignIn",
      now,
    }),
  );
  assert.strictEqual(expiredState.reason, "TokenExpired");

  const firstOAuth = yield* storage.completeOAuthSignIn({
    providerId: github,
    providerAccountId: "github-user-1",
    email: oauthEmail,
    emailVerified: true,
    name: "OAuth Live",
    image: null,
    scopes: ["read:user"],
    providerTokens: {
      accessToken,
      refreshToken,
      idToken,
      tokenType: "Bearer",
      scope: "read:user",
      accessTokenExpiresAt: now + 3_600_000,
    },
    allowImplicitSignUp: true,
    allowAutomaticSameEmailLinking: false,
    now,
  });
  assert.strictEqual(firstOAuth.isNewUser, true);
  assert.strictEqual(firstOAuth.account.providerTokens.accessToken, accessToken);
  const tokenRows = yield* sql.unsafe<{
    readonly providerAccessToken: string | null;
    readonly providerRefreshToken: string | null;
  }>(
    `SELECT provider_access_token AS "providerAccessToken",
            provider_refresh_token AS "providerRefreshToken"
       FROM auth_accounts
       WHERE provider_id = $1 AND account_id = $2`,
    [github, "github-user-1"],
  );
  assert.strictEqual(tokenRows[0]?.providerAccessToken, accessToken);
  assert.strictEqual(tokenRows[0]?.providerRefreshToken, refreshToken);

  const returningOAuth = yield* storage.completeOAuthSignIn({
    providerId: github,
    providerAccountId: "github-user-1",
    email: oauthEmail,
    emailVerified: true,
    name: "OAuth Live",
    image: null,
    scopes: ["read:user", "repo"],
    providerTokens: {
      accessToken: nextAccessToken,
      scope: "read:user repo",
    },
    allowImplicitSignUp: true,
    allowAutomaticSameEmailLinking: false,
    now: now + 1,
  });
  assert.strictEqual(returningOAuth.isNewUser, false);
  assert.strictEqual(returningOAuth.user.id, firstOAuth.user.id);
  assert.strictEqual(returningOAuth.account.providerTokens.accessToken, nextAccessToken);
  assert.strictEqual(returningOAuth.account.providerTokens.refreshToken, refreshToken);
  const publicOAuthAccounts = yield* storage.listUserAccounts({ userId: firstOAuth.user.id });
  assert.strictEqual(Object.hasOwn(publicOAuthAccounts[0] ?? {}, "providerTokens"), false);

  const sameEmailDenied = yield* Effect.flip(
    storage.completeOAuthSignIn({
      providerId: github,
      providerAccountId: "github-same-email",
      email,
      emailVerified: true,
      name: "Linked User",
      image: null,
      scopes: ["read:user"],
      providerTokens: { accessToken },
      allowImplicitSignUp: true,
      allowAutomaticSameEmailLinking: false,
      now,
    }),
  );
  assert.strictEqual(sameEmailDenied.reason, "AutomaticLinkingNotAllowed");
  const sameEmailLinked = yield* storage.completeOAuthSignIn({
    providerId: github,
    providerAccountId: "github-same-email",
    email,
    emailVerified: true,
    name: "Linked User",
    image: null,
    scopes: ["read:user"],
    providerTokens: { accessToken },
    allowImplicitSignUp: true,
    allowAutomaticSameEmailLinking: true,
    now,
  });
  assert.strictEqual(sameEmailLinked.isNewUser, false);
  assert.strictEqual(sameEmailLinked.user.id, user.id);

  const linkMismatch = yield* Effect.flip(
    storage.completeOAuthLink({
      userId: user.id,
      providerId: github,
      providerAccountId: "github-link",
      providerEmail: oauthEmail,
      scopes: ["read:user"],
      providerTokens: { accessToken },
      allowDifferentEmail: false,
      now,
    }),
  );
  assert.strictEqual(linkMismatch.reason, "LinkEmailMismatch");
  const linked = yield* storage.completeOAuthLink({
    userId: user.id,
    providerId: github,
    providerAccountId: "github-link",
    providerEmail: email,
    scopes: ["read:user"],
    providerTokens: { accessToken },
    allowDifferentEmail: false,
    now,
  });
  assert.strictEqual(linked.user.id, user.id);
  assert.strictEqual(linked.account.providerTokens.accessToken, accessToken);
  const relinked = yield* storage.completeOAuthLink({
    userId: user.id,
    providerId: github,
    providerAccountId: "github-link",
    providerEmail: email,
    scopes: ["read:user", "repo"],
    providerTokens: { accessToken: nextAccessToken },
    allowDifferentEmail: false,
    now: now + 1,
  });
  assert.strictEqual(relinked.account.providerTokens.accessToken, nextAccessToken);

  yield* storage.deleteUser({ userId: user.id });
  yield* storage.deleteUser({ userId: firstOAuth.user.id });
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
