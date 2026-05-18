import { Clock, Effect, Layer, Predicate, Random, Redacted, Schema } from "effect";
import * as SqlClient from "effect/unstable/sql/SqlClient";
import type { SqlError } from "effect/unstable/sql/SqlError";
import { getTableName } from "drizzle-orm";
import { boolean, index, pgTable, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";
import { NormalizedEmail } from "../../domain/index.js";
import {
  ProtectedProviderToken,
  type OAuthProviderId,
  type OAuthStateHash,
  type ProtectedProviderTokenSet,
  type StoredOAuthState,
} from "../../oauth/index.js";
import type { PasswordHash } from "../../password/index.js";
import type { TokenHash } from "../../token/index.js";
import {
  AuthStorage,
  AuthStorageFailure,
  OAuthAccountStorageFailure,
  type CredentialAuthAccount,
  type AuthStorageShape,
  type AuthUser,
  type PublicAuthAccount,
  type StoredSession,
} from "../index.js";

export interface SchemaOptions {
  readonly prefix?: string;
}

export type AuthDrizzlePgSchema = ReturnType<typeof schema>;

export interface LayerOptions<S extends AuthDrizzlePgSchema = AuthDrizzlePgSchema> {
  readonly schema: S;
}

const defaultPrefix = "auth_";
const identifierPattern = /^[A-Za-z_][A-Za-z0-9_]*$/u;

const prefixedTableNames = (options: SchemaOptions = {}) => {
  const prefix = options.prefix ?? defaultPrefix;
  const safePrefix = identifierPattern.test(`${prefix}users`) ? prefix : defaultPrefix;
  return {
    Users: `${safePrefix}users`,
    Accounts: `${safePrefix}accounts`,
    Sessions: `${safePrefix}sessions`,
    Verifications: `${safePrefix}verifications`,
    OAuthStates: `${safePrefix}oauth_states`,
  };
};

const tableNames = (schema: AuthDrizzlePgSchema) => ({
  Users: getTableName(schema.Users),
  Accounts: getTableName(schema.Accounts),
  Sessions: getTableName(schema.Sessions),
  Verifications: getTableName(schema.Verifications),
  OAuthStates: getTableName(schema.OAuthStates),
});

export const schema = (options: SchemaOptions = {}) => {
  const tables = prefixedTableNames(options);
  const Users = pgTable(
    tables.Users,
    {
      id: text("id").primaryKey(),
      email: text("email").notNull(),
      name: text("name").notNull(),
      image: text("image"),
      emailVerified: boolean("email_verified").notNull(),
      createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
      updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
    },
    (table) => [uniqueIndex(`${tables.Users}_email_unique`).on(table.email)],
  );
  const Accounts = pgTable(
    tables.Accounts,
    {
      id: text("id").primaryKey(),
      providerId: text("provider_id").notNull(),
      accountId: text("account_id").notNull(),
      userId: text("user_id")
        .notNull()
        .references(() => Users.id, { onDelete: "cascade" }),
      scopes: text("scopes").array().notNull(),
      passwordHash: text("password_hash"),
      providerAccessToken: text("provider_access_token"),
      providerRefreshToken: text("provider_refresh_token"),
      providerIdToken: text("provider_id_token"),
      providerTokenType: text("provider_token_type"),
      providerTokenScope: text("provider_token_scope"),
      providerAccessTokenExpiresAt: timestamp("provider_access_token_expires_at", {
        withTimezone: true,
      }),
      providerRefreshTokenExpiresAt: timestamp("provider_refresh_token_expires_at", {
        withTimezone: true,
      }),
      createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
      updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
    },
    (table) => [
      uniqueIndex(`${tables.Accounts}_provider_account_unique`).on(
        table.providerId,
        table.accountId,
      ),
      index(`${tables.Accounts}_user_id_idx`).on(table.userId),
    ],
  );
  const Sessions = pgTable(
    tables.Sessions,
    {
      id: text("id").primaryKey(),
      userId: text("user_id")
        .notNull()
        .references(() => Users.id, { onDelete: "cascade" }),
      tokenHash: text("token_hash").notNull(),
      createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
      updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
      expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
      revokedAt: timestamp("revoked_at", { withTimezone: true }),
      ipAddress: text("ip_address"),
      userAgent: text("user_agent"),
    },
    (table) => [
      uniqueIndex(`${tables.Sessions}_token_hash_unique`).on(table.tokenHash),
      index(`${tables.Sessions}_user_id_idx`).on(table.userId),
    ],
  );
  const Verifications = pgTable(
    tables.Verifications,
    {
      id: text("id").primaryKey(),
      identifier: text("identifier").notNull(),
      value: text("value").notNull(),
      purpose: text("purpose").notNull(),
      consumedAt: timestamp("consumed_at", { withTimezone: true }),
      expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
      createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
      updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
    },
    (table) => [
      uniqueIndex(`${tables.Verifications}_identifier_unique`).on(table.identifier),
      index(`${tables.Verifications}_value_purpose_idx`).on(table.value, table.purpose),
    ],
  );
  const OAuthStates = pgTable(
    tables.OAuthStates,
    {
      id: text("id").primaryKey(),
      stateHash: text("state_hash").notNull(),
      providerId: text("provider_id").notNull(),
      flow: text("flow").notNull(),
      redirectUri: text("redirect_uri").notNull(),
      scopes: text("scopes").array().notNull(),
      allowSignUp: boolean("allow_sign_up").notNull(),
      linkUserId: text("link_user_id").references(() => Users.id, { onDelete: "cascade" }),
      encryptedCodeVerifier: text("encrypted_code_verifier"),
      encryptedNonce: text("encrypted_nonce"),
      createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
      expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
      consumedAt: timestamp("consumed_at", { withTimezone: true }),
    },
    (table) => [
      uniqueIndex(`${tables.OAuthStates}_state_hash_unique`).on(table.stateHash),
      index(`${tables.OAuthStates}_provider_flow_idx`).on(table.providerId, table.flow),
      index(`${tables.OAuthStates}_expires_at_idx`).on(table.expiresAt),
      index(`${tables.OAuthStates}_link_user_id_idx`).on(table.linkUserId),
    ],
  );
  return { Users, Accounts, Sessions, Verifications, OAuthStates };
};

type UserRow = {
  readonly id: string;
  readonly email: string;
  readonly name: string;
  readonly image: string | null;
  readonly emailVerified: boolean;
  readonly createdAt: number;
  readonly updatedAt: number;
};

type AccountRow = {
  readonly id: string;
  readonly providerId: "credential" | OAuthProviderId;
  readonly accountId: string;
  readonly userId: string;
  readonly scopes: ReadonlyArray<string>;
  readonly passwordHash: string | null;
  readonly providerAccessToken: string | null;
  readonly providerRefreshToken: string | null;
  readonly providerIdToken: string | null;
  readonly providerTokenType: string | null;
  readonly providerTokenScope: string | null;
  readonly providerAccessTokenExpiresAt: number | null;
  readonly providerRefreshTokenExpiresAt: number | null;
  readonly createdAt: number;
  readonly updatedAt: number;
};

type SessionRow = {
  readonly id: string;
  readonly userId: string;
  readonly tokenHash: string;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly expiresAt: number;
  readonly revokedAt: number | null;
  readonly ipAddress: string | null;
  readonly userAgent: string | null;
};

type OAuthStateRow = {
  readonly id: string;
  readonly stateHash: string;
  readonly providerId: OAuthProviderId;
  readonly flow: "SignIn" | "Link";
  readonly redirectUri: string;
  readonly scopes: ReadonlyArray<string>;
  readonly allowSignUp: boolean;
  readonly linkUserId: string | null;
  readonly encryptedCodeVerifier: string | null;
  readonly encryptedNonce: string | null;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly consumedAt: number | null;
};

type CredentialJoinRow = {
  readonly userId: string;
  readonly userEmail: string;
  readonly userName: string;
  readonly userImage: string | null;
  readonly userEmailVerified: boolean;
  readonly userCreatedAt: number;
  readonly userUpdatedAt: number;
  readonly accountId: string;
  readonly accountProviderId: "credential";
  readonly accountAccountId: string;
  readonly accountUserId: string;
  readonly accountScopes: ReadonlyArray<string>;
  readonly accountPasswordHash: string;
  readonly accountCreatedAt: number;
  readonly accountUpdatedAt: number;
};

type SessionJoinRow = SessionRow & {
  readonly userRecordId: string;
  readonly userEmail: string;
  readonly userName: string;
  readonly userImage: string | null;
  readonly userEmailVerified: boolean;
  readonly userCreatedAt: number;
  readonly userUpdatedAt: number;
};

const tokenKey = (hash: TokenHash) => Redacted.value(hash);
const oauthStateKey = (hash: OAuthStateHash) => Redacted.value(hash);
const passwordHash = (hash: PasswordHash) => Redacted.value(hash);
const millis = (column: string) => `(extract(epoch from ${column}) * 1000)::double precision`;
const notFound = new AuthStorageFailure({ reason: "NotFound" });
const backendUnavailable = new AuthStorageFailure({ reason: "BackendUnavailable" });

const sqlFailure = (error: SqlError) =>
  Predicate.isTagged(error.reason, "ConstraintError")
    ? new AuthStorageFailure({ reason: "Conflict" })
    : backendUnavailable;

const storageFailure = (error: SqlError | AuthStorageFailure): AuthStorageFailure =>
  Predicate.isTagged(error, "AuthStorageFailure") ? error : sqlFailure(error);
const oauthAccountStorageFailure = (
  error: SqlError | AuthStorageFailure | OAuthAccountStorageFailure,
) => (Predicate.isTagged(error, "OAuthAccountStorageFailure") ? error : storageFailure(error));
const decodeNormalizedEmail = Schema.decodeSync(NormalizedEmail);
const decodeProtectedProviderToken = Schema.decodeUnknownEffect(ProtectedProviderToken);

const one = <A>(rows: ReadonlyArray<A>): Effect.Effect<A, AuthStorageFailure> => {
  const row = rows[0];
  return row === undefined ? Effect.fail(notFound) : Effect.succeed(row);
};

const verificationTokenFailure = Effect.fn("DrizzlePg.verificationTokenFailure")(function* (
  sql: SqlClient.SqlClient,
  tables: ReturnType<typeof prefixedTableNames>,
  tokenHash: TokenHash,
  purpose: string,
  now: number,
) {
  const row = yield* sql
    .unsafe<{
      readonly consumedAt: number | null;
      readonly expiresAt: number;
    }>(
      `SELECT ${millis("consumed_at")} AS "consumedAt", ${millis("expires_at")} AS "expiresAt"
     FROM ${tables.Verifications}
     WHERE identifier = $1 AND purpose = $2
     LIMIT 1`,
      [tokenKey(tokenHash), purpose],
    )
    .pipe(Effect.flatMap(one), Effect.mapError(storageFailure));
  if (row.consumedAt !== null) return yield* new AuthStorageFailure({ reason: "TokenConsumed" });
  if (row.expiresAt <= now) return yield* new AuthStorageFailure({ reason: "TokenExpired" });
  return yield* notFound;
});

const oauthStateFailure = Effect.fn("DrizzlePg.oauthStateFailure")(function* (
  sql: SqlClient.SqlClient,
  tables: ReturnType<typeof prefixedTableNames>,
  stateHash: OAuthStateHash,
  providerId: OAuthProviderId,
  flow: "SignIn" | "Link",
  now: number,
) {
  const row = yield* sql
    .unsafe<{
      readonly consumedAt: number | null;
      readonly expiresAt: number;
    }>(
      `SELECT ${millis("consumed_at")} AS "consumedAt", ${millis("expires_at")} AS "expiresAt"
     FROM ${tables.OAuthStates}
     WHERE state_hash = $1 AND provider_id = $2 AND flow = $3
     LIMIT 1`,
      [oauthStateKey(stateHash), providerId, flow],
    )
    .pipe(Effect.flatMap(one), Effect.mapError(storageFailure));
  if (row.consumedAt !== null) return yield* new AuthStorageFailure({ reason: "TokenConsumed" });
  if (row.expiresAt <= now) return yield* new AuthStorageFailure({ reason: "TokenExpired" });
  return yield* notFound;
});

const makeFindSessionByTokenHash = (
  sql: SqlClient.SqlClient,
  tables: ReturnType<typeof prefixedTableNames>,
): AuthStorageShape["findSessionByTokenHash"] =>
  Effect.fn("DrizzlePg.findSessionByTokenHash")(function* (hash) {
    const now = yield* Clock.currentTimeMillis;
    const row = yield* sql
      .unsafe<SessionJoinRow>(
        `SELECT ${sessionJoinSelect}
       FROM ${tables.Sessions} s
       JOIN ${tables.Users} u ON u.id = s.user_id
       WHERE s.token_hash = $1
       LIMIT 1`,
        [tokenKey(hash)],
      )
      .pipe(Effect.flatMap(one), Effect.mapError(storageFailure));
    if (row.revokedAt !== null) return yield* notFound;
    if (row.expiresAt <= now) return yield* new AuthStorageFailure({ reason: "SessionExpired" });
    return { session: toSession(row), user: joinedSessionUser(row) };
  });

const toUser = (row: UserRow): AuthUser => ({
  id: row.id,
  email: decodeNormalizedEmail(row.email),
  name: row.name,
  image: row.image,
  emailVerified: row.emailVerified,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
});

const toPublicAccount = (row: AccountRow): PublicAuthAccount => ({
  id: row.id,
  providerId: row.providerId,
  accountId: row.accountId,
  userId: row.userId,
  scopes: row.scopes,
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
});

const optionalProtectedProviderToken = (
  value: string | null,
): Effect.Effect<ProtectedProviderToken | undefined, AuthStorageFailure> =>
  value === null
    ? Effect.sync((): ProtectedProviderToken | undefined => undefined)
    : decodeProtectedProviderToken(value).pipe(Effect.mapError(() => backendUnavailable));

const toProviderTokens = Effect.fn("DrizzlePg.toProviderTokens")(function* (row: AccountRow) {
  const accessToken = yield* optionalProtectedProviderToken(row.providerAccessToken);
  const refreshToken = yield* optionalProtectedProviderToken(row.providerRefreshToken);
  const idToken = yield* optionalProtectedProviderToken(row.providerIdToken);
  return {
    ...(accessToken === undefined ? {} : { accessToken }),
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(idToken === undefined ? {} : { idToken }),
    ...(row.providerTokenType === null ? {} : { tokenType: row.providerTokenType }),
    ...(row.providerTokenScope === null ? {} : { scope: row.providerTokenScope }),
    ...(row.providerAccessTokenExpiresAt === null
      ? {}
      : { accessTokenExpiresAt: row.providerAccessTokenExpiresAt }),
    ...(row.providerRefreshTokenExpiresAt === null
      ? {}
      : { refreshTokenExpiresAt: row.providerRefreshTokenExpiresAt }),
  } satisfies ProtectedProviderTokenSet;
});

const toOAuthProviderAccount = Effect.fn("DrizzlePg.toOAuthProviderAccount")(function* (
  row: AccountRow,
) {
  if (row.providerId === "credential") return yield* backendUnavailable;
  const providerTokens = yield* toProviderTokens(row);
  return {
    id: row.id,
    providerId: row.providerId,
    accountId: row.accountId,
    userId: row.userId,
    scopes: row.scopes,
    providerTokens,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
});

const joinedCredentialUser = (row: CredentialJoinRow): AuthUser => ({
  id: row.userId,
  email: decodeNormalizedEmail(row.userEmail),
  name: row.userName,
  image: row.userImage,
  emailVerified: row.userEmailVerified,
  createdAt: row.userCreatedAt,
  updatedAt: row.userUpdatedAt,
});

const joinedSessionUser = (row: SessionJoinRow): AuthUser => ({
  id: row.userRecordId,
  email: decodeNormalizedEmail(row.userEmail),
  name: row.userName,
  image: row.userImage,
  emailVerified: row.userEmailVerified,
  createdAt: row.userCreatedAt,
  updatedAt: row.userUpdatedAt,
});

const joinedAccount = (row: CredentialJoinRow): CredentialAuthAccount => ({
  id: row.accountId,
  providerId: row.accountProviderId,
  accountId: row.accountAccountId,
  userId: row.accountUserId,
  scopes: row.accountScopes,
  passwordHash: Redacted.make(row.accountPasswordHash),
  createdAt: row.accountCreatedAt,
  updatedAt: row.accountUpdatedAt,
});

const toSession = (row: SessionRow): StoredSession => ({
  id: row.id,
  userId: row.userId,
  tokenHash: Redacted.make(row.tokenHash),
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
  expiresAt: row.expiresAt,
  ...(row.revokedAt === null ? {} : { revokedAt: row.revokedAt }),
  ...(row.ipAddress === null ? {} : { ipAddress: row.ipAddress }),
  ...(row.userAgent === null ? {} : { userAgent: row.userAgent }),
});

const toOAuthState = (row: OAuthStateRow): StoredOAuthState => ({
  id: row.id,
  stateHash: Redacted.make(row.stateHash),
  providerId: row.providerId,
  flow: row.flow,
  redirectUri: new URL(row.redirectUri),
  scopes: row.scopes,
  allowSignUp: row.allowSignUp,
  ...(row.linkUserId === null ? {} : { linkUserId: row.linkUserId }),
  ...(row.encryptedCodeVerifier === null
    ? {}
    : { encryptedCodeVerifier: row.encryptedCodeVerifier }),
  ...(row.encryptedNonce === null ? {} : { encryptedNonce: row.encryptedNonce }),
  createdAt: row.createdAt,
  expiresAt: row.expiresAt,
  ...(row.consumedAt === null ? {} : { consumedAt: row.consumedAt }),
});

const userSelect = (alias: string) => `
  ${alias}.id AS "id",
  ${alias}.email AS "email",
  ${alias}.name AS "name",
  ${alias}.image AS "image",
  ${alias}.email_verified AS "emailVerified",
  ${millis(`${alias}.created_at`)} AS "createdAt",
  ${millis(`${alias}.updated_at`)} AS "updatedAt"
`;

const accountSelect = (alias: string) => `
  ${alias}.id AS "id",
  ${alias}.provider_id AS "providerId",
  ${alias}.account_id AS "accountId",
  ${alias}.user_id AS "userId",
  ${alias}.scopes AS "scopes",
  ${alias}.password_hash AS "passwordHash",
  ${alias}.provider_access_token AS "providerAccessToken",
  ${alias}.provider_refresh_token AS "providerRefreshToken",
  ${alias}.provider_id_token AS "providerIdToken",
  ${alias}.provider_token_type AS "providerTokenType",
  ${alias}.provider_token_scope AS "providerTokenScope",
  ${millis(`${alias}.provider_access_token_expires_at`)} AS "providerAccessTokenExpiresAt",
  ${millis(`${alias}.provider_refresh_token_expires_at`)} AS "providerRefreshTokenExpiresAt",
  ${millis(`${alias}.created_at`)} AS "createdAt",
  ${millis(`${alias}.updated_at`)} AS "updatedAt"
`;

const sessionSelect = (alias: string) => `
  ${alias}.id AS "id",
  ${alias}.user_id AS "userId",
  ${alias}.token_hash AS "tokenHash",
  ${millis(`${alias}.created_at`)} AS "createdAt",
  ${millis(`${alias}.updated_at`)} AS "updatedAt",
  ${millis(`${alias}.expires_at`)} AS "expiresAt",
  ${millis(`${alias}.revoked_at`)} AS "revokedAt",
  ${alias}.ip_address AS "ipAddress",
  ${alias}.user_agent AS "userAgent"
`;

const oauthStateSelect = (alias: string) => `
  ${alias}.id AS "id",
  ${alias}.state_hash AS "stateHash",
  ${alias}.provider_id AS "providerId",
  ${alias}.flow AS "flow",
  ${alias}.redirect_uri AS "redirectUri",
  ${alias}.scopes AS "scopes",
  ${alias}.allow_sign_up AS "allowSignUp",
  ${alias}.link_user_id AS "linkUserId",
  ${alias}.encrypted_code_verifier AS "encryptedCodeVerifier",
  ${alias}.encrypted_nonce AS "encryptedNonce",
  ${millis(`${alias}.created_at`)} AS "createdAt",
  ${millis(`${alias}.expires_at`)} AS "expiresAt",
  ${millis(`${alias}.consumed_at`)} AS "consumedAt"
`;

const credentialJoinSelect = `
  u.id AS "userId",
  u.email AS "userEmail",
  u.name AS "userName",
  u.image AS "userImage",
  u.email_verified AS "userEmailVerified",
  ${millis("u.created_at")} AS "userCreatedAt",
  ${millis("u.updated_at")} AS "userUpdatedAt",
  a.id AS "accountId",
  a.provider_id AS "accountProviderId",
  a.account_id AS "accountAccountId",
  a.user_id AS "accountUserId",
  a.scopes AS "accountScopes",
  a.password_hash AS "accountPasswordHash",
  ${millis("a.created_at")} AS "accountCreatedAt",
  ${millis("a.updated_at")} AS "accountUpdatedAt"
`;

const sessionJoinSelect = `
  ${sessionSelect("s")},
  u.id AS "userRecordId",
  u.email AS "userEmail",
  u.name AS "userName",
  u.image AS "userImage",
  u.email_verified AS "userEmailVerified",
  ${millis("u.created_at")} AS "userCreatedAt",
  ${millis("u.updated_at")} AS "userUpdatedAt"
`;

const makeId = (prefix: string) =>
  Random.nextUUIDv4.pipe(Effect.map((uuid) => `${prefix}_${uuid.replaceAll("-", "")}`));

const make: <S extends AuthDrizzlePgSchema>(
  options: LayerOptions<S>,
) => Effect.Effect<AuthStorageShape, never, SqlClient.SqlClient> = Effect.fn("DrizzlePg.make")(
  (options) =>
    Effect.gen(function* () {
      const sql = yield* SqlClient.SqlClient;
      const tables = tableNames(options.schema);

      const findCredentialAccountByEmail: AuthStorageShape["findCredentialAccountByEmail"] = (
        email,
      ) =>
        sql
          .unsafe<CredentialJoinRow>(
            `SELECT ${credentialJoinSelect}
         FROM ${tables.Users} u
         JOIN ${tables.Accounts} a ON a.user_id = u.id
         WHERE u.email = $1 AND a.provider_id = 'credential' AND a.password_hash IS NOT NULL
         LIMIT 1`,
            [email],
          )
          .pipe(
            Effect.flatMap(one),
            Effect.map((row) => ({ user: joinedCredentialUser(row), account: joinedAccount(row) })),
            Effect.mapError(storageFailure),
          );

      const findSessionByTokenHash = makeFindSessionByTokenHash(sql, tables);

      const consumeVerificationToken: AuthStorageShape["consumeVerificationToken"] = (input) =>
        sql
          .withTransaction(
            sql
              .unsafe<{ readonly value: string }>(
                `UPDATE ${tables.Verifications}
           SET consumed_at = to_timestamp($3 / 1000.0), updated_at = to_timestamp($3 / 1000.0)
           WHERE identifier = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > to_timestamp($3 / 1000.0)
           RETURNING value`,
                [tokenKey(input.tokenHash), input.purpose, input.now],
              )
              .pipe(
                Effect.flatMap((rows) =>
                  rows[0] === undefined
                    ? verificationTokenFailure(
                        sql,
                        tables,
                        input.tokenHash,
                        input.purpose,
                        input.now,
                      )
                    : Effect.succeed(rows[0]),
                ),
                Effect.tap((row) =>
                  input.purpose === "EmailVerification"
                    ? sql.unsafe(
                        `UPDATE ${tables.Users}
                   SET email_verified = true, updated_at = to_timestamp($2 / 1000.0)
                   WHERE id = $1`,
                        [row.value, input.now],
                      )
                    : Effect.void,
                ),
                Effect.flatMap((row) =>
                  sql.unsafe<CredentialJoinRow>(
                    `SELECT ${credentialJoinSelect}
               FROM ${tables.Users} u
               JOIN ${tables.Accounts} a ON a.user_id = u.id
           WHERE u.id = $1 AND a.provider_id = 'credential' AND a.password_hash IS NOT NULL
               LIMIT 1`,
                    [row.value],
                  ),
                ),
                Effect.flatMap(one),
                Effect.map((row) => ({
                  user: joinedCredentialUser(row),
                  account: joinedAccount(row),
                })),
              ),
          )
          .pipe(Effect.mapError(storageFailure));

      const selectOAuthAccountForUpdate = Effect.fn("DrizzlePg.selectOAuthAccountForUpdate")(
        function* (providerId: OAuthProviderId, providerAccountId: string) {
          const rows = yield* sql.unsafe<AccountRow>(
            `SELECT ${accountSelect("a")}
             FROM ${tables.Accounts} a
             WHERE a.provider_id = $1 AND a.account_id = $2
             LIMIT 1
             FOR UPDATE`,
            [providerId, providerAccountId],
          );
          return rows[0];
        },
      );

      const selectUserByIdForUpdate = Effect.fn("DrizzlePg.selectUserByIdForUpdate")(function* (
        userId: string,
      ) {
        const rows = yield* sql.unsafe<UserRow>(
          `SELECT ${userSelect("u")}
           FROM ${tables.Users} u
           WHERE u.id = $1
           LIMIT 1
           FOR UPDATE`,
          [userId],
        );
        return rows[0];
      });

      const selectUserByEmailForUpdate = Effect.fn("DrizzlePg.selectUserByEmailForUpdate")(
        function* (email: AuthUser["email"]) {
          const rows = yield* sql.unsafe<UserRow>(
            `SELECT ${userSelect("u")}
             FROM ${tables.Users} u
             WHERE u.email = $1
             LIMIT 1
             FOR UPDATE`,
            [email],
          );
          return rows[0];
        },
      );

      const insertOAuthAccount = Effect.fn("DrizzlePg.insertOAuthAccount")(function* (input: {
        readonly providerId: OAuthProviderId;
        readonly providerAccountId: string;
        readonly userId: string;
        readonly scopes: ReadonlyArray<string>;
        readonly providerTokens: ProtectedProviderTokenSet;
        readonly now: number;
      }) {
        const id = yield* makeId("acc");
        const row = yield* sql
          .unsafe<AccountRow>(
            `INSERT INTO ${tables.Accounts}
               (id, provider_id, account_id, user_id, scopes, password_hash,
                provider_access_token, provider_refresh_token, provider_id_token,
                provider_token_type, provider_token_scope,
                provider_access_token_expires_at, provider_refresh_token_expires_at,
                created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NULL,
                     $6, $7, $8, $9, $10,
                     CASE WHEN $11::boolean THEN to_timestamp($12 / 1000.0) ELSE NULL END,
                     CASE WHEN $13::boolean THEN to_timestamp($14 / 1000.0) ELSE NULL END,
                     to_timestamp($15 / 1000.0), to_timestamp($15 / 1000.0))
             RETURNING ${accountSelect(tables.Accounts)}`,
            [
              id,
              input.providerId,
              input.providerAccountId,
              input.userId,
              input.scopes,
              input.providerTokens.accessToken ?? null,
              input.providerTokens.refreshToken ?? null,
              input.providerTokens.idToken ?? null,
              input.providerTokens.tokenType ?? null,
              input.providerTokens.scope ?? null,
              input.providerTokens.accessTokenExpiresAt !== undefined,
              input.providerTokens.accessTokenExpiresAt ?? null,
              input.providerTokens.refreshTokenExpiresAt !== undefined,
              input.providerTokens.refreshTokenExpiresAt ?? null,
              input.now,
            ],
          )
          .pipe(Effect.flatMap(one));
        return yield* toOAuthProviderAccount(row);
      });

      const updateOAuthAccount = Effect.fn("DrizzlePg.updateOAuthAccount")(function* (input: {
        readonly providerId: OAuthProviderId;
        readonly providerAccountId: string;
        readonly scopes: ReadonlyArray<string>;
        readonly providerTokens: ProtectedProviderTokenSet;
        readonly now: number;
      }) {
        const row = yield* sql
          .unsafe<AccountRow>(
            `UPDATE ${tables.Accounts}
             SET scopes = $3,
                 provider_access_token = COALESCE($4, provider_access_token),
                 provider_refresh_token = COALESCE($5, provider_refresh_token),
                 provider_id_token = COALESCE($6, provider_id_token),
                 provider_token_type = COALESCE($7, provider_token_type),
                 provider_token_scope = COALESCE($8, provider_token_scope),
                 provider_access_token_expires_at = CASE WHEN $9::boolean THEN to_timestamp($10 / 1000.0) ELSE provider_access_token_expires_at END,
                 provider_refresh_token_expires_at = CASE WHEN $11::boolean THEN to_timestamp($12 / 1000.0) ELSE provider_refresh_token_expires_at END,
                 updated_at = to_timestamp($13 / 1000.0)
             WHERE provider_id = $1 AND account_id = $2
             RETURNING ${accountSelect(tables.Accounts)}`,
            [
              input.providerId,
              input.providerAccountId,
              input.scopes,
              input.providerTokens.accessToken ?? null,
              input.providerTokens.refreshToken ?? null,
              input.providerTokens.idToken ?? null,
              input.providerTokens.tokenType ?? null,
              input.providerTokens.scope ?? null,
              input.providerTokens.accessTokenExpiresAt !== undefined,
              input.providerTokens.accessTokenExpiresAt ?? null,
              input.providerTokens.refreshTokenExpiresAt !== undefined,
              input.providerTokens.refreshTokenExpiresAt ?? null,
              input.now,
            ],
          )
          .pipe(Effect.flatMap(one));
        return yield* toOAuthProviderAccount(row);
      });

      return {
        createUserWithCredentialAccount: (input) =>
          sql
            .withTransaction(
              Effect.gen(function* () {
                const userId = yield* makeId("usr");
                const accountId = yield* makeId("acc");
                const user = yield* sql
                  .unsafe<UserRow>(
                    `INSERT INTO ${tables.Users} (id, email, name, image, email_verified, created_at, updated_at)
               VALUES ($1, $2, $3, $4, false, to_timestamp($5 / 1000.0), to_timestamp($5 / 1000.0))
               RETURNING ${userSelect(tables.Users)}`,
                    [userId, input.email, input.name, input.image, input.now],
                  )
                  .pipe(Effect.flatMap(one));
                yield* sql.unsafe(
                  `INSERT INTO ${tables.Accounts}
                 (id, provider_id, account_id, user_id, scopes, password_hash, created_at, updated_at)
               VALUES ($1, 'credential', $2, $2, ARRAY[]::text[], $3, to_timestamp($4 / 1000.0), to_timestamp($4 / 1000.0))`,
                  [accountId, userId, passwordHash(input.passwordHash), input.now],
                );
                return toUser(user);
              }),
            )
            .pipe(Effect.mapError(storageFailure)),
        findCredentialAccountByEmail,
        updateUser: (input) =>
          sql
            .unsafe<UserRow>(
              `UPDATE ${tables.Users}
           SET name = COALESCE($2, name),
               image = CASE WHEN $3::boolean THEN $4 ELSE image END,
               updated_at = to_timestamp($5 / 1000.0)
           WHERE id = $1
           RETURNING ${userSelect(tables.Users)}`,
              [
                input.userId,
                input.name ?? null,
                input.image !== undefined,
                input.image ?? null,
                input.now,
              ],
            )
            .pipe(Effect.flatMap(one), Effect.map(toUser), Effect.mapError(storageFailure)),
        listUserAccounts: ({ userId }) =>
          sql
            .unsafe<AccountRow>(
              `SELECT ${accountSelect(tables.Accounts)}
           FROM ${tables.Accounts}
           WHERE user_id = $1
           ORDER BY created_at ASC, id ASC`,
              [userId],
            )
            .pipe(
              Effect.map((rows) => rows.map(toPublicAccount)),
              Effect.mapError(storageFailure),
            ),
        storeVerificationToken: (input) =>
          Effect.gen(function* () {
            const id = yield* makeId("ver");
            yield* sql.unsafe(
              `INSERT INTO ${tables.Verifications}
               (id, identifier, value, purpose, consumed_at, expires_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, NULL, to_timestamp($5 / 1000.0), to_timestamp($6 / 1000.0), to_timestamp($6 / 1000.0))`,
              [
                id,
                tokenKey(input.tokenHash),
                input.userId,
                input.purpose,
                input.expiresAt,
                input.now,
              ],
            );
          }).pipe(Effect.mapError(storageFailure)),
        findVerificationToken: (input) =>
          sql
            .unsafe<{ readonly value: string }>(
              `SELECT value
           FROM ${tables.Verifications}
           WHERE identifier = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > to_timestamp($3 / 1000.0)
           LIMIT 1`,
              [tokenKey(input.tokenHash), input.purpose, input.now],
            )
            .pipe(
              Effect.flatMap((rows) =>
                rows[0] === undefined
                  ? verificationTokenFailure(sql, tables, input.tokenHash, input.purpose, input.now)
                  : Effect.succeed(rows[0]),
              ),
              Effect.flatMap((row) =>
                sql.unsafe<CredentialJoinRow>(
                  `SELECT ${credentialJoinSelect}
                 FROM ${tables.Users} u
                 JOIN ${tables.Accounts} a ON a.user_id = u.id
                 WHERE u.id = $1 AND a.provider_id = 'credential' AND a.password_hash IS NOT NULL
               LIMIT 1`,
                  [row.value],
                ),
              ),
              Effect.flatMap(one),
              Effect.map((row) => ({
                user: joinedCredentialUser(row),
                account: joinedAccount(row),
              })),
              Effect.mapError(storageFailure),
            ),
        consumeVerificationToken,
        createSession: (input) =>
          makeId("ses").pipe(
            Effect.flatMap((id) =>
              sql.unsafe<SessionRow>(
                `INSERT INTO ${tables.Sessions}
                 (id, user_id, token_hash, created_at, updated_at, expires_at, revoked_at, ip_address, user_agent)
               VALUES ($1, $2, $3, to_timestamp($4 / 1000.0), to_timestamp($4 / 1000.0), to_timestamp($5 / 1000.0), NULL, $6, $7)
               RETURNING ${sessionSelect(tables.Sessions)}`,
                [
                  id,
                  input.userId,
                  tokenKey(input.tokenHash),
                  input.now,
                  input.expiresAt,
                  input.ipAddress ?? null,
                  input.userAgent ?? null,
                ],
              ),
            ),
            Effect.flatMap(one),
            Effect.map(toSession),
            Effect.mapError(storageFailure),
          ),
        findSessionByTokenHash,
        rotateSessionToken: (input) =>
          sql
            .unsafe<SessionRow>(
              `UPDATE ${tables.Sessions}
           SET token_hash = $2, updated_at = to_timestamp($4 / 1000.0), expires_at = to_timestamp($3 / 1000.0)
           WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > to_timestamp($4 / 1000.0)
           RETURNING ${sessionSelect(tables.Sessions)}`,
              [tokenKey(input.previousHash), tokenKey(input.nextHash), input.expiresAt, input.now],
            )
            .pipe(Effect.flatMap(one), Effect.map(toSession), Effect.mapError(storageFailure)),
        revokeSession: (input) =>
          sql
            .unsafe(
              `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($2 / 1000.0), updated_at = to_timestamp($2 / 1000.0)
           WHERE token_hash = $1`,
              [tokenKey(input.tokenHash), input.now],
            )
            .pipe(Effect.asVoid, Effect.mapError(storageFailure)),
        listUserSessions: (input) =>
          sql
            .unsafe<SessionRow>(
              `SELECT ${sessionSelect(tables.Sessions)}
           FROM ${tables.Sessions}
           WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > to_timestamp($2 / 1000.0)
           ORDER BY created_at DESC, id DESC`,
              [input.userId, input.now],
            )
            .pipe(
              Effect.map((rows) => rows.map(toSession)),
              Effect.mapError(storageFailure),
            ),
        revokeUserSession: (input) =>
          sql
            .unsafe<SessionRow>(
              `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($3 / 1000.0), updated_at = to_timestamp($3 / 1000.0)
           WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL AND expires_at > to_timestamp($3 / 1000.0)
           RETURNING ${sessionSelect(tables.Sessions)}`,
              [input.userId, input.sessionId, input.now],
            )
            .pipe(Effect.flatMap(one), Effect.asVoid, Effect.mapError(storageFailure)),
        revokeOtherSessions: (input) =>
          sql
            .unsafe(
              `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($3 / 1000.0), updated_at = to_timestamp($3 / 1000.0)
           WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`,
              [input.userId, input.currentSessionId, input.now],
            )
            .pipe(Effect.asVoid, Effect.mapError(storageFailure)),
        revokeAllUserSessions: (input) =>
          sql
            .unsafe(
              `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($2 / 1000.0), updated_at = to_timestamp($2 / 1000.0)
           WHERE user_id = $1 AND revoked_at IS NULL`,
              [input.userId, input.now],
            )
            .pipe(Effect.asVoid, Effect.mapError(storageFailure)),
        updateCredentialAccountPasswordHash: (input) =>
          sql
            .unsafe<AccountRow>(
              `UPDATE ${tables.Accounts}
           SET password_hash = $2, updated_at = to_timestamp($3 / 1000.0)
           WHERE user_id = $1 AND provider_id = 'credential'
           RETURNING ${accountSelect(tables.Accounts)}`,
              [input.userId, passwordHash(input.passwordHash), input.now],
            )
            .pipe(Effect.flatMap(one), Effect.asVoid, Effect.mapError(storageFailure)),
        completePasswordReset: ({ token, passwordHash }) =>
          sql
            .withTransaction(
              consumeVerificationToken(token).pipe(
                Effect.flatMap(({ user }) =>
                  sql
                    .unsafe(
                      `UPDATE ${tables.Accounts}
                 SET password_hash = $2, updated_at = to_timestamp($3 / 1000.0)
                 WHERE user_id = $1 AND provider_id = 'credential'`,
                      [user.id, Redacted.value(passwordHash), token.now],
                    )
                    .pipe(
                      Effect.flatMap(() =>
                        sql.unsafe(
                          `UPDATE ${tables.Sessions}
                     SET revoked_at = to_timestamp($2 / 1000.0), updated_at = to_timestamp($2 / 1000.0)
                     WHERE user_id = $1 AND revoked_at IS NULL`,
                          [user.id, token.now],
                        ),
                      ),
                    ),
                ),
              ),
            )
            .pipe(Effect.asVoid, Effect.mapError(storageFailure)),
        changePasswordSession: (input) =>
          sql
            .withTransaction(
              sql
                .unsafe(
                  `UPDATE ${tables.Accounts}
             SET password_hash = $2, updated_at = to_timestamp($3 / 1000.0)
             WHERE user_id = $1 AND provider_id = 'credential'`,
                  [
                    input.password.userId,
                    passwordHash(input.password.passwordHash),
                    input.password.now,
                  ],
                )
                .pipe(
                  Effect.flatMap(() =>
                    sql.unsafe(
                      `UPDATE ${tables.Sessions}
                 SET revoked_at = to_timestamp($3 / 1000.0), updated_at = to_timestamp($3 / 1000.0)
                 WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`,
                      [input.password.userId, input.currentSessionId, input.password.now],
                    ),
                  ),
                  Effect.flatMap(() =>
                    sql.unsafe<SessionRow>(
                      `UPDATE ${tables.Sessions}
                 SET token_hash = $2,
                     updated_at = to_timestamp($4 / 1000.0),
                     expires_at = to_timestamp($3 / 1000.0)
                 WHERE token_hash = $1 AND id = $5 AND revoked_at IS NULL AND expires_at > to_timestamp($4 / 1000.0)
                 RETURNING ${sessionSelect(tables.Sessions)}`,
                      [
                        tokenKey(input.previousSessionTokenHash),
                        tokenKey(input.nextSessionTokenHash),
                        input.sessionExpiresAt,
                        input.password.now,
                        input.currentSessionId,
                      ],
                    ),
                  ),
                  Effect.flatMap(one),
                  Effect.map(toSession),
                ),
            )
            .pipe(Effect.mapError(storageFailure)),
        deleteUser: (input) =>
          sql
            .withTransaction(
              sql
                .unsafe(`DELETE FROM ${tables.Verifications} WHERE value = $1`, [input.userId])
                .pipe(
                  Effect.flatMap(() =>
                    sql.unsafe<UserRow>(
                      `DELETE FROM ${tables.Users}
                 WHERE id = $1
                 RETURNING ${userSelect(tables.Users)}`,
                      [input.userId],
                    ),
                  ),
                  Effect.flatMap(one),
                  Effect.asVoid,
                ),
            )
            .pipe(Effect.mapError(storageFailure)),
        storeOAuthState: (input) =>
          makeId("ost").pipe(
            Effect.flatMap((id) =>
              sql.unsafe<OAuthStateRow>(
                `INSERT INTO ${tables.OAuthStates}
                 (id, state_hash, provider_id, flow, redirect_uri, scopes, allow_sign_up, link_user_id, encrypted_code_verifier, encrypted_nonce, created_at, expires_at, consumed_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11 / 1000.0), to_timestamp($12 / 1000.0), NULL)
               RETURNING ${oauthStateSelect(tables.OAuthStates)}`,
                [
                  id,
                  oauthStateKey(input.stateHash),
                  input.providerId,
                  input.flow,
                  input.redirectUri.href,
                  input.scopes,
                  input.allowSignUp,
                  input.linkUserId ?? null,
                  input.encryptedCodeVerifier ?? null,
                  input.encryptedNonce ?? null,
                  input.now,
                  input.expiresAt,
                ],
              ),
            ),
            Effect.flatMap(one),
            Effect.map(toOAuthState),
            Effect.mapError(storageFailure),
          ),
        consumeOAuthState: (input) =>
          sql
            .withTransaction(
              sql
                .unsafe<OAuthStateRow>(
                  `UPDATE ${tables.OAuthStates}
             SET consumed_at = to_timestamp($4 / 1000.0)
             WHERE state_hash = $1 AND provider_id = $2 AND flow = $3 AND consumed_at IS NULL AND expires_at > to_timestamp($4 / 1000.0)
             RETURNING ${oauthStateSelect(tables.OAuthStates)}`,
                  [oauthStateKey(input.stateHash), input.providerId, input.flow, input.now],
                )
                .pipe(
                  Effect.flatMap((rows) =>
                    rows[0] === undefined
                      ? oauthStateFailure(
                          sql,
                          tables,
                          input.stateHash,
                          input.providerId,
                          input.flow,
                          input.now,
                        )
                      : Effect.succeed(rows[0]),
                  ),
                  Effect.map(toOAuthState),
                ),
            )
            .pipe(Effect.mapError(storageFailure)),
        completeOAuthSignIn: (input) =>
          sql
            .withTransaction(
              Effect.gen(function* () {
                const existingAccount = yield* selectOAuthAccountForUpdate(
                  input.providerId,
                  input.providerAccountId,
                );
                if (existingAccount !== undefined) {
                  const userRow = yield* selectUserByIdForUpdate(existingAccount.userId).pipe(
                    Effect.flatMap((row) =>
                      row === undefined ? Effect.fail(backendUnavailable) : Effect.succeed(row),
                    ),
                  );
                  const account = yield* updateOAuthAccount(input);
                  return { user: toUser(userRow), account, isNewUser: false };
                }

                const existingUser = yield* selectUserByEmailForUpdate(input.email);
                if (existingUser !== undefined && !input.allowAutomaticSameEmailLinking) {
                  return yield* new OAuthAccountStorageFailure({
                    reason: "AutomaticLinkingNotAllowed",
                  });
                }
                if (existingUser !== undefined) {
                  const account = yield* insertOAuthAccount({
                    providerId: input.providerId,
                    providerAccountId: input.providerAccountId,
                    userId: existingUser.id,
                    scopes: input.scopes,
                    providerTokens: input.providerTokens,
                    now: input.now,
                  });
                  return { user: toUser(existingUser), account, isNewUser: false };
                }
                if (!input.allowImplicitSignUp) {
                  return yield* new OAuthAccountStorageFailure({
                    reason: "ImplicitSignUpDisabled",
                  });
                }

                const userId = yield* makeId("usr");
                const userRow = yield* sql
                  .unsafe<UserRow>(
                    `INSERT INTO ${tables.Users}
                       (id, email, name, image, email_verified, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, to_timestamp($6 / 1000.0), to_timestamp($6 / 1000.0))
                     RETURNING ${userSelect(tables.Users)}`,
                    [userId, input.email, input.name, input.image, input.emailVerified, input.now],
                  )
                  .pipe(Effect.flatMap(one));
                const account = yield* insertOAuthAccount({
                  providerId: input.providerId,
                  providerAccountId: input.providerAccountId,
                  userId,
                  scopes: input.scopes,
                  providerTokens: input.providerTokens,
                  now: input.now,
                });
                return { user: toUser(userRow), account, isNewUser: true };
              }),
            )
            .pipe(Effect.mapError(oauthAccountStorageFailure)),
        completeOAuthLink: (input) =>
          sql
            .withTransaction(
              Effect.gen(function* () {
                const userRow = yield* selectUserByIdForUpdate(input.userId).pipe(
                  Effect.flatMap((row) =>
                    row === undefined
                      ? Effect.fail(new OAuthAccountStorageFailure({ reason: "LinkUserNotFound" }))
                      : Effect.succeed(row),
                  ),
                );
                const user = toUser(userRow);
                const existingAccount = yield* selectOAuthAccountForUpdate(
                  input.providerId,
                  input.providerAccountId,
                );
                if (existingAccount !== undefined && existingAccount.userId !== input.userId) {
                  return yield* new OAuthAccountStorageFailure({
                    reason: "ProviderAccountLinkedToDifferentUser",
                  });
                }
                if (user.email !== input.providerEmail && !input.allowDifferentEmail) {
                  return yield* new OAuthAccountStorageFailure({ reason: "LinkEmailMismatch" });
                }
                if (existingAccount !== undefined) {
                  const account = yield* updateOAuthAccount(input);
                  return { user, account, isNewUser: false };
                }
                const account = yield* insertOAuthAccount({
                  providerId: input.providerId,
                  providerAccountId: input.providerAccountId,
                  userId: input.userId,
                  scopes: input.scopes,
                  providerTokens: input.providerTokens,
                  now: input.now,
                });
                return { user, account, isNewUser: false };
              }),
            )
            .pipe(Effect.mapError(oauthAccountStorageFailure)),
      };
    }),
);

export const layer = <S extends AuthDrizzlePgSchema>(options: LayerOptions<S>) =>
  Layer.effect(AuthStorage)(make(options));

export const DrizzlePg = {
  schema,
  layer,
};
