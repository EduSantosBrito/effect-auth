import { Clock, Effect, Layer, Predicate, Random, Redacted, Schema } from "effect";
import * as SqlClient from "effect/unstable/sql/SqlClient";
import type { SqlError } from "effect/unstable/sql/SqlError";
import { boolean, index, pgTable, text, timestamp, uniqueIndex } from "drizzle-orm/pg-core";
import { NormalizedEmail } from "../domain/index.js";
import type { PasswordHash } from "../password/index.js";
import type { TokenHash } from "../token/index.js";
import {
  AuthStorage,
  AuthStorageFailure,
  type AuthAccount,
  type AuthStorageShape,
  type AuthUser,
  type PublicAuthAccount,
  type StoredSession,
} from "./index.js";

export interface SchemaOptions {
  readonly prefix?: string;
}

export interface LayerOptions extends SchemaOptions {}

const defaultPrefix = "auth_";
const identifierPattern = /^[A-Za-z_][A-Za-z0-9_]*$/u;

const tableNames = (options: SchemaOptions = {}) => {
  const prefix = options.prefix ?? defaultPrefix;
  const safePrefix = identifierPattern.test(`${prefix}users`) ? prefix : defaultPrefix;
  return {
    Users: `${safePrefix}users`,
    Accounts: `${safePrefix}accounts`,
    Sessions: `${safePrefix}sessions`,
    Verifications: `${safePrefix}verifications`,
  };
};

export const schema = (options: SchemaOptions = {}) => {
  const tables = tableNames(options);
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
      passwordHash: text("password_hash").notNull(),
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
      identifier: text("identifier").primaryKey(),
      value: text("value").notNull(),
      purpose: text("purpose").notNull(),
      consumedAt: timestamp("consumed_at", { withTimezone: true }),
      expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
      createdAt: timestamp("created_at", { withTimezone: true }).notNull(),
      updatedAt: timestamp("updated_at", { withTimezone: true }).notNull(),
    },
    (table) => [
      index(`${tables.Verifications}_value_purpose_idx`).on(table.value, table.purpose),
    ],
  );
  return { Users, Accounts, Sessions, Verifications };
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
  readonly providerId: "credential";
  readonly accountId: string;
  readonly userId: string;
  readonly scopes: ReadonlyArray<string>;
  readonly passwordHash: string;
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
const passwordHash = (hash: PasswordHash) => Redacted.value(hash);
const millis = (column: string) => `(extract(epoch from ${column}) * 1000)::double precision`;
const notFound = new AuthStorageFailure({ reason: "NotFound" });
const backendUnavailable = new AuthStorageFailure({ reason: "BackendUnavailable" });

const sqlFailure = (error: SqlError) =>
  Predicate.isTagged(error.reason, "UniqueViolation")
    ? new AuthStorageFailure({ reason: "Conflict" })
    : backendUnavailable;

const storageFailure = (error: SqlError | AuthStorageFailure): AuthStorageFailure =>
  Predicate.isTagged(error, "AuthStorageFailure") ? error : sqlFailure(error);
const decodeNormalizedEmail = Schema.decodeSync(NormalizedEmail);

const one = <A>(rows: ReadonlyArray<A>): Effect.Effect<A, AuthStorageFailure> => {
  const row = rows[0];
  return row === undefined ? Effect.fail(notFound) : Effect.succeed(row);
};

const verificationTokenFailure = Effect.fn("DrizzlePg.verificationTokenFailure")(function* (
  sql: SqlClient.SqlClient,
  tables: ReturnType<typeof tableNames>,
  tokenHash: TokenHash,
  purpose: string,
  now: number,
) {
  const row = yield* sql.unsafe<{
    readonly consumedAt: number | null;
    readonly expiresAt: number;
  }>(
    `SELECT ${millis("consumed_at")} AS "consumedAt", ${millis("expires_at")} AS "expiresAt"
     FROM ${tables.Verifications}
     WHERE identifier = $1 AND purpose = $2
     LIMIT 1`,
    [tokenKey(tokenHash), purpose],
  ).pipe(Effect.flatMap(one), Effect.mapError(storageFailure));
  if (row.consumedAt !== null) return yield* new AuthStorageFailure({ reason: "TokenConsumed" });
  if (row.expiresAt <= now) return yield* new AuthStorageFailure({ reason: "TokenExpired" });
  return yield* notFound;
});

const makeFindSessionByTokenHash = (
  sql: SqlClient.SqlClient,
  tables: ReturnType<typeof tableNames>,
): AuthStorageShape["findSessionByTokenHash"] =>
  Effect.fn("DrizzlePg.findSessionByTokenHash")(function* (hash) {
    const now = yield* Clock.currentTimeMillis;
    const row = yield* sql.unsafe<SessionJoinRow>(
      `SELECT ${sessionJoinSelect}
       FROM ${tables.Sessions} s
       JOIN ${tables.Users} u ON u.id = s.user_id
       WHERE s.token_hash = $1
       LIMIT 1`,
      [tokenKey(hash)],
    ).pipe(Effect.flatMap(one), Effect.mapError(storageFailure));
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

const toAccount = (row: AccountRow): AuthAccount => ({
  id: row.id,
  providerId: row.providerId,
  accountId: row.accountId,
  userId: row.userId,
  scopes: row.scopes,
  passwordHash: Redacted.make(row.passwordHash),
  createdAt: row.createdAt,
  updatedAt: row.updatedAt,
});

const toPublicAccount = ({ passwordHash: _passwordHash, ...account }: AuthAccount): PublicAuthAccount =>
  account;

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

const joinedAccount = (row: CredentialJoinRow): AuthAccount => ({
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

export const make: (
  options?: LayerOptions,
) => Effect.Effect<AuthStorageShape, never, SqlClient.SqlClient> = Effect.fn("DrizzlePg.make")(
  (options = {}) =>
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const tables = tableNames(options);

    const findCredentialAccountByEmail: AuthStorageShape["findCredentialAccountByEmail"] = (
      email,
    ) =>
      sql.unsafe<CredentialJoinRow>(
        `SELECT ${credentialJoinSelect}
         FROM ${tables.Users} u
         JOIN ${tables.Accounts} a ON a.user_id = u.id
         WHERE u.email = $1 AND a.provider_id = 'credential'
         LIMIT 1`,
        [email],
      ).pipe(
        Effect.flatMap(one),
        Effect.map((row) => ({ user: joinedCredentialUser(row), account: joinedAccount(row) })),
        Effect.mapError(storageFailure),
      );

    const findSessionByTokenHash = makeFindSessionByTokenHash(sql, tables);

    const consumeVerificationToken: AuthStorageShape["consumeVerificationToken"] = (input) =>
      sql.withTransaction(
        sql.unsafe<{ readonly value: string }>(
          `UPDATE ${tables.Verifications}
           SET consumed_at = to_timestamp($3 / 1000.0), updated_at = to_timestamp($3 / 1000.0)
           WHERE identifier = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > to_timestamp($3 / 1000.0)
           RETURNING value`,
          [tokenKey(input.tokenHash), input.purpose, input.now],
        ).pipe(
          Effect.flatMap((rows) =>
            rows[0] === undefined
              ? verificationTokenFailure(sql, tables, input.tokenHash, input.purpose, input.now)
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
               WHERE u.id = $1 AND a.provider_id = 'credential'
               LIMIT 1`,
              [row.value],
            ),
          ),
          Effect.flatMap(one),
          Effect.map((row) => ({ user: joinedCredentialUser(row), account: joinedAccount(row) })),
        ),
      ).pipe(Effect.mapError(storageFailure));

    return {
      createUserWithCredentialAccount: (input) =>
        sql.withTransaction(
          Effect.gen(function* () {
            const userId = yield* makeId("usr");
            const accountId = yield* makeId("acc");
            const user = yield* sql.unsafe<UserRow>(
              `INSERT INTO ${tables.Users} (id, email, name, image, email_verified, created_at, updated_at)
               VALUES ($1, $2, $3, $4, false, to_timestamp($5 / 1000.0), to_timestamp($5 / 1000.0))
               RETURNING ${userSelect(tables.Users)}`,
              [userId, input.email, input.name, input.image, input.now],
            ).pipe(Effect.flatMap(one));
            yield* sql.unsafe(
              `INSERT INTO ${tables.Accounts}
                 (id, provider_id, account_id, user_id, scopes, password_hash, created_at, updated_at)
               VALUES ($1, 'credential', $2, $2, ARRAY[]::text[], $3, to_timestamp($4 / 1000.0), to_timestamp($4 / 1000.0))`,
              [accountId, userId, passwordHash(input.passwordHash), input.now],
            );
            return toUser(user);
          }),
        ).pipe(Effect.mapError(storageFailure)),
      findCredentialAccountByEmail,
      updateUser: (input) =>
        sql.unsafe<UserRow>(
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
        ).pipe(Effect.flatMap(one), Effect.map(toUser), Effect.mapError(storageFailure)),
      listUserAccounts: ({ userId }) =>
        sql.unsafe<AccountRow>(
          `SELECT ${accountSelect(tables.Accounts)}
           FROM ${tables.Accounts}
           WHERE user_id = $1
           ORDER BY created_at ASC, id ASC`,
          [userId],
        ).pipe(
          Effect.map((rows) => rows.map((row) => toPublicAccount(toAccount(row)))),
          Effect.mapError(storageFailure),
        ),
      storeVerificationToken: (input) =>
        sql.unsafe(
          `INSERT INTO ${tables.Verifications}
             (identifier, value, purpose, consumed_at, expires_at, created_at, updated_at)
           VALUES ($1, $2, $3, NULL, to_timestamp($4 / 1000.0), to_timestamp($5 / 1000.0), to_timestamp($5 / 1000.0))`,
          [tokenKey(input.tokenHash), input.userId, input.purpose, input.expiresAt, input.now],
        ).pipe(Effect.asVoid, Effect.mapError(storageFailure)),
      findVerificationToken: (input) =>
        sql.unsafe<{ readonly value: string }>(
          `SELECT value
           FROM ${tables.Verifications}
           WHERE identifier = $1 AND purpose = $2 AND consumed_at IS NULL AND expires_at > to_timestamp($3 / 1000.0)
           LIMIT 1`,
          [tokenKey(input.tokenHash), input.purpose, input.now],
        ).pipe(
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
                 WHERE u.id = $1 AND a.provider_id = 'credential'
               LIMIT 1`,
              [row.value],
            ),
          ),
          Effect.flatMap(one),
          Effect.map((row) => ({ user: joinedCredentialUser(row), account: joinedAccount(row) })),
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
        sql.unsafe<SessionRow>(
          `UPDATE ${tables.Sessions}
           SET token_hash = $2, updated_at = to_timestamp($4 / 1000.0), expires_at = to_timestamp($3 / 1000.0)
           WHERE token_hash = $1 AND revoked_at IS NULL
           RETURNING ${sessionSelect(tables.Sessions)}`,
          [tokenKey(input.previousHash), tokenKey(input.nextHash), input.expiresAt, input.now],
        ).pipe(Effect.flatMap(one), Effect.map(toSession), Effect.mapError(storageFailure)),
      revokeSession: (input) =>
        sql.unsafe(
          `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($2 / 1000.0), updated_at = to_timestamp($2 / 1000.0)
           WHERE token_hash = $1`,
          [tokenKey(input.tokenHash), input.now],
        ).pipe(Effect.asVoid, Effect.mapError(storageFailure)),
      listUserSessions: (input) =>
        sql.unsafe<SessionRow>(
          `SELECT ${sessionSelect(tables.Sessions)}
           FROM ${tables.Sessions}
           WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > to_timestamp($2 / 1000.0)
           ORDER BY created_at DESC, id DESC`,
          [input.userId, input.now],
        ).pipe(Effect.map((rows) => rows.map(toSession)), Effect.mapError(storageFailure)),
      revokeUserSession: (input) =>
        sql.unsafe<SessionRow>(
          `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($3 / 1000.0), updated_at = to_timestamp($3 / 1000.0)
           WHERE user_id = $1 AND id = $2 AND revoked_at IS NULL AND expires_at > to_timestamp($3 / 1000.0)
           RETURNING ${sessionSelect(tables.Sessions)}`,
          [input.userId, input.sessionId, input.now],
        ).pipe(Effect.flatMap(one), Effect.asVoid, Effect.mapError(storageFailure)),
      revokeOtherSessions: (input) =>
        sql.unsafe(
          `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($3 / 1000.0), updated_at = to_timestamp($3 / 1000.0)
           WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL`,
          [input.userId, input.currentSessionId, input.now],
        ).pipe(Effect.asVoid, Effect.mapError(storageFailure)),
      revokeAllUserSessions: (input) =>
        sql.unsafe(
          `UPDATE ${tables.Sessions}
           SET revoked_at = to_timestamp($2 / 1000.0), updated_at = to_timestamp($2 / 1000.0)
           WHERE user_id = $1 AND revoked_at IS NULL`,
          [input.userId, input.now],
        ).pipe(Effect.asVoid, Effect.mapError(storageFailure)),
      updateCredentialAccountPasswordHash: (input) =>
        sql.unsafe<AccountRow>(
          `UPDATE ${tables.Accounts}
           SET password_hash = $2, updated_at = to_timestamp($3 / 1000.0)
           WHERE user_id = $1 AND provider_id = 'credential'
           RETURNING ${accountSelect(tables.Accounts)}`,
          [input.userId, passwordHash(input.passwordHash), input.now],
        ).pipe(Effect.flatMap(one), Effect.asVoid, Effect.mapError(storageFailure)),
      completePasswordReset: ({ token, passwordHash }) =>
        sql.withTransaction(
          consumeVerificationToken(token).pipe(
            Effect.flatMap(({ user }) =>
              sql.unsafe(
                `UPDATE ${tables.Accounts}
                 SET password_hash = $2, updated_at = to_timestamp($3 / 1000.0)
                 WHERE user_id = $1 AND provider_id = 'credential'`,
                [user.id, Redacted.value(passwordHash), token.now],
              ).pipe(
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
        ).pipe(Effect.asVoid, Effect.mapError(storageFailure)),
      changePasswordSession: (input) =>
        sql.withTransaction(
          sql.unsafe(
            `UPDATE ${tables.Accounts}
             SET password_hash = $2, updated_at = to_timestamp($3 / 1000.0)
             WHERE user_id = $1 AND provider_id = 'credential'`,
            [
              input.password.userId,
              passwordHash(input.password.passwordHash),
              input.password.now,
            ],
          ).pipe(
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
                 WHERE token_hash = $1 AND id = $5 AND revoked_at IS NULL
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
        ).pipe(Effect.mapError(storageFailure)),
      deleteUser: (input) =>
        sql.withTransaction(
          sql.unsafe(`DELETE FROM ${tables.Verifications} WHERE value = $1`, [input.userId]).pipe(
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
        ).pipe(Effect.mapError(storageFailure)),
    };
  }),
);

export const layer = (options: LayerOptions = {}) => Layer.effect(AuthStorage)(make(options));

export const DrizzlePg = {
  schema,
  layer,
};
