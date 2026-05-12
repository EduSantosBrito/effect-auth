import { Clock, Effect, Layer, Match, Redacted } from "effect";
import type { TokenHash } from "../token/index.js";
import {
  AuthStorage,
  AuthStorageFailure,
  type AuthStorageShape,
  type AuthUser,
  type AuthUserId,
  type EmailPasswordCredential,
  type StoredSession,
} from "./index.js";

interface TokenRecord {
  readonly userId: AuthUserId;
  readonly email: EmailPasswordCredential["email"];
  readonly purpose: "EmailVerification" | "PasswordReset";
  readonly tokenHash: TokenHash;
  readonly expiresAt: number;
  consumedAt?: number;
}

export interface DevMemoryStorageState {
  readonly users: Map<AuthUserId, AuthUser>;
  readonly credentialsByEmail: Map<string, EmailPasswordCredential>;
  readonly tokensByHash: Map<string, TokenRecord>;
  readonly sessionsByHash: Map<string, StoredSession>;
}

export const makeDevMemoryStorageState = (): DevMemoryStorageState => ({
  users: new Map(),
  credentialsByEmail: new Map(),
  tokensByHash: new Map(),
  sessionsByHash: new Map(),
});

let nextId = 0;
const id = (prefix: string) => `${prefix}_${++nextId}`;
const tokenKey = (hash: TokenHash) => Redacted.value(hash);

const isStoredSessionRecord = (session: StoredSession | undefined): session is StoredSession =>
  session !== undefined &&
  typeof session.id === "string" &&
  typeof session.userId === "string" &&
  typeof session.createdAt === "number" &&
  typeof session.updatedAt === "number" &&
  typeof session.expiresAt === "number" &&
  (session.revokedAt === undefined || typeof session.revokedAt === "number") &&
  (session.ipAddress === undefined || typeof session.ipAddress === "string") &&
  (session.userAgent === undefined || typeof session.userAgent === "string");

const findUsableVerificationToken = (
  state: DevMemoryStorageState,
  { purpose, tokenHash, now }: Parameters<AuthStorageShape["findVerificationToken"]>[0],
) =>
  Effect.suspend(() => {
    const record = state.tokensByHash.get(tokenKey(tokenHash));
    if (!record || record.purpose !== purpose)
      return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    if (record.consumedAt !== undefined)
      return Effect.fail(new AuthStorageFailure({ reason: "TokenConsumed" }));
    if (record.expiresAt <= now)
      return Effect.fail(new AuthStorageFailure({ reason: "TokenExpired" }));
    const credential = state.credentialsByEmail.get(String(record.email));
    const user = credential ? state.users.get(credential.userId) : undefined;
    return credential && user
      ? Effect.succeed({ user, credential })
      : Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
  });

const consumeVerificationToken = (
  state: DevMemoryStorageState,
  { purpose, tokenHash, now }: Parameters<AuthStorageShape["consumeVerificationToken"]>[0],
) =>
  findUsableVerificationToken(state, { purpose, tokenHash, now }).pipe(
    Effect.flatMap(({ user, credential }) =>
      Effect.suspend(() => {
        const record = state.tokensByHash.get(tokenKey(tokenHash));
        if (!record) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
        record.consumedAt = now;
        const consumedCredential =
          purpose === "EmailVerification"
            ? { ...credential, emailVerified: true, updatedAt: now }
            : credential;
        state.credentialsByEmail.set(String(record.email), consumedCredential);
        return Effect.succeed({ user, credential: consumedCredential });
      }),
    ),
  );

const updatePasswordHash = (
  state: DevMemoryStorageState,
  { userId, passwordHash, now }: Parameters<AuthStorageShape["updatePasswordHash"]>[0],
) =>
  Effect.suspend(() => {
    const entry = Array.from(state.credentialsByEmail.entries()).find(
      ([, credential]) => credential.userId === userId,
    );
    if (!entry) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    const [email, credential] = entry;
    state.credentialsByEmail.set(email, { ...credential, passwordHash, updatedAt: now });
    return Effect.void;
  });

const rotateSessionToken = (
  state: DevMemoryStorageState,
  { previousHash, nextHash, expiresAt, now }: Parameters<AuthStorageShape["rotateSessionToken"]>[0],
) =>
  Effect.suspend(() => {
    const session = state.sessionsByHash.get(tokenKey(previousHash));
    if (!isStoredSessionRecord(session))
      return Effect.fail(new AuthStorageFailure({ reason: "BackendUnavailable" }));
    if (session.revokedAt !== undefined)
      return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    state.sessionsByHash.delete(tokenKey(previousHash));
    const rotated = { ...session, tokenHash: nextHash, updatedAt: now, expiresAt };
    state.sessionsByHash.set(tokenKey(nextHash), rotated);
    return Effect.succeed(rotated);
  });

const revokeOtherSessions = (
  state: DevMemoryStorageState,
  { userId, currentSessionId, now }: Parameters<AuthStorageShape["revokeOtherSessions"]>[0],
) =>
  Effect.sync(() => {
    for (const [key, session] of state.sessionsByHash) {
      if (session.userId === userId && session.id !== currentSessionId) {
        state.sessionsByHash.set(key, { ...session, revokedAt: now, updatedAt: now });
      }
    }
  });

const isActiveSession = (session: StoredSession, now: number) =>
  session.revokedAt === undefined && session.expiresAt > now;

const failOnMalformedSessions = (
  state: DevMemoryStorageState,
): Effect.Effect<void, AuthStorageFailure> =>
  Effect.suspend(() => {
    for (const session of state.sessionsByHash.values()) {
      if (!isStoredSessionRecord(session)) {
        return Effect.fail(new AuthStorageFailure({ reason: "BackendUnavailable" }));
      }
    }
    return Effect.void;
  });

const listUserSessions = (
  state: DevMemoryStorageState,
  { userId, now }: Parameters<AuthStorageShape["listUserSessions"]>[0],
) =>
  failOnMalformedSessions(state).pipe(
    Effect.flatMap(() =>
      Effect.sync(() =>
        Array.from(state.sessionsByHash.values()).filter(
          (session) => session.userId === userId && isActiveSession(session, now),
        ),
      ),
    ),
  );

const revokeUserSession = (
  state: DevMemoryStorageState,
  { userId, sessionId, now }: Parameters<AuthStorageShape["revokeUserSession"]>[0],
) =>
  failOnMalformedSessions(state).pipe(
    Effect.flatMap(() =>
      Effect.suspend(() => {
        const entry: readonly [string, StoredSession] | undefined = Array.from(
          state.sessionsByHash.entries(),
        ).find(([, session]) => session.id === sessionId && session.userId === userId);
        return Match.value(entry).pipe(
          Match.when(
            (
              entry: readonly [string, StoredSession] | undefined,
            ): entry is readonly [string, StoredSession] =>
              entry !== undefined && isActiveSession(entry[1], now),
            ([key, session]) =>
              Effect.sync(() => {
                state.sessionsByHash.set(key, { ...session, revokedAt: now, updatedAt: now });
              }),
          ),
          Match.orElse(() => Effect.fail(new AuthStorageFailure({ reason: "NotFound" }))),
        );
      }),
    ),
  );

const revokeAllUserSessions = (
  state: DevMemoryStorageState,
  { userId, now }: Parameters<AuthStorageShape["revokeAllUserSessions"]>[0],
) =>
  Effect.sync(() => {
    for (const [key, session] of state.sessionsByHash) {
      if (session.userId === userId)
        state.sessionsByHash.set(key, { ...session, revokedAt: now, updatedAt: now });
    }
  });

export const makeDevMemoryStorage = (state = makeDevMemoryStorageState()): AuthStorageShape => ({
  createUserWithEmailPasswordCredential: ({ email, passwordHash, now }) =>
    Effect.suspend(() => {
      if (state.credentialsByEmail.has(String(email)))
        return Effect.fail(new AuthStorageFailure({ reason: "Conflict" }));
      const user: AuthUser = { id: id("usr"), email, createdAt: now };
      const credential: EmailPasswordCredential = {
        id: id("cred"),
        userId: user.id,
        email,
        passwordHash,
        emailVerified: false,
        createdAt: now,
        updatedAt: now,
      };
      state.users.set(user.id, user);
      state.credentialsByEmail.set(String(email), credential);
      return Effect.succeed(user);
    }),
  findCredentialByEmail: (email) =>
    Effect.suspend(() => {
      const credential = state.credentialsByEmail.get(String(email));
      const user = credential ? state.users.get(credential.userId) : undefined;
      return credential && user
        ? Effect.succeed({ user, credential })
        : Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    }),
  storeVerificationToken: (input) =>
    Effect.sync(() => {
      state.tokensByHash.set(tokenKey(input.tokenHash), { ...input });
    }),
  findVerificationToken: (input) => findUsableVerificationToken(state, input),
  consumeVerificationToken: (input) => consumeVerificationToken(state, input),
  createSession: ({ userId, tokenHash, expiresAt, now, ipAddress, userAgent }) =>
    Effect.sync(() => {
      const session: StoredSession = {
        id: id("ses"),
        userId,
        tokenHash,
        createdAt: now,
        updatedAt: now,
        expiresAt,
        ...(ipAddress === undefined ? {} : { ipAddress }),
        ...(userAgent === undefined ? {} : { userAgent }),
      };
      state.sessionsByHash.set(tokenKey(tokenHash), session);
      return session;
    }),
  findSessionByTokenHash: (hash) =>
    Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      const session = state.sessionsByHash.get(tokenKey(hash));
      if (session !== undefined && !isStoredSessionRecord(session))
        return yield* new AuthStorageFailure({ reason: "BackendUnavailable" });
      const user = session ? state.users.get(session.userId) : undefined;
      if (!session || !user || session.revokedAt !== undefined)
        return yield* new AuthStorageFailure({ reason: "NotFound" });
      if (session.expiresAt <= now)
        return yield* new AuthStorageFailure({ reason: "SessionExpired" });
      return { session, user };
    }),
  rotateSessionToken: (input) => rotateSessionToken(state, input),
  revokeSession: ({ tokenHash, now }) =>
    Effect.gen(function* () {
      const key = tokenKey(tokenHash);
      const session = yield* Match.value(state.sessionsByHash.get(key)).pipe(
        Match.when(
          (session) => session !== undefined && !isStoredSessionRecord(session),
          () => new AuthStorageFailure({ reason: "BackendUnavailable" }),
        ),
        Match.when(
          (session) => session === undefined,
          () => new AuthStorageFailure({ reason: "NotFound" }),
        ),
        Match.orElse((session) => Effect.succeed(session)),
      );
      state.sessionsByHash.set(key, {
        ...session,
        revokedAt: now,
        updatedAt: now,
      });
    }),
  listUserSessions: (input) => listUserSessions(state, input),
  revokeUserSession: (input) => revokeUserSession(state, input),
  revokeOtherSessions: (input) => revokeOtherSessions(state, input),
  revokeAllUserSessions: (input) => revokeAllUserSessions(state, input),
  updatePasswordHash: (input) => updatePasswordHash(state, input),
  completePasswordReset: ({ token, passwordHash }) =>
    consumeVerificationToken(state, token).pipe(
      Effect.flatMap(({ user }) =>
        updatePasswordHash(state, { userId: user.id, passwordHash, now: token.now }).pipe(
          Effect.flatMap(() => revokeAllUserSessions(state, { userId: user.id, now: token.now })),
        ),
      ),
    ),
  changePasswordSession: ({
    password,
    currentSessionId,
    previousSessionTokenHash,
    nextSessionTokenHash,
    sessionExpiresAt,
  }) =>
    updatePasswordHash(state, password).pipe(
      Effect.flatMap(() =>
        revokeOtherSessions(state, {
          userId: password.userId,
          currentSessionId,
          now: password.now,
        }),
      ),
      Effect.flatMap(() =>
        rotateSessionToken(state, {
          previousHash: previousSessionTokenHash,
          nextHash: nextSessionTokenHash,
          expiresAt: sessionExpiresAt,
          now: password.now,
        }),
      ),
    ),
});

export const DevMemoryAuthStorage = (state?: DevMemoryStorageState) =>
  Layer.succeed(AuthStorage)(makeDevMemoryStorage(state));
