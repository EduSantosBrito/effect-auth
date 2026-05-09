import { Clock, Effect, Layer, Redacted } from "effect";
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
  consumeVerificationToken: ({ purpose, tokenHash, now }) =>
    findUsableVerificationToken(state, { purpose, tokenHash, now }).pipe(
      Effect.map(({ user, credential }) => {
        const record = state.tokensByHash.get(tokenKey(tokenHash));
        if (!record) throw new Error("verification token disappeared during consume");
        record.consumedAt = now;
        const consumedCredential =
          purpose === "EmailVerification"
            ? { ...credential, emailVerified: true, updatedAt: now }
            : credential;
        state.credentialsByEmail.set(String(record.email), consumedCredential);
        return { user, credential: consumedCredential };
      }),
    ),
  createSession: ({ userId, tokenHash, expiresAt, now }) =>
    Effect.sync(() => {
      const session: StoredSession = {
        id: id("ses"),
        userId,
        tokenHash,
        createdAt: now,
        updatedAt: now,
        expiresAt,
      };
      state.sessionsByHash.set(tokenKey(tokenHash), session);
      return session;
    }),
  findSessionByTokenHash: (hash) =>
    Effect.gen(function* () {
      const now = yield* Clock.currentTimeMillis;
      const session = state.sessionsByHash.get(tokenKey(hash));
      const user = session ? state.users.get(session.userId) : undefined;
      if (!session || !user || session.revokedAt !== undefined)
        return yield* new AuthStorageFailure({ reason: "NotFound" });
      if (session.expiresAt <= now)
        return yield* new AuthStorageFailure({ reason: "SessionExpired" });
      return { session, user };
    }),
  rotateSessionToken: ({ previousHash, nextHash, expiresAt, now }) =>
    Effect.suspend(() => {
      const session = state.sessionsByHash.get(tokenKey(previousHash));
      if (!session || session.revokedAt !== undefined)
        return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
      state.sessionsByHash.delete(tokenKey(previousHash));
      const rotated = { ...session, tokenHash: nextHash, updatedAt: now, expiresAt };
      state.sessionsByHash.set(tokenKey(nextHash), rotated);
      return Effect.succeed(rotated);
    }),
  revokeSession: ({ tokenHash, now }) =>
    Effect.suspend(() => {
      const session = state.sessionsByHash.get(tokenKey(tokenHash));
      if (!session) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
      state.sessionsByHash.set(tokenKey(tokenHash), {
        ...session,
        revokedAt: now,
        updatedAt: now,
      });
      return Effect.void;
    }),
  revokeOtherSessions: ({ userId, currentSessionId, now }) =>
    Effect.sync(() => {
      for (const [key, session] of state.sessionsByHash) {
        if (session.userId === userId && session.id !== currentSessionId) {
          state.sessionsByHash.set(key, { ...session, revokedAt: now, updatedAt: now });
        }
      }
    }),
  revokeAllUserSessions: ({ userId, now }) =>
    Effect.sync(() => {
      for (const [key, session] of state.sessionsByHash) {
        if (session.userId === userId)
          state.sessionsByHash.set(key, { ...session, revokedAt: now, updatedAt: now });
      }
    }),
  updatePasswordHash: ({ userId, passwordHash, now }) =>
    Effect.suspend(() => {
      const entry = Array.from(state.credentialsByEmail.entries()).find(
        ([, credential]) => credential.userId === userId,
      );
      if (!entry) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
      const [email, credential] = entry;
      state.credentialsByEmail.set(email, { ...credential, passwordHash, updatedAt: now });
      return Effect.void;
    }),
});

export const DevMemoryAuthStorage = (state?: DevMemoryStorageState) =>
  Layer.succeed(AuthStorage)(makeDevMemoryStorage(state));
