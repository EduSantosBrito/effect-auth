import { Clock, Effect, Layer, Redacted } from "effect";
import { Email, EmailMessage } from "effect-email";
import { AuthEmail, AuthEmailFailure } from "effect-auth/email";
import {
  AuthStorage,
  AuthStorageFailure,
  type AuthStorageShape,
  type AuthUser,
  type AuthUserId,
  type EmailPasswordCredential,
  type StoredSession,
} from "effect-auth/storage";
import type { TokenHash } from "effect-auth/token";

interface TokenRecord {
  readonly userId: AuthUserId;
  readonly email: EmailPasswordCredential["email"];
  readonly purpose: "EmailVerification" | "PasswordReset";
  readonly tokenHash: TokenHash;
  readonly expiresAt: number;
  consumedAt?: number;
}

export interface ExampleStorageState {
  readonly users: Map<AuthUserId, AuthUser>;
  readonly credentialsByEmail: Map<string, EmailPasswordCredential>;
  readonly tokensByHash: Map<string, TokenRecord>;
  readonly sessionsByHash: Map<string, StoredSession>;
}

export const makeExampleStorageState = (): ExampleStorageState => ({
  users: new Map(),
  credentialsByEmail: new Map(),
  tokensByHash: new Map(),
  sessionsByHash: new Map(),
});

let nextId = 0;
const id = (prefix: string) => `${prefix}_${++nextId}`;
const tokenKey = (hash: TokenHash) => Redacted.value(hash);

const findUsableVerificationToken = (
  state: ExampleStorageState,
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
  state: ExampleStorageState,
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
  state: ExampleStorageState,
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
  state: ExampleStorageState,
  { previousHash, nextHash, expiresAt, now }: Parameters<AuthStorageShape["rotateSessionToken"]>[0],
) =>
  Effect.suspend(() => {
    const session = state.sessionsByHash.get(tokenKey(previousHash));
    if (!session || session.revokedAt !== undefined)
      return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    state.sessionsByHash.delete(tokenKey(previousHash));
    const rotated = { ...session, tokenHash: nextHash, updatedAt: now, expiresAt };
    state.sessionsByHash.set(tokenKey(nextHash), rotated);
    return Effect.succeed(rotated);
  });

const revokeOtherSessions = (
  state: ExampleStorageState,
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

const listUserSessions = (
  state: ExampleStorageState,
  { userId, now }: Parameters<AuthStorageShape["listUserSessions"]>[0],
) =>
  Effect.sync(() =>
    Array.from(state.sessionsByHash.values()).filter(
      (session) => session.userId === userId && isActiveSession(session, now),
    ),
  );

const revokeUserSession = (
  state: ExampleStorageState,
  { userId, sessionId, now }: Parameters<AuthStorageShape["revokeUserSession"]>[0],
) =>
  Effect.suspend(() => {
    const entry = Array.from(state.sessionsByHash.entries()).find(
      ([, session]) => session.id === sessionId && session.userId === userId,
    );
    if (!entry) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    const [key, session] = entry;
    if (!isActiveSession(session, now))
      return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    state.sessionsByHash.set(key, { ...session, revokedAt: now, updatedAt: now });
    return Effect.void;
  });

const revokeAllUserSessions = (
  state: ExampleStorageState,
  { userId, now }: Parameters<AuthStorageShape["revokeAllUserSessions"]>[0],
) =>
  Effect.sync(() => {
    for (const [key, session] of state.sessionsByHash) {
      if (session.userId === userId)
        state.sessionsByHash.set(key, { ...session, revokedAt: now, updatedAt: now });
    }
  });

const makeExampleStorage = (state: ExampleStorageState): AuthStorageShape => ({
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
      const user = session ? state.users.get(session.userId) : undefined;
      if (!session || !user || session.revokedAt !== undefined)
        return yield* new AuthStorageFailure({ reason: "NotFound" });
      if (session.expiresAt <= now)
        return yield* new AuthStorageFailure({ reason: "SessionExpired" });
      return { session, user };
    }),
  rotateSessionToken: (input) => rotateSessionToken(state, input),
  revokeSession: ({ tokenHash, now }) =>
    Effect.suspend(() => {
      const session = state.sessionsByHash.get(tokenKey(tokenHash));
      if (!session) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
      state.sessionsByHash.set(tokenKey(tokenHash), { ...session, revokedAt: now, updatedAt: now });
      return Effect.void;
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

const callbackWithToken = ({
  callbackUrl,
  token,
}: Parameters<typeof AuthEmail.Service.sendEmailVerification>[0]) => {
  const url = new URL(callbackUrl);
  url.searchParams.set("token", Redacted.value(token));
  return url.toString();
};

const mapSendFailure = () => new AuthEmailFailure({ reason: "DeliveryUnavailable" });

const makeAuthEmailMessage = (input: {
  readonly kind: "EmailVerification" | "PasswordReset";
  readonly to: Parameters<typeof AuthEmail.Service.sendEmailVerification>[0]["to"];
  readonly token: Parameters<typeof AuthEmail.Service.sendEmailVerification>[0]["token"];
  readonly callbackUrl: URL;
}) => {
  const url = callbackWithToken(input);
  return EmailMessage.make({
    from: "Effect Auth <auth@example.com>",
    to: String(input.to),
    subject: input.kind === "EmailVerification" ? "Verify your email" : "Reset your password",
    text:
      input.kind === "EmailVerification"
        ? `Verify your email: ${url}`
        : `Reset your password: ${url}`,
  }).pipe(Effect.mapError(mapSendFailure));
};

export const ExampleAuthStorage = (state: ExampleStorageState) =>
  Layer.succeed(AuthStorage)(makeExampleStorage(state));

export const EffectEmailAuthEmail: Layer.Layer<AuthEmail, never, Email> = Layer.effect(
  AuthEmail,
  Effect.gen(function* () {
    const email = yield* Email;
    return AuthEmail.of({
      sendEmailVerification: (input) =>
        makeAuthEmailMessage({ kind: "EmailVerification", ...input }).pipe(
          Effect.flatMap(email.send),
          Effect.mapError(mapSendFailure),
          Effect.asVoid,
        ),
      sendPasswordReset: (input) =>
        makeAuthEmailMessage({ kind: "PasswordReset", ...input }).pipe(
          Effect.flatMap(email.send),
          Effect.mapError(mapSendFailure),
          Effect.asVoid,
        ),
    });
  }).pipe(Effect.annotateLogs("service", "AuthEmail")),
);
