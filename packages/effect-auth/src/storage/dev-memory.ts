import { Clock, Effect, Layer, Match, Redacted } from "effect";
import type {
  OAuthProviderId,
  OAuthStateHash,
  ProtectedProviderTokenSet,
  StoredOAuthState,
} from "../oauth/index.js";
import type { TokenHash } from "../token/index.js";
import {
  AuthStorage,
  AuthStorageFailure,
  OAuthAccountStorageFailure,
  type AuthAccount,
  type CredentialAuthAccount,
  type AuthStorageShape,
  type AuthUser,
  type AuthUserId,
  type OAuthProviderAccount,
  type PublicAuthAccount,
  type StoredSession,
} from "./index.js";

interface TokenRecord {
  readonly userId: AuthUserId;
  readonly email: AuthUser["email"];
  readonly purpose: "EmailVerification" | "PasswordReset";
  readonly tokenHash: TokenHash;
  readonly expiresAt: number;
  consumedAt?: number;
}

export interface DevMemoryStorageState {
  readonly users: Map<AuthUserId, AuthUser>;
  readonly accountsByEmail: Map<string, CredentialAuthAccount>;
  readonly tokensByHash: Map<string, TokenRecord>;
  readonly sessionsByHash: Map<string, StoredSession>;
  readonly oauthStatesByHash: Map<string, StoredOAuthState>;
  readonly providerAccountsByKey: Map<string, OAuthProviderAccount>;
}

export const makeDevMemoryStorageState = (): DevMemoryStorageState => ({
  users: new Map(),
  accountsByEmail: new Map(),
  tokensByHash: new Map(),
  sessionsByHash: new Map(),
  oauthStatesByHash: new Map(),
  providerAccountsByKey: new Map(),
});

let nextId = 0;
const id = (prefix: string) => `${prefix}_${++nextId}`;
const tokenKey = (hash: TokenHash) => Redacted.value(hash);
const oauthStateKey = (hash: OAuthStateHash) => Redacted.value(hash);
const providerAccountKey = (providerId: OAuthProviderId, accountId: string) =>
  `${String(providerId)}:${accountId}`;

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
    const account = state.accountsByEmail.get(String(record.email));
    const user = account ? state.users.get(account.userId) : undefined;
    return account && user
      ? Effect.succeed({ user, account })
      : Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
  });

const consumeVerificationToken = (
  state: DevMemoryStorageState,
  { purpose, tokenHash, now }: Parameters<AuthStorageShape["consumeVerificationToken"]>[0],
) =>
  findUsableVerificationToken(state, { purpose, tokenHash, now }).pipe(
    Effect.flatMap(({ user, account }) =>
      Effect.suspend(() => {
        const record = state.tokensByHash.get(tokenKey(tokenHash));
        if (!record) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
        record.consumedAt = now;
        const consumedUser =
          purpose === "EmailVerification" ? { ...user, emailVerified: true, updatedAt: now } : user;
        state.users.set(user.id, consumedUser);
        return Effect.succeed({ user: consumedUser, account });
      }),
    ),
  );

const updateCredentialAccountPasswordHash = (
  state: DevMemoryStorageState,
  {
    userId,
    passwordHash,
    now,
  }: Parameters<AuthStorageShape["updateCredentialAccountPasswordHash"]>[0],
) =>
  Effect.suspend(() => {
    const entry = Array.from(state.accountsByEmail.entries()).find(
      ([, account]) => account.userId === userId,
    );
    if (!entry) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    const [email, account] = entry;
    state.accountsByEmail.set(email, { ...account, passwordHash, updatedAt: now });
    return Effect.void;
  });

const publicAccount = (account: AuthAccount): PublicAuthAccount => ({
  id: account.id,
  providerId: account.providerId,
  accountId: account.accountId,
  userId: account.userId,
  scopes: account.scopes,
  createdAt: account.createdAt,
  updatedAt: account.updatedAt,
});

const findUserByEmail = (state: DevMemoryStorageState, email: AuthUser["email"]) =>
  Array.from(state.users.values()).find((user) => user.email === email);

const mergeProtectedTokens = (
  previous: ProtectedProviderTokenSet | undefined,
  next: ProtectedProviderTokenSet,
): ProtectedProviderTokenSet => {
  const accessToken = next.accessToken ?? previous?.accessToken;
  const refreshToken = next.refreshToken ?? previous?.refreshToken;
  const idToken = next.idToken ?? previous?.idToken;
  const tokenType = next.tokenType ?? previous?.tokenType;
  const scope = next.scope ?? previous?.scope;
  const accessTokenExpiresAt = next.accessTokenExpiresAt ?? previous?.accessTokenExpiresAt;
  const refreshTokenExpiresAt = next.refreshTokenExpiresAt ?? previous?.refreshTokenExpiresAt;
  return {
    ...(accessToken === undefined ? {} : { accessToken }),
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(idToken === undefined ? {} : { idToken }),
    ...(tokenType === undefined ? {} : { tokenType }),
    ...(scope === undefined ? {} : { scope }),
    ...(accessTokenExpiresAt === undefined ? {} : { accessTokenExpiresAt }),
    ...(refreshTokenExpiresAt === undefined ? {} : { refreshTokenExpiresAt }),
  };
};

const makeOAuthProviderAccount = (input: {
  readonly providerId: OAuthProviderId;
  readonly providerAccountId: string;
  readonly userId: AuthUserId;
  readonly scopes: ReadonlyArray<string>;
  readonly providerTokens: ProtectedProviderTokenSet;
  readonly now: number;
}): OAuthProviderAccount => ({
  id: id("acc"),
  providerId: input.providerId,
  accountId: input.providerAccountId,
  userId: input.userId,
  scopes: input.scopes,
  providerTokens: input.providerTokens,
  createdAt: input.now,
  updatedAt: input.now,
});

const updateOAuthProviderAccount = (
  account: OAuthProviderAccount,
  input: {
    readonly scopes: ReadonlyArray<string>;
    readonly providerTokens: ProtectedProviderTokenSet;
    readonly now: number;
  },
): OAuthProviderAccount => ({
  ...account,
  scopes: input.scopes,
  providerTokens: mergeProtectedTokens(account.providerTokens, input.providerTokens),
  updatedAt: input.now,
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

const deleteUser = (
  state: DevMemoryStorageState,
  { userId }: Parameters<AuthStorageShape["deleteUser"]>[0],
) =>
  Effect.suspend(() => {
    if (!state.users.has(userId))
      return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    state.users.delete(userId);
    for (const [email, account] of state.accountsByEmail) {
      if (account.userId === userId) state.accountsByEmail.delete(email);
    }
    for (const [key, token] of state.tokensByHash) {
      if (token.userId === userId) state.tokensByHash.delete(key);
    }
    for (const [key, session] of state.sessionsByHash) {
      if (session.userId === userId) state.sessionsByHash.delete(key);
    }
    for (const [key, oauthState] of state.oauthStatesByHash) {
      if (oauthState.linkUserId === userId) state.oauthStatesByHash.delete(key);
    }
    for (const [key, account] of state.providerAccountsByKey) {
      if (account.userId === userId) state.providerAccountsByKey.delete(key);
    }
    return Effect.void;
  });

export const makeDevMemoryStorage = (state = makeDevMemoryStorageState()): AuthStorageShape => ({
  createUserWithCredentialAccount: ({ email, name, image, passwordHash, now }) =>
    Effect.suspend(() => {
      if (state.accountsByEmail.has(String(email)))
        return Effect.fail(new AuthStorageFailure({ reason: "Conflict" }));
      const user: AuthUser = {
        id: id("usr"),
        email,
        name,
        image,
        emailVerified: false,
        createdAt: now,
        updatedAt: now,
      };
      const account: CredentialAuthAccount = {
        id: id("acc"),
        providerId: "credential",
        accountId: user.id,
        userId: user.id,
        scopes: [],
        passwordHash,
        createdAt: now,
        updatedAt: now,
      };
      state.users.set(user.id, user);
      state.accountsByEmail.set(String(email), account);
      return Effect.succeed(user);
    }),
  findCredentialAccountByEmail: (email) =>
    Effect.suspend(() => {
      const account = state.accountsByEmail.get(String(email));
      const user = account ? state.users.get(account.userId) : undefined;
      return account && user
        ? Effect.succeed({ user, account })
        : Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
    }),
  updateUser: ({ userId, name, image, now }) =>
    Effect.suspend(() => {
      const user = state.users.get(userId);
      if (!user) return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
      const updated = {
        ...user,
        ...(name === undefined ? {} : { name }),
        ...(image === undefined ? {} : { image }),
        updatedAt: now,
      };
      state.users.set(userId, updated);
      return Effect.succeed(updated);
    }),
  listUserAccounts: ({ userId }) =>
    Effect.sync(() =>
      [
        ...Array.from(state.accountsByEmail.values()),
        ...Array.from(state.providerAccountsByKey.values()),
      ]
        .filter((account) => account.userId === userId)
        .sort((left, right) => left.createdAt - right.createdAt || left.id.localeCompare(right.id))
        .map(publicAccount),
    ),
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
  updateCredentialAccountPasswordHash: (input) => updateCredentialAccountPasswordHash(state, input),
  completePasswordReset: ({ token, passwordHash }) =>
    consumeVerificationToken(state, token).pipe(
      Effect.flatMap(({ user }) =>
        updateCredentialAccountPasswordHash(state, {
          userId: user.id,
          passwordHash,
          now: token.now,
        }).pipe(
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
    updateCredentialAccountPasswordHash(state, password).pipe(
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
  deleteUser: (input) => deleteUser(state, input),
  storeOAuthState: (input) =>
    Effect.suspend(() => {
      const key = oauthStateKey(input.stateHash);
      if (state.oauthStatesByHash.has(key)) {
        return Effect.fail(new AuthStorageFailure({ reason: "Conflict" }));
      }
      const stored: StoredOAuthState = {
        id: id("ost"),
        stateHash: input.stateHash,
        providerId: input.providerId,
        flow: input.flow,
        redirectUri: input.redirectUri,
        scopes: input.scopes,
        allowSignUp: input.allowSignUp,
        ...(input.linkUserId === undefined ? {} : { linkUserId: input.linkUserId }),
        ...(input.encryptedCodeVerifier === undefined
          ? {}
          : { encryptedCodeVerifier: input.encryptedCodeVerifier }),
        ...(input.encryptedNonce === undefined ? {} : { encryptedNonce: input.encryptedNonce }),
        createdAt: input.now,
        expiresAt: input.expiresAt,
      };
      state.oauthStatesByHash.set(key, stored);
      return Effect.succeed(stored);
    }),
  consumeOAuthState: ({ stateHash, providerId, flow, now }) =>
    Effect.suspend(() => {
      const key = oauthStateKey(stateHash);
      const stored = state.oauthStatesByHash.get(key);
      if (stored === undefined || stored.providerId !== providerId || stored.flow !== flow) {
        return Effect.fail(new AuthStorageFailure({ reason: "NotFound" }));
      }
      if (stored.consumedAt !== undefined) {
        return Effect.fail(new AuthStorageFailure({ reason: "TokenConsumed" }));
      }
      if (stored.expiresAt <= now) {
        return Effect.fail(new AuthStorageFailure({ reason: "TokenExpired" }));
      }
      const consumed = { ...stored, consumedAt: now };
      state.oauthStatesByHash.set(key, consumed);
      return Effect.succeed(consumed);
    }),
  completeOAuthSignIn: (input) =>
    Effect.suspend((): ReturnType<AuthStorageShape["completeOAuthSignIn"]> => {
      const key = providerAccountKey(input.providerId, input.providerAccountId);
      const existingAccount = state.providerAccountsByKey.get(key);
      if (existingAccount !== undefined) {
        const user = state.users.get(existingAccount.userId);
        if (user === undefined) {
          return Effect.fail(new AuthStorageFailure({ reason: "BackendUnavailable" }));
        }
        const updatedAccount = updateOAuthProviderAccount(existingAccount, input);
        state.providerAccountsByKey.set(key, updatedAccount);
        return Effect.succeed({ user, account: updatedAccount, isNewUser: false });
      }

      const existingUser = findUserByEmail(state, input.email);
      if (existingUser !== undefined && !input.allowAutomaticSameEmailLinking) {
        return Effect.fail(
          new OAuthAccountStorageFailure({ reason: "AutomaticLinkingNotAllowed" }),
        );
      }
      if (existingUser !== undefined) {
        const account = makeOAuthProviderAccount({ ...input, userId: existingUser.id });
        state.providerAccountsByKey.set(key, account);
        return Effect.succeed({ user: existingUser, account, isNewUser: false });
      }
      if (!input.allowImplicitSignUp) {
        return Effect.fail(new OAuthAccountStorageFailure({ reason: "ImplicitSignUpDisabled" }));
      }

      const user: AuthUser = {
        id: id("usr"),
        email: input.email,
        name: input.name,
        image: input.image,
        emailVerified: input.emailVerified,
        createdAt: input.now,
        updatedAt: input.now,
      };
      const account = makeOAuthProviderAccount({ ...input, userId: user.id });
      state.users.set(user.id, user);
      state.providerAccountsByKey.set(key, account);
      return Effect.succeed({ user, account, isNewUser: true });
    }),
  completeOAuthLink: (input) =>
    Effect.suspend((): ReturnType<AuthStorageShape["completeOAuthLink"]> => {
      const user = state.users.get(input.userId);
      if (user === undefined) {
        return Effect.fail(new OAuthAccountStorageFailure({ reason: "LinkUserNotFound" }));
      }
      const key = providerAccountKey(input.providerId, input.providerAccountId);
      const existingAccount = state.providerAccountsByKey.get(key);
      if (existingAccount !== undefined && existingAccount.userId !== input.userId) {
        return Effect.fail(
          new OAuthAccountStorageFailure({ reason: "ProviderAccountLinkedToDifferentUser" }),
        );
      }
      if (user.email !== input.providerEmail && !input.allowDifferentEmail) {
        return Effect.fail(new OAuthAccountStorageFailure({ reason: "LinkEmailMismatch" }));
      }
      if (existingAccount !== undefined) {
        const updatedAccount = updateOAuthProviderAccount(existingAccount, input);
        state.providerAccountsByKey.set(key, updatedAccount);
        return Effect.succeed({ user, account: updatedAccount, isNewUser: false });
      }
      const account = makeOAuthProviderAccount({ ...input, userId: input.userId });
      state.providerAccountsByKey.set(key, account);
      return Effect.succeed({ user, account, isNewUser: false });
    }),
});

export const DevMemoryAuthStorage = (state?: DevMemoryStorageState) =>
  Layer.succeed(AuthStorage)(makeDevMemoryStorage(state));
