import { Context, Effect, Schema } from "effect";
import type { NormalizedEmail } from "../domain/index.js";
import type { ConsumeOAuthState, StoreOAuthState, StoredOAuthState } from "../oauth/index.js";
import type { PasswordHash } from "../password/index.js";
import type { TokenHash } from "../token/index.js";

export type AuthUserId = string;
export type AccountId = string;
export type SessionId = string;

export interface AuthUser {
  readonly id: AuthUserId;
  readonly email: NormalizedEmail;
  readonly name: string;
  readonly image: string | null;
  readonly emailVerified: boolean;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface AuthAccount {
  readonly id: AccountId;
  readonly providerId: "credential";
  readonly accountId: string;
  readonly userId: AuthUserId;
  readonly scopes: ReadonlyArray<string>;
  readonly passwordHash?: PasswordHash;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface CredentialAuthAccount extends AuthAccount {
  readonly passwordHash: PasswordHash;
}

export interface PublicAuthAccount {
  readonly id: AccountId;
  readonly providerId: "credential";
  readonly accountId: string;
  readonly userId: AuthUserId;
  readonly scopes: ReadonlyArray<string>;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface CredentialAccountLookup {
  readonly user: AuthUser;
  readonly account: CredentialAuthAccount;
}

export type VerificationTokenPurpose = "EmailVerification" | "PasswordReset";

export interface CreateUserWithCredentialAccount {
  readonly email: NormalizedEmail;
  readonly name: string;
  readonly image: null;
  readonly passwordHash: PasswordHash;
  readonly now: number;
}

export interface StoreVerificationToken {
  readonly userId: AuthUserId;
  readonly email: NormalizedEmail;
  readonly purpose: VerificationTokenPurpose;
  readonly tokenHash: TokenHash;
  readonly expiresAt: number;
  readonly now: number;
}

export interface ConsumeVerificationToken {
  readonly purpose: VerificationTokenPurpose;
  readonly tokenHash: TokenHash;
  readonly now: number;
}

export interface VerificationTokenLookup {
  readonly user: AuthUser;
  readonly account: CredentialAuthAccount;
}

export interface CreateSession {
  readonly userId: AuthUserId;
  readonly tokenHash: TokenHash;
  readonly expiresAt: number;
  readonly now: number;
  readonly ipAddress?: string;
  readonly userAgent?: string;
}

export interface StoredSession {
  readonly id: SessionId;
  readonly userId: AuthUserId;
  readonly tokenHash: TokenHash;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly expiresAt: number;
  readonly revokedAt?: number;
  readonly ipAddress?: string;
  readonly userAgent?: string;
}

export interface StoredSessionLookup {
  readonly session: StoredSession;
  readonly user: AuthUser;
}

export interface RotateSessionToken {
  readonly previousHash: TokenHash;
  readonly nextHash: TokenHash;
  readonly expiresAt: number;
  readonly now: number;
}

export interface RevokeSession {
  readonly tokenHash: TokenHash;
  readonly now: number;
}

export interface ListUserSessions {
  readonly userId: AuthUserId;
  readonly now: number;
}

export interface RevokeUserSession {
  readonly userId: AuthUserId;
  readonly sessionId: SessionId;
  readonly now: number;
}

export interface RevokeOtherSessions {
  readonly userId: AuthUserId;
  readonly currentSessionId: SessionId;
  readonly now: number;
}

export interface RevokeAllUserSessions {
  readonly userId: AuthUserId;
  readonly now: number;
}

export interface UpdateCredentialAccountPasswordHash {
  readonly userId: AuthUserId;
  readonly passwordHash: PasswordHash;
  readonly now: number;
}

export interface UpdateUserStorageInput {
  readonly userId: AuthUserId;
  readonly name?: string;
  readonly image?: string | null;
  readonly now: number;
}

export interface CompletePasswordReset {
  readonly token: ConsumeVerificationToken;
  readonly passwordHash: PasswordHash;
}

export interface ChangePasswordSession {
  readonly password: UpdateCredentialAccountPasswordHash;
  readonly currentSessionId: SessionId;
  readonly previousSessionTokenHash: TokenHash;
  readonly nextSessionTokenHash: TokenHash;
  readonly sessionExpiresAt: number;
}

export interface DeleteUserStorageInput {
  readonly userId: AuthUserId;
}

export class AuthStorageFailure extends Schema.TaggedErrorClass<AuthStorageFailure>()(
  "AuthStorageFailure",
  {
    reason: Schema.Literals([
      "Conflict",
      "NotFound",
      "TokenExpired",
      "TokenConsumed",
      "SessionExpired",
      "BackendUnavailable",
    ]),
  },
) {}

export class AuthStorage extends Context.Service<
  AuthStorage,
  {
    readonly createUserWithCredentialAccount: (
      input: CreateUserWithCredentialAccount,
    ) => Effect.Effect<AuthUser, AuthStorageFailure>;
    readonly findCredentialAccountByEmail: (
      email: NormalizedEmail,
    ) => Effect.Effect<CredentialAccountLookup, AuthStorageFailure>;
    readonly updateUser: (
      input: UpdateUserStorageInput,
    ) => Effect.Effect<AuthUser, AuthStorageFailure>;
    readonly listUserAccounts: (input: {
      readonly userId: AuthUserId;
    }) => Effect.Effect<ReadonlyArray<PublicAuthAccount>, AuthStorageFailure>;
    readonly storeVerificationToken: (
      input: StoreVerificationToken,
    ) => Effect.Effect<void, AuthStorageFailure>;
    readonly findVerificationToken: (
      input: ConsumeVerificationToken,
    ) => Effect.Effect<VerificationTokenLookup, AuthStorageFailure>;
    readonly consumeVerificationToken: (
      input: ConsumeVerificationToken,
    ) => Effect.Effect<VerificationTokenLookup, AuthStorageFailure>;
    readonly createSession: (
      input: CreateSession,
    ) => Effect.Effect<StoredSession, AuthStorageFailure>;
    readonly findSessionByTokenHash: (
      hash: TokenHash,
    ) => Effect.Effect<StoredSessionLookup, AuthStorageFailure>;
    readonly rotateSessionToken: (
      input: RotateSessionToken,
    ) => Effect.Effect<StoredSession, AuthStorageFailure>;
    readonly revokeSession: (input: RevokeSession) => Effect.Effect<void, AuthStorageFailure>;
    readonly listUserSessions: (
      input: ListUserSessions,
    ) => Effect.Effect<ReadonlyArray<StoredSession>, AuthStorageFailure>;
    readonly revokeUserSession: (
      input: RevokeUserSession,
    ) => Effect.Effect<void, AuthStorageFailure>;
    readonly revokeOtherSessions: (
      input: RevokeOtherSessions,
    ) => Effect.Effect<void, AuthStorageFailure>;
    readonly revokeAllUserSessions: (
      input: RevokeAllUserSessions,
    ) => Effect.Effect<void, AuthStorageFailure>;
    readonly updateCredentialAccountPasswordHash: (
      input: UpdateCredentialAccountPasswordHash,
    ) => Effect.Effect<void, AuthStorageFailure>;
    readonly completePasswordReset: (
      input: CompletePasswordReset,
    ) => Effect.Effect<void, AuthStorageFailure>;
    readonly changePasswordSession: (
      input: ChangePasswordSession,
    ) => Effect.Effect<StoredSession, AuthStorageFailure>;
    readonly deleteUser: (input: DeleteUserStorageInput) => Effect.Effect<void, AuthStorageFailure>;
    readonly storeOAuthState: (
      input: StoreOAuthState,
    ) => Effect.Effect<StoredOAuthState, AuthStorageFailure>;
    readonly consumeOAuthState: (
      input: ConsumeOAuthState,
    ) => Effect.Effect<StoredOAuthState, AuthStorageFailure>;
  }
>()("effect-auth/AuthStorage") {}
export type AuthStorageShape = typeof AuthStorage.Service;
