import { Context, Effect, Schema } from "effect";
import type { NormalizedEmail } from "../domain/index.js";
import type { PasswordHash } from "../password/index.js";
import type { TokenHash } from "../token/index.js";

export type AuthUserId = string;
export type CredentialId = string;
export type SessionId = string;

export interface AuthUser {
  readonly id: AuthUserId;
  readonly email: NormalizedEmail;
  readonly createdAt: number;
}

export interface EmailPasswordCredential {
  readonly id: CredentialId;
  readonly userId: AuthUserId;
  readonly email: NormalizedEmail;
  readonly passwordHash: PasswordHash;
  readonly emailVerified: boolean;
  readonly createdAt: number;
  readonly updatedAt: number;
}

export interface EmailPasswordCredentialLookup {
  readonly user: AuthUser;
  readonly credential: EmailPasswordCredential;
}

export type VerificationTokenPurpose = "EmailVerification" | "PasswordReset";

export interface CreateUserWithCredential {
  readonly email: NormalizedEmail;
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
  readonly credential: EmailPasswordCredential;
}

export interface CreateSession {
  readonly userId: AuthUserId;
  readonly tokenHash: TokenHash;
  readonly expiresAt: number;
  readonly now: number;
}

export interface StoredSession {
  readonly id: SessionId;
  readonly userId: AuthUserId;
  readonly tokenHash: TokenHash;
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly expiresAt: number;
  readonly revokedAt?: number;
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

export interface RevokeOtherSessions {
  readonly userId: AuthUserId;
  readonly currentSessionId: SessionId;
  readonly now: number;
}

export interface RevokeAllUserSessions {
  readonly userId: AuthUserId;
  readonly now: number;
}

export interface UpdatePasswordHash {
  readonly userId: AuthUserId;
  readonly passwordHash: PasswordHash;
  readonly now: number;
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

export interface AuthStorageShape {
  readonly createUserWithEmailPasswordCredential: (
    input: CreateUserWithCredential,
  ) => Effect.Effect<AuthUser, AuthStorageFailure>;
  readonly findCredentialByEmail: (
    email: NormalizedEmail,
  ) => Effect.Effect<EmailPasswordCredentialLookup, AuthStorageFailure>;
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
  readonly revokeOtherSessions: (
    input: RevokeOtherSessions,
  ) => Effect.Effect<void, AuthStorageFailure>;
  readonly revokeAllUserSessions: (
    input: RevokeAllUserSessions,
  ) => Effect.Effect<void, AuthStorageFailure>;
  readonly updatePasswordHash: (
    input: UpdatePasswordHash,
  ) => Effect.Effect<void, AuthStorageFailure>;
}

export class AuthStorage extends Context.Service<AuthStorage, AuthStorageShape>()(
  "effect-auth/storage/AuthStorage",
) {}
