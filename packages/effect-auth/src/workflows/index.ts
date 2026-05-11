import { Clock, Context, Data, Effect, Layer } from "effect";
import {
  AuthBoundary,
  emailNotVerified,
  invalidCredentials,
  invalidToken,
  rateLimited,
  unauthorized,
  type BoundaryParseError,
  type NormalizedEmail,
  type PublicAuthError,
} from "../domain/index.js";
import { AuthEmail, type AuthEmailFailure } from "../email/mock.js";
import {
  PasswordHasher,
  PasswordPolicy,
  type PasswordHashFailure,
  type PasswordPolicyFailure,
} from "../password/index.js";
import { RateLimiter, type RateLimitExceeded } from "../rate-limit/index.js";
import {
  AuthStorage,
  type AuthStorageFailure as AuthStorageFailureType,
  type AuthUser,
  type StoredSession,
} from "../storage/index.js";
import {
  AuthToken,
  type SessionToken,
  type TokenGenerationFailure,
  type VerificationToken,
} from "../token/index.js";

const days = (n: number) => n * 24 * 60 * 60 * 1000;
const minutes = (n: number) => n * 60 * 1000;
const genericFromStorageToken = (error: AuthStorageFailureType): PublicAuthError =>
  error.reason === "TokenExpired" || error.reason === "TokenConsumed" || error.reason === "NotFound"
    ? invalidToken
    : unauthorized;
const genericRateLimit = (_: RateLimitExceeded): PublicAuthError => rateLimited;
const rateAttempt = (
  bucket: RateLimitExceeded["bucket"],
  email?: NormalizedEmail,
  ip?: string,
) => ({
  bucket,
  ...(email === undefined ? {} : { email }),
  ...(ip === undefined ? {} : { ip }),
});

export interface SignUpInput {
  readonly email: unknown;
  readonly password: unknown;
  readonly verificationCallbackUrl: URL;
  readonly ip?: string;
}

export interface SignUpResult {
  readonly user: AuthUser;
}

export interface VerifyEmailInput {
  readonly token: VerificationToken;
}

export interface VerifyEmailResult {
  readonly user: AuthUser;
}

export interface ResendVerificationInput {
  readonly email: unknown;
  readonly verificationCallbackUrl: URL;
  readonly ip?: string;
}

export interface SignInInput {
  readonly email: unknown;
  readonly password: unknown;
  readonly ip?: string;
}

export interface SignInResult {
  readonly user: AuthUser;
  readonly session: StoredSession;
  readonly sessionToken: SessionToken;
}

export interface CurrentSessionInput {
  readonly sessionToken: SessionToken;
}

export type TokenRotationDecision = Data.TaggedEnum<{
  Unchanged: {};
  Rotated: { readonly token: SessionToken };
}>;

const TokenRotationDecision = Data.taggedEnum<TokenRotationDecision>();

export interface SessionLookupResult {
  readonly user: AuthUser;
  readonly session: StoredSession;
  readonly tokenRotation: TokenRotationDecision;
}

export interface SignOutInput {
  readonly sessionToken: SessionToken;
}

export interface RequestPasswordResetInput {
  readonly email: unknown;
  readonly resetCallbackUrl: URL;
  readonly ip?: string;
}

export interface ResetPasswordInput {
  readonly token: VerificationToken;
  readonly password: unknown;
}

export interface ChangePasswordInput {
  readonly sessionToken: SessionToken;
  readonly currentPassword: unknown;
  readonly newPassword: unknown;
  readonly ip?: string;
}

export interface ChangePasswordResult {
  readonly currentSessionToken: SessionToken;
}

export interface EmailPasswordWorkflowsShape {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    SignUpResult,
    | PublicAuthError
    | BoundaryParseError
    | PasswordPolicyFailure
    | PasswordHashFailure
    | AuthStorageFailureType
    | TokenGenerationFailure
    | AuthEmailFailure
    | RateLimitExceeded
  >;
  readonly verifyEmail: (
    input: VerifyEmailInput,
  ) => Effect.Effect<
    VerifyEmailResult,
    PublicAuthError | AuthStorageFailureType | TokenGenerationFailure
  >;
  readonly resendVerification: (
    input: ResendVerificationInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | AuthStorageFailureType
    | TokenGenerationFailure
    | AuthEmailFailure
    | RateLimitExceeded
  >;
  readonly signIn: (
    input: SignInInput,
  ) => Effect.Effect<
    SignInResult,
    | PublicAuthError
    | BoundaryParseError
    | PasswordHashFailure
    | AuthStorageFailureType
    | TokenGenerationFailure
    | RateLimitExceeded
  >;
}

export interface SessionWorkflowsShape {
  readonly currentSession: (
    input: CurrentSessionInput,
  ) => Effect.Effect<
    SessionLookupResult,
    PublicAuthError | AuthStorageFailureType | TokenGenerationFailure
  >;
  readonly signOut: (
    input: SignOutInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailureType | TokenGenerationFailure>;
}

export interface PasswordRecoveryWorkflowsShape {
  readonly requestPasswordReset: (
    input: RequestPasswordResetInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | AuthStorageFailureType
    | TokenGenerationFailure
    | AuthEmailFailure
    | RateLimitExceeded
  >;
  readonly resetPassword: (
    input: ResetPasswordInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | PasswordPolicyFailure
    | PasswordHashFailure
    | AuthStorageFailureType
    | TokenGenerationFailure
  >;
  readonly changePassword: (
    input: ChangePasswordInput,
  ) => Effect.Effect<
    ChangePasswordResult,
    | PublicAuthError
    | BoundaryParseError
    | PasswordPolicyFailure
    | PasswordHashFailure
    | AuthStorageFailureType
    | TokenGenerationFailure
    | RateLimitExceeded
  >;
}

export class EmailPasswordWorkflows extends Context.Service<
  EmailPasswordWorkflows,
  {
    readonly signUp: EmailPasswordWorkflowsShape["signUp"];
    readonly verifyEmail: EmailPasswordWorkflowsShape["verifyEmail"];
    readonly resendVerification: EmailPasswordWorkflowsShape["resendVerification"];
    readonly signIn: EmailPasswordWorkflowsShape["signIn"];
  }
>()("effect-auth/EmailPasswordWorkflows") {}
export class SessionWorkflows extends Context.Service<
  SessionWorkflows,
  {
    readonly currentSession: SessionWorkflowsShape["currentSession"];
    readonly signOut: SessionWorkflowsShape["signOut"];
  }
>()("effect-auth/SessionWorkflows") {}
export class PasswordRecoveryWorkflows extends Context.Service<
  PasswordRecoveryWorkflows,
  {
    readonly requestPasswordReset: PasswordRecoveryWorkflowsShape["requestPasswordReset"];
    readonly resetPassword: PasswordRecoveryWorkflowsShape["resetPassword"];
    readonly changePassword: PasswordRecoveryWorkflowsShape["changePassword"];
  }
>()("effect-auth/PasswordRecoveryWorkflows") {}

export const EmailPasswordWorkflowsLive = Layer.effect(EmailPasswordWorkflows)(
  Effect.gen(function* () {
    const boundary = yield* AuthBoundary;
    const policy = yield* PasswordPolicy;
    const hasher = yield* PasswordHasher;
    const token = yield* AuthToken;
    const storage = yield* AuthStorage;
    const email = yield* AuthEmail;
    const limiter = yield* RateLimiter;

    const signUp: EmailPasswordWorkflowsShape["signUp"] = Effect.fn("EmailPassword.signUp")(
      function* (input) {
        const parsedEmail = yield* boundary.parseEmail(input.email);
        const password = yield* boundary.parsePassword(input.password);
        yield* limiter
          .check(rateAttempt("SignUp", parsedEmail, input.ip))
          .pipe(Effect.mapError(genericRateLimit));
        yield* policy.validate({ email: parsedEmail, password });
        const passwordHash = yield* hasher.hash(password);
        const now = yield* Clock.currentTimeMillis;
        const user = yield* storage.createUserWithEmailPasswordCredential({
          email: parsedEmail,
          passwordHash,
          now,
        });
        const pair = yield* token.makeVerificationToken();
        yield* storage.storeVerificationToken({
          userId: user.id,
          email: parsedEmail,
          purpose: "EmailVerification",
          tokenHash: pair.hash,
          expiresAt: now + days(1),
          now,
        });
        yield* email.sendEmailVerification({
          to: parsedEmail,
          token: pair.token,
          callbackUrl: input.verificationCallbackUrl,
        });
        return { user };
      },
    );

    const verifyEmail: EmailPasswordWorkflowsShape["verifyEmail"] = Effect.fn(
      "EmailPassword.verifyEmail",
    )(function* (input) {
      const hash = yield* token.hashToken(input.token);
      const now = yield* Clock.currentTimeMillis;
      const consumed = yield* storage
        .consumeVerificationToken({ purpose: "EmailVerification", tokenHash: hash, now })
        .pipe(Effect.mapError(genericFromStorageToken));
      return { user: consumed.user };
    });

    const resendVerification: EmailPasswordWorkflowsShape["resendVerification"] = Effect.fn(
      "EmailPassword.resendVerification",
    )(function* (input) {
      const parsedEmail = yield* boundary.parseEmail(input.email);
      yield* limiter
        .check(rateAttempt("ResendVerification", parsedEmail, input.ip))
        .pipe(Effect.mapError(genericRateLimit));
      const lookup = yield* storage
        .findCredentialByEmail(parsedEmail)
        .pipe(Effect.mapError(() => invalidCredentials));
      if (lookup.credential.emailVerified) return;
      const now = yield* Clock.currentTimeMillis;
      const pair = yield* token.makeVerificationToken();
      yield* storage.storeVerificationToken({
        userId: lookup.user.id,
        email: parsedEmail,
        purpose: "EmailVerification",
        tokenHash: pair.hash,
        expiresAt: now + days(1),
        now,
      });
      yield* email.sendEmailVerification({
        to: parsedEmail,
        token: pair.token,
        callbackUrl: input.verificationCallbackUrl,
      });
    });

    const signIn: EmailPasswordWorkflowsShape["signIn"] = Effect.fn("EmailPassword.signIn")(
      function* (input) {
        const parsedEmail = yield* boundary.parseEmail(input.email);
        const password = yield* boundary.parsePassword(input.password);
        yield* limiter
          .check(rateAttempt("SignIn", parsedEmail, input.ip))
          .pipe(Effect.mapError(genericRateLimit));
        const lookup = yield* storage
          .findCredentialByEmail(parsedEmail)
          .pipe(Effect.catchTag("AuthStorageFailure", () => Effect.succeed(null)));
        if (!lookup) {
          yield* hasher.hash(password);
          return yield* invalidCredentials;
        }
        const verified = yield* hasher.verify({ password, hash: lookup.credential.passwordHash });
        if (!verified) return yield* invalidCredentials;
        if (!lookup.credential.emailVerified) return yield* emailNotVerified;
        const now = yield* Clock.currentTimeMillis;
        const pair = yield* token.makeSessionToken();
        const session = yield* storage.createSession({
          userId: lookup.user.id,
          tokenHash: pair.hash,
          expiresAt: now + days(7),
          now,
        });
        return { user: lookup.user, session, sessionToken: pair.token };
      },
    );

    return { signUp, verifyEmail, resendVerification, signIn };
  }),
);

export const SessionWorkflowsLive = Layer.effect(SessionWorkflows)(
  Effect.gen(function* () {
    const token = yield* AuthToken;
    const storage = yield* AuthStorage;

    const currentSession: SessionWorkflowsShape["currentSession"] = Effect.fn(
      "Session.currentSession",
    )(function* (input) {
      const hash = yield* token.hashToken(input.sessionToken);
      const lookup = yield* storage
        .findSessionByTokenHash(hash)
        .pipe(Effect.mapError(() => unauthorized));
      const now = yield* Clock.currentTimeMillis;
      if (lookup.session.expiresAt <= now) return yield* unauthorized;
      if (lookup.session.updatedAt + days(1) <= now) {
        const pair = yield* token.makeSessionToken();
        const session = yield* storage.rotateSessionToken({
          previousHash: hash,
          nextHash: pair.hash,
          expiresAt: now + days(7),
          now,
        });
        return {
          user: lookup.user,
          session,
          tokenRotation: TokenRotationDecision.Rotated({ token: pair.token }),
        };
      }
      return {
        user: lookup.user,
        session: lookup.session,
        tokenRotation: TokenRotationDecision.Unchanged(),
      };
    });

    const signOut: SessionWorkflowsShape["signOut"] = Effect.fn("Session.signOut")(
      function* (input) {
        const hash = yield* token.hashToken(input.sessionToken);
        const now = yield* Clock.currentTimeMillis;
        yield* storage
          .revokeSession({ tokenHash: hash, now })
          .pipe(Effect.mapError(() => unauthorized));
      },
    );

    return { currentSession, signOut };
  }),
);

export const PasswordRecoveryWorkflowsLive = Layer.effect(PasswordRecoveryWorkflows)(
  Effect.gen(function* () {
    const boundary = yield* AuthBoundary;
    const policy = yield* PasswordPolicy;
    const hasher = yield* PasswordHasher;
    const token = yield* AuthToken;
    const storage = yield* AuthStorage;
    const email = yield* AuthEmail;
    const limiter = yield* RateLimiter;

    const requestPasswordReset: PasswordRecoveryWorkflowsShape["requestPasswordReset"] = Effect.fn(
      "PasswordRecovery.requestPasswordReset",
    )(function* (input) {
      const parsedEmail = yield* boundary.parseEmail(input.email);
      yield* limiter
        .check(rateAttempt("PasswordReset", parsedEmail, input.ip))
        .pipe(Effect.mapError(genericRateLimit));
      const lookup = yield* storage
        .findCredentialByEmail(parsedEmail)
        .pipe(Effect.catchTag("AuthStorageFailure", () => Effect.succeed(null)));
      if (!lookup) return;
      const now = yield* Clock.currentTimeMillis;
      const pair = yield* token.makeVerificationToken();
      yield* storage.storeVerificationToken({
        userId: lookup.user.id,
        email: parsedEmail,
        purpose: "PasswordReset",
        tokenHash: pair.hash,
        expiresAt: now + minutes(15),
        now,
      });
      yield* email.sendPasswordReset({
        to: parsedEmail,
        token: pair.token,
        callbackUrl: input.resetCallbackUrl,
      });
    });

    const resetPassword: PasswordRecoveryWorkflowsShape["resetPassword"] = Effect.fn(
      "PasswordRecovery.resetPassword",
    )(function* (input) {
      const password = yield* boundary.parsePassword(input.password);
      const hash = yield* token.hashToken(input.token);
      const now = yield* Clock.currentTimeMillis;
      const lookup = yield* storage
        .findVerificationToken({ purpose: "PasswordReset", tokenHash: hash, now })
        .pipe(Effect.mapError(genericFromStorageToken));
      yield* policy.validate({ email: lookup.credential.email, password });
      const passwordHash = yield* hasher.hash(password);
      const consumed = yield* storage
        .consumeVerificationToken({ purpose: "PasswordReset", tokenHash: hash, now })
        .pipe(Effect.mapError(genericFromStorageToken));
      yield* storage.updatePasswordHash({ userId: consumed.user.id, passwordHash, now });
      yield* storage.revokeAllUserSessions({ userId: consumed.user.id, now });
    });

    const changePassword: PasswordRecoveryWorkflowsShape["changePassword"] = Effect.fn(
      "PasswordRecovery.changePassword",
    )(function* (input) {
      const currentPassword = yield* boundary.parsePassword(input.currentPassword);
      const newPassword = yield* boundary.parsePassword(input.newPassword);
      yield* limiter
        .check(rateAttempt("PasswordChange", undefined, input.ip))
        .pipe(Effect.mapError(genericRateLimit));
      const sessionHash = yield* token.hashToken(input.sessionToken);
      const lookup = yield* storage
        .findSessionByTokenHash(sessionHash)
        .pipe(Effect.mapError(() => unauthorized));
      const credential = yield* storage
        .findCredentialByEmail(lookup.user.email)
        .pipe(Effect.mapError(() => unauthorized));
      const currentProof = yield* hasher.verify({
        password: currentPassword,
        hash: credential.credential.passwordHash,
      });
      if (!currentProof) return yield* invalidCredentials;
      yield* policy.validate({ email: credential.credential.email, password: newPassword });
      const passwordHash = yield* hasher.hash(newPassword);
      const now = yield* Clock.currentTimeMillis;
      yield* storage.updatePasswordHash({ userId: lookup.user.id, passwordHash, now });
      yield* storage.revokeOtherSessions({
        userId: lookup.user.id,
        currentSessionId: lookup.session.id,
        now,
      });
      const pair = yield* token.makeSessionToken();
      yield* storage.rotateSessionToken({
        previousHash: sessionHash,
        nextHash: pair.hash,
        expiresAt: now + days(7),
        now,
      });
      return { currentSessionToken: pair.token };
    });

    return { requestPasswordReset, resetPassword, changePassword };
  }),
);
