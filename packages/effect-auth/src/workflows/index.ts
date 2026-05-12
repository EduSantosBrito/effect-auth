import { Clock, Context, Data, Duration, Effect, Layer, Match } from "effect";
import {
  AuthBoundary,
  BoundaryParseError,
  emailNotVerified,
  invalidCredentials,
  invalidToken,
  rateLimited,
  unauthorized,
  type CallbackUrl,
  type ClientIp,
  type NormalizedEmail,
  type PasswordText,
  type PublicAuthError,
} from "../domain/index.js";
import { AuthEmail, type AuthEmailFailure } from "../email/index.js";
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
  type SessionId,
  type StoredSession,
} from "../storage/index.js";
import {
  AuthToken,
  type SessionToken,
  type TokenGenerationFailure,
  type VerificationToken,
} from "../token/index.js";

export interface VerificationTokenConfigInput {
  readonly emailVerificationTtl?: Duration.Input;
  readonly passwordResetTtl?: Duration.Input;
}

export interface VerificationTokenConfigShape {
  readonly emailVerificationTtlMillis: number;
  readonly passwordResetTtlMillis: number;
}

export interface SessionPolicyInput {
  readonly sessionTtl?: Duration.Input;
  readonly sessionUpdateAge?: Duration.Input;
}

export interface SessionPolicyShape {
  readonly sessionTtlMillis: number;
  readonly sessionUpdateAgeMillis: number;
}

const positiveFiniteDurationMillis = (
  input: Duration.Input,
  field: string,
): Effect.Effect<number, BoundaryParseError> => {
  const millis = Duration.toMillis(input);
  return Match.value(Number.isFinite(millis) && millis > 0).pipe(
    Match.when(true, () => Effect.succeed(millis)),
    Match.orElse(() =>
      Effect.fail(new BoundaryParseError({ field, reason: "Expected positive finite duration" })),
    ),
  );
};

const verificationTokenConfigFromInput = (
  input: VerificationTokenConfigInput = {},
): VerificationTokenConfigShape => ({
  emailVerificationTtlMillis: Duration.toMillis(input.emailVerificationTtl ?? Duration.days(1)),
  passwordResetTtlMillis: Duration.toMillis(input.passwordResetTtl ?? Duration.minutes(15)),
});

const defaultSessionPolicy: SessionPolicyShape = {
  sessionTtlMillis: Duration.toMillis(Duration.days(7)),
  sessionUpdateAgeMillis: Duration.toMillis(Duration.days(1)),
};

const sessionPolicyFromInput: (
  input?: SessionPolicyInput,
) => Effect.Effect<SessionPolicyShape, BoundaryParseError> = Effect.fn("sessionPolicyFromInput")(
  (input = {}) =>
    Effect.gen(function* () {
      const sessionTtlMillis = yield* positiveFiniteDurationMillis(
        input.sessionTtl ?? Duration.days(7),
        "sessionTtl",
      );
      const sessionUpdateAgeMillis = yield* positiveFiniteDurationMillis(
        input.sessionUpdateAge ?? Duration.days(1),
        "sessionUpdateAge",
      );
      return { sessionTtlMillis, sessionUpdateAgeMillis };
    }),
);

export const VerificationTokenConfig = Context.Reference<VerificationTokenConfigShape>(
  "effect-auth/VerificationTokenConfig",
  { defaultValue: verificationTokenConfigFromInput },
);

export const VerificationTokenConfigLive = (input: VerificationTokenConfigInput = {}) =>
  Layer.succeed(VerificationTokenConfig)(verificationTokenConfigFromInput(input));

export const SessionPolicy = Context.Reference<SessionPolicyShape>("effect-auth/SessionPolicy", {
  defaultValue: () => defaultSessionPolicy,
});

export const SessionPolicyLive = (input: SessionPolicyInput = {}) =>
  Layer.effect(SessionPolicy)(sessionPolicyFromInput(input));

const genericFromStorageToken = (error: AuthStorageFailureType): PublicAuthError =>
  error.reason === "TokenExpired" || error.reason === "TokenConsumed" || error.reason === "NotFound"
    ? invalidToken
    : unauthorized;
const genericRateLimit = (_: RateLimitExceeded): PublicAuthError => rateLimited;
const rateAttempt = (
  bucket: RateLimitExceeded["bucket"],
  email?: NormalizedEmail,
  ip?: ClientIp,
) => ({
  bucket,
  ...(email === undefined ? {} : { email }),
  ...(ip === undefined ? {} : { ip }),
});

export interface SignUpInput {
  readonly email: NormalizedEmail;
  readonly password: PasswordText;
  readonly verificationCallbackUrl: CallbackUrl;
  readonly ip?: ClientIp;
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
  readonly verificationCallbackUrl: unknown;
  readonly ip?: ClientIp;
}

export interface SignInInput {
  readonly email: NormalizedEmail;
  readonly password: PasswordText;
  readonly ip?: ClientIp;
  readonly userAgent?: string;
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

export interface ListedSession {
  readonly id: SessionId;
  readonly userId: AuthUser["id"];
  readonly createdAt: number;
  readonly updatedAt: number;
  readonly expiresAt: number;
  readonly isCurrent: boolean;
  readonly ipAddress?: string;
  readonly userAgent?: string;
}

export interface ListSessionsInput {
  readonly sessionToken: SessionToken;
}

export interface ListSessionsResult {
  readonly user: AuthUser;
  readonly sessions: ReadonlyArray<ListedSession>;
  readonly tokenRotation: TokenRotationDecision;
}

export interface RevokeUserSessionInput {
  readonly sessionToken: SessionToken;
  readonly sessionId: SessionId;
}

export interface SignOutInput {
  readonly sessionToken: SessionToken;
}

export interface RequestPasswordResetInput {
  readonly email: NormalizedEmail;
  readonly resetCallbackUrl: CallbackUrl;
  readonly ip?: ClientIp;
}

export interface ResetPasswordInput {
  readonly token: VerificationToken;
  readonly password: PasswordText;
}

export interface ChangePasswordInput {
  readonly sessionToken: SessionToken;
  readonly currentPassword: PasswordText;
  readonly newPassword: PasswordText;
  readonly ip?: ClientIp;
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
  readonly listSessions: (
    input: ListSessionsInput,
  ) => Effect.Effect<
    ListSessionsResult,
    PublicAuthError | AuthStorageFailureType | TokenGenerationFailure
  >;
  readonly revokeSession: (
    input: RevokeUserSessionInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailureType | TokenGenerationFailure>;
  readonly revokeOtherSessions: (
    input: SignOutInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailureType | TokenGenerationFailure>;
  readonly revokeSessions: (
    input: SignOutInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailureType | TokenGenerationFailure>;
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
    readonly listSessions: SessionWorkflowsShape["listSessions"];
    readonly revokeSession: SessionWorkflowsShape["revokeSession"];
    readonly revokeOtherSessions: SessionWorkflowsShape["revokeOtherSessions"];
    readonly revokeSessions: SessionWorkflowsShape["revokeSessions"];
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
    const tokenConfig = yield* VerificationTokenConfig;
    const sessionPolicy = yield* SessionPolicy;

    const signUp: EmailPasswordWorkflowsShape["signUp"] = Effect.fn("EmailPassword.signUp")(
      function* (input) {
        yield* limiter
          .check(rateAttempt("SignUp", input.email, input.ip))
          .pipe(Effect.mapError(genericRateLimit));
        yield* policy.validate({ email: input.email, password: input.password });
        const passwordHash = yield* hasher.hash(input.password);
        const now = yield* Clock.currentTimeMillis;
        const user = yield* storage.createUserWithEmailPasswordCredential({
          email: input.email,
          passwordHash,
          now,
        });
        const pair = yield* token.makeVerificationToken();
        yield* storage.storeVerificationToken({
          userId: user.id,
          email: input.email,
          purpose: "EmailVerification",
          tokenHash: pair.hash,
          expiresAt: now + tokenConfig.emailVerificationTtlMillis,
          now,
        });
        yield* email.sendEmailVerification({
          to: input.email,
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
      const verificationCallbackUrl: CallbackUrl = yield* boundary.parseCallbackUrl(
        input.verificationCallbackUrl,
      );
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
        expiresAt: now + tokenConfig.emailVerificationTtlMillis,
        now,
      });
      yield* email.sendEmailVerification({
        to: parsedEmail,
        token: pair.token,
        callbackUrl: verificationCallbackUrl,
      });
    });

    const signIn: EmailPasswordWorkflowsShape["signIn"] = Effect.fn("EmailPassword.signIn")(
      function* (input) {
        yield* limiter
          .check(rateAttempt("SignIn", input.email, input.ip))
          .pipe(Effect.mapError(genericRateLimit));
        const lookup = yield* storage
          .findCredentialByEmail(input.email)
          .pipe(Effect.catchTag("AuthStorageFailure", () => Effect.succeed(null)));
        if (!lookup) {
          yield* hasher.hash(input.password);
          return yield* invalidCredentials;
        }
        const verified = yield* hasher.verify({
          password: input.password,
          hash: lookup.credential.passwordHash,
        });
        if (!verified) return yield* invalidCredentials;
        if (!lookup.credential.emailVerified) return yield* emailNotVerified;
        const now = yield* Clock.currentTimeMillis;
        const pair = yield* token.makeSessionToken();
        const session = yield* storage.createSession({
          userId: lookup.user.id,
          tokenHash: pair.hash,
          expiresAt: now + sessionPolicy.sessionTtlMillis,
          now,
          ...(input.ip === undefined ? {} : { ipAddress: input.ip }),
          ...(input.userAgent === undefined ? {} : { userAgent: input.userAgent }),
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
    const sessionPolicy = yield* SessionPolicy;

    const lookupCurrentSession = Effect.fn("Session.lookupCurrentSession")(function* (
      sessionToken: SessionToken,
    ) {
      const hash = yield* token.hashToken(sessionToken);
      const lookup = yield* storage
        .findSessionByTokenHash(hash)
        .pipe(Effect.mapError(() => unauthorized));
      const now = yield* Clock.currentTimeMillis;
      if (lookup.session.updatedAt + sessionPolicy.sessionUpdateAgeMillis <= now) {
        const pair = yield* token.makeSessionToken();
        const session = yield* storage.rotateSessionToken({
          previousHash: hash,
          nextHash: pair.hash,
          expiresAt: now + sessionPolicy.sessionTtlMillis,
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

    const currentSession: SessionWorkflowsShape["currentSession"] = Effect.fn(
      "Session.currentSession",
    )(function* (input) {
      return yield* lookupCurrentSession(input.sessionToken);
    });

    const listSessions: SessionWorkflowsShape["listSessions"] = Effect.fn("Session.listSessions")(
      function* (input) {
        const current = yield* lookupCurrentSession(input.sessionToken);
        const now = yield* Clock.currentTimeMillis;
        const sessions = yield* storage.listUserSessions({ userId: current.user.id, now });
        return {
          user: current.user,
          sessions: sessions.map(
            ({ tokenHash: _tokenHash, revokedAt: _revokedAt, ...session }) => ({
              ...session,
              isCurrent: session.id === current.session.id,
            }),
          ),
          tokenRotation: current.tokenRotation,
        };
      },
    );

    const revokeSession: SessionWorkflowsShape["revokeSession"] = Effect.fn(
      "Session.revokeSession",
    )(function* (input) {
      const current = yield* lookupCurrentSession(input.sessionToken);
      const now = yield* Clock.currentTimeMillis;
      yield* storage
        .revokeUserSession({ userId: current.user.id, sessionId: input.sessionId, now })
        .pipe(Effect.mapError(() => unauthorized));
    });

    const revokeOtherSessions: SessionWorkflowsShape["revokeOtherSessions"] = Effect.fn(
      "Session.revokeOtherSessions",
    )(function* (input) {
      const current = yield* lookupCurrentSession(input.sessionToken);
      const now = yield* Clock.currentTimeMillis;
      yield* storage
        .revokeOtherSessions({
          userId: current.user.id,
          currentSessionId: current.session.id,
          now,
        })
        .pipe(Effect.mapError(() => unauthorized));
    });

    const revokeSessions: SessionWorkflowsShape["revokeSessions"] = Effect.fn(
      "Session.revokeSessions",
    )(function* (input) {
      const current = yield* lookupCurrentSession(input.sessionToken);
      const now = yield* Clock.currentTimeMillis;
      yield* storage
        .revokeAllUserSessions({ userId: current.user.id, now })
        .pipe(Effect.mapError(() => unauthorized));
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

    return {
      currentSession,
      listSessions,
      revokeSession,
      revokeOtherSessions,
      revokeSessions,
      signOut,
    };
  }),
);

export const PasswordRecoveryWorkflowsLive = Layer.effect(PasswordRecoveryWorkflows)(
  Effect.gen(function* () {
    const policy = yield* PasswordPolicy;
    const hasher = yield* PasswordHasher;
    const token = yield* AuthToken;
    const storage = yield* AuthStorage;
    const email = yield* AuthEmail;
    const limiter = yield* RateLimiter;
    const tokenConfig = yield* VerificationTokenConfig;
    const sessionPolicy = yield* SessionPolicy;

    const requestPasswordReset: PasswordRecoveryWorkflowsShape["requestPasswordReset"] = Effect.fn(
      "PasswordRecovery.requestPasswordReset",
    )(function* (input) {
      yield* limiter
        .check(rateAttempt("PasswordReset", input.email, input.ip))
        .pipe(Effect.mapError(genericRateLimit));
      const lookup = yield* storage
        .findCredentialByEmail(input.email)
        .pipe(Effect.catchTag("AuthStorageFailure", () => Effect.succeed(null)));
      if (!lookup) return;
      const now = yield* Clock.currentTimeMillis;
      const pair = yield* token.makeVerificationToken();
      yield* storage.storeVerificationToken({
        userId: lookup.user.id,
        email: input.email,
        purpose: "PasswordReset",
        tokenHash: pair.hash,
        expiresAt: now + tokenConfig.passwordResetTtlMillis,
        now,
      });
      yield* email.sendPasswordReset({
        to: input.email,
        token: pair.token,
        callbackUrl: input.resetCallbackUrl,
      });
    });

    const resetPassword: PasswordRecoveryWorkflowsShape["resetPassword"] = Effect.fn(
      "PasswordRecovery.resetPassword",
    )(function* (input) {
      const hash = yield* token.hashToken(input.token);
      const now = yield* Clock.currentTimeMillis;
      const lookup = yield* storage
        .findVerificationToken({ purpose: "PasswordReset", tokenHash: hash, now })
        .pipe(Effect.mapError(genericFromStorageToken));
      yield* policy.validate({ email: lookup.credential.email, password: input.password });
      const passwordHash = yield* hasher.hash(input.password);
      yield* storage
        .completePasswordReset({
          token: { purpose: "PasswordReset", tokenHash: hash, now },
          passwordHash,
        })
        .pipe(Effect.mapError(genericFromStorageToken));
    });

    const changePassword: PasswordRecoveryWorkflowsShape["changePassword"] = Effect.fn(
      "PasswordRecovery.changePassword",
    )(function* (input) {
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
        password: input.currentPassword,
        hash: credential.credential.passwordHash,
      });
      if (!currentProof) return yield* invalidCredentials;
      yield* policy.validate({ email: credential.credential.email, password: input.newPassword });
      const passwordHash = yield* hasher.hash(input.newPassword);
      const now = yield* Clock.currentTimeMillis;
      const pair = yield* token.makeSessionToken();
      yield* storage.changePasswordSession({
        password: { userId: lookup.user.id, passwordHash, now },
        currentSessionId: lookup.session.id,
        previousSessionTokenHash: sessionHash,
        nextSessionTokenHash: pair.hash,
        sessionExpiresAt: now + sessionPolicy.sessionTtlMillis,
      });
      return { currentSessionToken: pair.token };
    });

    return { requestPasswordReset, resetPassword, changePassword };
  }),
);
