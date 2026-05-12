import { Context, Effect, Layer, Redacted, Schema } from "effect";
import {
  AuthBoundary,
  AuthBoundaryLive,
  BoundaryParseError,
  type ClientIp,
  type PublicAuthError,
} from "./domain/index.js";
import { AuthEmail, type AuthEmailFailure } from "./email/index.js";
import {
  NativeScryptPasswordHasher,
  SecureDefaultPasswordPolicy,
  type PasswordHashFailure,
  type PasswordPolicyFailure,
} from "./password/index.js";
import {
  PermissiveDevRateLimiter,
  RateLimiter,
  type RateLimitExceeded,
} from "./rate-limit/index.js";
import { AuthStorage, type AuthStorageFailure } from "./storage/index.js";
import {
  AuthTokenLive,
  SessionToken,
  VerificationToken,
  type TokenGenerationFailure,
} from "./token/index.js";
import {
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  SessionPolicy,
  SessionWorkflows,
  SessionWorkflowsLive,
  VerificationTokenConfigLive,
  type ChangePasswordInput as ChangePasswordCommand,
  type ChangePasswordResult,
  type CurrentSessionInput as CurrentSessionCommand,
  type ListSessionsInput,
  type ListSessionsResult,
  type RequestPasswordResetInput as RequestPasswordResetCommand,
  type RevokeUserSessionInput as RevokeUserSessionCommand,
  type ResendVerificationInput,
  type ResetPasswordInput as ResetPasswordCommand,
  type SessionLookupResult,
  type SignInInput as SignInCommand,
  type SignInResult,
  type SignOutInput as SignOutCommand,
  type SignUpInput as SignUpCommand,
  type SignUpResult,
  type VerifyEmailInput as VerifyEmailCommand,
  type VerifyEmailResult,
} from "./workflows/index.js";

export interface SignUpInput {
  readonly email: unknown;
  readonly password: unknown;
  readonly verificationCallbackUrl: unknown;
  readonly ip?: unknown;
}

export interface SignInInput {
  readonly email: unknown;
  readonly password: unknown;
  readonly ip?: unknown;
  readonly userAgent?: string;
}

export interface VerifyEmailInput {
  readonly token: unknown;
}

export interface SessionTokenInput {
  readonly sessionToken: unknown;
}

export interface RevokeUserSessionInput {
  readonly sessionToken: unknown;
  readonly sessionId: RevokeUserSessionCommand["sessionId"];
}

export interface RequestPasswordResetInput {
  readonly email: unknown;
  readonly resetCallbackUrl: unknown;
  readonly ip?: unknown;
}

export interface ResetPasswordInput {
  readonly token: unknown;
  readonly password: unknown;
}

export interface ChangePasswordInput {
  readonly sessionToken: unknown;
  readonly currentPassword: unknown;
  readonly newPassword: unknown;
  readonly ip?: unknown;
}

const decodeVerificationToken = Schema.decodeUnknownEffect(VerificationToken);
const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);

const parseVerificationToken = (
  input: unknown,
): Effect.Effect<VerificationToken, BoundaryParseError> =>
  decodeVerificationToken(Redacted.isRedacted(input) ? Redacted.value(input) : input).pipe(
    Effect.mapError(
      () => new BoundaryParseError({ field: "token", reason: "Invalid verification token" }),
    ),
  );

const parseSessionToken = (input: unknown): Effect.Effect<SessionToken, BoundaryParseError> =>
  decodeSessionToken(Redacted.isRedacted(input) ? Redacted.value(input) : input).pipe(
    Effect.mapError(
      () => new BoundaryParseError({ field: "sessionToken", reason: "Invalid session token" }),
    ),
  );

const parseOptionalClientIp = (
  boundary: typeof AuthBoundary.Service,
  input: unknown,
): Effect.Effect<ClientIp | undefined, BoundaryParseError> =>
  input === undefined ? Effect.void.pipe(Effect.as(undefined)) : boundary.parseClientIp(input);

const parseSignUpCommand = Effect.fn("Auth.parseSignUpCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: SignUpInput,
) {
  const email = yield* boundary.parseEmail(input.email);
  const password = yield* boundary.parsePassword(input.password);
  const verificationCallbackUrl = yield* boundary.parseCallbackUrl(input.verificationCallbackUrl);
  const ip = yield* parseOptionalClientIp(boundary, input.ip);
  return {
    email,
    password,
    verificationCallbackUrl,
    ...(ip === undefined ? {} : { ip }),
  } satisfies SignUpCommand;
});

const parseSignInCommand = Effect.fn("Auth.parseSignInCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: SignInInput,
) {
  const email = yield* boundary.parseEmail(input.email);
  const password = yield* boundary.parsePassword(input.password);
  const ip = yield* parseOptionalClientIp(boundary, input.ip);
  return {
    email,
    password,
    ...(ip === undefined ? {} : { ip }),
    ...(input.userAgent === undefined ? {} : { userAgent: input.userAgent }),
  } satisfies SignInCommand;
});

const parseVerifyEmailCommand = Effect.fn("Auth.parseVerifyEmailCommand")(function* (
  input: VerifyEmailInput,
) {
  const token = yield* parseVerificationToken(input.token);
  return { token } satisfies VerifyEmailCommand;
});

const parseRequestPasswordResetCommand = Effect.fn("Auth.parseRequestPasswordResetCommand")(
  function* (boundary: typeof AuthBoundary.Service, input: RequestPasswordResetInput) {
    const email = yield* boundary.parseEmail(input.email);
    const resetCallbackUrl = yield* boundary.parseCallbackUrl(input.resetCallbackUrl);
    const ip = yield* parseOptionalClientIp(boundary, input.ip);
    return {
      email,
      resetCallbackUrl,
      ...(ip === undefined ? {} : { ip }),
    } satisfies RequestPasswordResetCommand;
  },
);

const parseResetPasswordCommand = Effect.fn("Auth.parseResetPasswordCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: ResetPasswordInput,
) {
  const token = yield* parseVerificationToken(input.token);
  const password = yield* boundary.parsePassword(input.password);
  return { token, password } satisfies ResetPasswordCommand;
});

const parseChangePasswordCommand = Effect.fn("Auth.parseChangePasswordCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: ChangePasswordInput,
) {
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  const currentPassword = yield* boundary.parsePassword(input.currentPassword);
  const newPassword = yield* boundary.parsePassword(input.newPassword);
  const ip = yield* parseOptionalClientIp(boundary, input.ip);
  return {
    sessionToken,
    currentPassword,
    newPassword,
    ...(ip === undefined ? {} : { ip }),
  } satisfies ChangePasswordCommand;
});

const parseSessionTokenCommand = Effect.fn("Auth.parseSessionTokenCommand")(function* (
  input: SessionTokenInput,
) {
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  return { sessionToken } satisfies CurrentSessionCommand & ListSessionsInput & SignOutCommand;
});

const parseRevokeUserSessionCommand = Effect.fn("Auth.parseRevokeUserSessionCommand")(function* (
  input: RevokeUserSessionInput,
) {
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  return { sessionToken, sessionId: input.sessionId } satisfies RevokeUserSessionCommand;
});

export interface AuthShape {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    SignUpResult,
    | PublicAuthError
    | BoundaryParseError
    | PasswordPolicyFailure
    | PasswordHashFailure
    | AuthStorageFailure
    | TokenGenerationFailure
    | AuthEmailFailure
    | RateLimitExceeded
  >;
  readonly verifyEmail: (
    input: VerifyEmailInput,
  ) => Effect.Effect<
    VerifyEmailResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly resendVerification: (
    input: ResendVerificationInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | AuthStorageFailure
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
    | AuthStorageFailure
    | TokenGenerationFailure
    | RateLimitExceeded
  >;
  readonly currentSession: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    SessionLookupResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly listSessions: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    ListSessionsResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly revokeSession: (
    input: RevokeUserSessionInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly revokeOtherSessions: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly revokeSessions: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly signOut: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly requestPasswordReset: (
    input: RequestPasswordResetInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | AuthStorageFailure
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
    | AuthStorageFailure
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
    | AuthStorageFailure
    | TokenGenerationFailure
    | RateLimitExceeded
  >;
}

export class Auth extends Context.Service<
  Auth,
  {
    readonly signUp: AuthShape["signUp"];
    readonly verifyEmail: AuthShape["verifyEmail"];
    readonly resendVerification: AuthShape["resendVerification"];
    readonly signIn: AuthShape["signIn"];
    readonly currentSession: AuthShape["currentSession"];
    readonly listSessions: AuthShape["listSessions"];
    readonly revokeSession: AuthShape["revokeSession"];
    readonly revokeOtherSessions: AuthShape["revokeOtherSessions"];
    readonly revokeSessions: AuthShape["revokeSessions"];
    readonly signOut: AuthShape["signOut"];
    readonly requestPasswordReset: AuthShape["requestPasswordReset"];
    readonly resetPassword: AuthShape["resetPassword"];
    readonly changePassword: AuthShape["changePassword"];
  }
>()("effect-auth/Auth") {}

const AuthLiveLayer = Layer.effect(Auth)(
  Effect.gen(function* () {
    const boundary = yield* AuthBoundary;
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;

    return {
      signUp: (input) =>
        parseSignUpCommand(boundary, input).pipe(Effect.flatMap(emailPassword.signUp)),
      verifyEmail: (input) =>
        parseVerifyEmailCommand(input).pipe(Effect.flatMap(emailPassword.verifyEmail)),
      resendVerification: emailPassword.resendVerification,
      signIn: (input) =>
        parseSignInCommand(boundary, input).pipe(Effect.flatMap(emailPassword.signIn)),
      currentSession: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.currentSession)),
      listSessions: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.listSessions)),
      revokeSession: (input) =>
        parseRevokeUserSessionCommand(input).pipe(Effect.flatMap(sessions.revokeSession)),
      revokeOtherSessions: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.revokeOtherSessions)),
      revokeSessions: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.revokeSessions)),
      signOut: (input) => parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.signOut)),
      requestPasswordReset: (input) =>
        parseRequestPasswordResetCommand(boundary, input).pipe(
          Effect.flatMap(recovery.requestPasswordReset),
        ),
      resetPassword: (input) =>
        parseResetPasswordCommand(boundary, input).pipe(Effect.flatMap(recovery.resetPassword)),
      changePassword: (input) =>
        parseChangePasswordCommand(boundary, input).pipe(Effect.flatMap(recovery.changePassword)),
    };
  }),
);

const AuthDefaultsLive = Layer.mergeAll(
  AuthBoundaryLive,
  SecureDefaultPasswordPolicy,
  NativeScryptPasswordHasher,
  AuthTokenLive,
  VerificationTokenConfigLive(),
  Layer.succeed(SessionPolicy)({
    sessionTtlMillis: 7 * 24 * 60 * 60 * 1000,
    sessionUpdateAgeMillis: 24 * 60 * 60 * 1000,
  }),
);

const AuthDevDefaultsLive = Layer.mergeAll(AuthDefaultsLive, PermissiveDevRateLimiter);

const InternalWorkflowsLive = Layer.mergeAll(
  EmailPasswordWorkflowsLive,
  SessionWorkflowsLive,
  PasswordRecoveryWorkflowsLive,
).pipe(Layer.provide(AuthDefaultsLive));

const InternalDevWorkflowsLive = Layer.mergeAll(
  EmailPasswordWorkflowsLive,
  SessionWorkflowsLive,
  PasswordRecoveryWorkflowsLive,
).pipe(Layer.provide(AuthDevDefaultsLive));

export const AuthLive = {
  production: AuthLiveLayer.pipe(
    Layer.provide(Layer.mergeAll(InternalWorkflowsLive, AuthDefaultsLive)),
  ),
  dev: AuthLiveLayer.pipe(
    Layer.provide(Layer.mergeAll(InternalDevWorkflowsLive, AuthDevDefaultsLive)),
  ),
  default: AuthLiveLayer.pipe(
    Layer.provide(Layer.mergeAll(InternalDevWorkflowsLive, AuthDevDefaultsLive)),
  ),
} satisfies {
  readonly production: Layer.Layer<Auth, never, AuthStorage | AuthEmail | RateLimiter>;
  readonly dev: Layer.Layer<Auth, never, AuthStorage | AuthEmail>;
  readonly default: Layer.Layer<Auth, never, AuthStorage | AuthEmail>;
};
