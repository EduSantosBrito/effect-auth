import { Context, Effect, Layer } from "effect";
import { AuthBoundaryLive, type BoundaryParseError, type PublicAuthError } from "./domain/index.js";
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
import { AuthTokenLive, type TokenGenerationFailure } from "./token/index.js";
import {
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  SessionPolicy,
  SessionWorkflows,
  SessionWorkflowsLive,
  VerificationTokenConfigLive,
  type ChangePasswordInput,
  type ChangePasswordResult,
  type CurrentSessionInput,
  type ListSessionsInput,
  type ListSessionsResult,
  type RequestPasswordResetInput,
  type RevokeUserSessionInput,
  type ResendVerificationInput,
  type ResetPasswordInput,
  type SessionLookupResult,
  type SignInInput,
  type SignInResult,
  type SignOutInput,
  type SignUpInput,
  type SignUpResult,
  type VerifyEmailInput,
  type VerifyEmailResult,
} from "./workflows/index.js";

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
    PublicAuthError | AuthStorageFailure | TokenGenerationFailure
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
    input: CurrentSessionInput,
  ) => Effect.Effect<
    SessionLookupResult,
    PublicAuthError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly listSessions: (
    input: ListSessionsInput,
  ) => Effect.Effect<
    ListSessionsResult,
    PublicAuthError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly revokeSession: (
    input: RevokeUserSessionInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailure | TokenGenerationFailure>;
  readonly revokeOtherSessions: (
    input: SignOutInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailure | TokenGenerationFailure>;
  readonly revokeSessions: (
    input: SignOutInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailure | TokenGenerationFailure>;
  readonly signOut: (
    input: SignOutInput,
  ) => Effect.Effect<void, PublicAuthError | AuthStorageFailure | TokenGenerationFailure>;
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
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;

    return {
      signUp: emailPassword.signUp,
      verifyEmail: emailPassword.verifyEmail,
      resendVerification: emailPassword.resendVerification,
      signIn: emailPassword.signIn,
      currentSession: sessions.currentSession,
      listSessions: sessions.listSessions,
      revokeSession: sessions.revokeSession,
      revokeOtherSessions: sessions.revokeOtherSessions,
      revokeSessions: sessions.revokeSessions,
      signOut: sessions.signOut,
      requestPasswordReset: recovery.requestPasswordReset,
      resetPassword: recovery.resetPassword,
      changePassword: recovery.changePassword,
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
  production: AuthLiveLayer.pipe(Layer.provide(InternalWorkflowsLive)),
  dev: AuthLiveLayer.pipe(Layer.provide(InternalDevWorkflowsLive)),
  default: AuthLiveLayer.pipe(Layer.provide(InternalDevWorkflowsLive)),
} satisfies {
  readonly production: Layer.Layer<Auth, never, AuthStorage | AuthEmail | RateLimiter>;
  readonly dev: Layer.Layer<Auth, never, AuthStorage | AuthEmail>;
  readonly default: Layer.Layer<Auth, never, AuthStorage | AuthEmail>;
};
