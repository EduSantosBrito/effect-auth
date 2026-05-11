import { Context, Effect, Layer } from "effect";
import { AuthBoundaryLive, type BoundaryParseError, type PublicAuthError } from "./domain/index.js";
import { AuthEmail, type AuthEmailFailure } from "./email/mock.js";
import {
  NativeScryptPasswordHasher,
  SecureDefaultPasswordPolicy,
  type PasswordHashFailure,
  type PasswordPolicyFailure,
} from "./password/index.js";
import { PermissiveDevRateLimiter, type RateLimitExceeded } from "./rate-limit/index.js";
import { AuthStorage, type AuthStorageFailure } from "./storage/index.js";
import { AuthTokenLive, type TokenGenerationFailure } from "./token/index.js";
import {
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  SessionWorkflows,
  SessionWorkflowsLive,
  type ChangePasswordInput,
  type ChangePasswordResult,
  type CurrentSessionInput,
  type RequestPasswordResetInput,
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

export class Auth extends Context.Service<Auth, AuthShape>()("effect-auth/Auth") {}

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
  PermissiveDevRateLimiter,
);

const InternalWorkflowsLive = Layer.mergeAll(
  EmailPasswordWorkflowsLive,
  SessionWorkflowsLive,
  PasswordRecoveryWorkflowsLive,
).pipe(Layer.provide(AuthDefaultsLive));

export const AuthLive = {
  default: AuthLiveLayer.pipe(Layer.provide(InternalWorkflowsLive)),
} satisfies {
  readonly default: Layer.Layer<Auth, never, AuthStorage | AuthEmail>;
};
