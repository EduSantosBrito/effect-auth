import { Auth, AuthLive, type PublicAuthError } from "effect-auth";
import type { AuthBoundary, NormalizedEmail } from "effect-auth/domain";
import type { AuthEmail, SentAuthEmail } from "effect-auth/email/mock";
import {
  AuthApi,
  AuthHttp,
  AuthHttpAdapter,
  AuthHttpConfig,
  AuthHttpErrorMapper,
  AuthHttpHandlersLive,
  handleChangePassword,
  handleCompletePasswordReset,
  handleCurrentSession,
  handleRequestPasswordReset,
  handleSignInEmail,
  handleSignOut,
  handleSignUpEmail,
  handleVerifyEmail,
  type TrustedOriginPolicy,
} from "effect-auth/http";
import {
  makeNativeScryptPasswordHasher,
  type NativeScryptRuntime,
  type PasswordHasher,
  type PasswordPolicy,
} from "effect-auth/password";
import type { RateLimiter } from "effect-auth/rate-limit";
import type { AuthStorage } from "effect-auth/storage";
import type { DevMemoryStorageState } from "effect-auth/storage/dev-memory";
import type { AuthToken, SessionToken } from "effect-auth/token";
import type {
  EmailPasswordWorkflows,
  PasswordRecoveryWorkflows,
  SessionWorkflows,
} from "effect-auth/workflows";

type DocumentedImportsCompile = {
  readonly root: PublicAuthError;
  readonly auth: typeof Auth | typeof AuthLive;
  readonly domain: AuthBoundary | NormalizedEmail;
  readonly password: PasswordHasher | PasswordPolicy;
  readonly nativeScryptRuntime: NativeScryptRuntime;
  readonly makeNativeScryptPasswordHasher: typeof makeNativeScryptPasswordHasher;
  readonly token: AuthToken | SessionToken;
  readonly storage: AuthStorage | DevMemoryStorageState;
  readonly email: AuthEmail | SentAuthEmail;
  readonly rateLimit: RateLimiter;
  readonly workflows: EmailPasswordWorkflows | SessionWorkflows | PasswordRecoveryWorkflows;
  readonly http:
    | typeof AuthApi
    | typeof AuthHttp
    | typeof AuthHttpConfig
    | typeof AuthHttpErrorMapper
    | typeof AuthHttpAdapter
    | typeof AuthHttpHandlersLive
    | typeof handleSignUpEmail
    | typeof handleVerifyEmail
    | typeof handleSignInEmail
    | typeof handleCurrentSession
    | typeof handleSignOut
    | typeof handleRequestPasswordReset
    | typeof handleCompletePasswordReset
    | typeof handleChangePassword
    | TrustedOriginPolicy;
};

export type { DocumentedImportsCompile };
