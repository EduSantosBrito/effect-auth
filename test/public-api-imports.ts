import type { PublicAuthError } from "effect-auth";
import type { AuthBoundary, NormalizedEmail } from "effect-auth/domain";
import type { AuthEmail, SentAuthEmail } from "effect-auth/email/mock";
import type {
  AuthApi,
  AuthHttpAdapter,
  AuthHttpHandlersLive,
  TrustedOriginPolicy,
} from "effect-auth/http";
import type { PasswordHasher, PasswordPolicy } from "effect-auth/password";
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
  readonly domain: AuthBoundary | NormalizedEmail;
  readonly password: PasswordHasher | PasswordPolicy;
  readonly token: AuthToken | SessionToken;
  readonly storage: AuthStorage | DevMemoryStorageState;
  readonly email: AuthEmail | SentAuthEmail;
  readonly rateLimit: RateLimiter;
  readonly workflows: EmailPasswordWorkflows | SessionWorkflows | PasswordRecoveryWorkflows;
  readonly http:
    | typeof AuthApi
    | typeof AuthHttpAdapter
    | typeof AuthHttpHandlersLive
    | TrustedOriginPolicy;
};

export type { DocumentedImportsCompile };
