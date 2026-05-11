import {
  Auth,
  AuthLive,
  VerificationTokenConfig,
  VerificationTokenConfigLive,
  createEffectAuthClient,
  packageName,
  type AuthShape,
  type EffectAuthClient,
  type EffectAuthClientOptions,
  type PublicAuthError,
  type VerificationTokenConfigInput,
  type VerificationTokenConfigShape,
} from "effect-auth";
import {
  AuthBoundary,
  AuthBoundaryLive,
  BoundaryParseError,
  CallbackUrl,
  OriginUrl,
  PasswordText,
  emailNotVerified,
  invalidCredentials,
  invalidToken,
  normalizeEmail,
  normalizePassword,
  parseCallbackUrl,
  parseOrigin,
  rateLimited,
  unauthorized,
  type AuthBoundaryShape,
  type NormalizedEmail,
} from "effect-auth/domain";
import {
  AuthEmail,
  AuthEmailFailure,
  MockAuthEmail,
  makeMockAuthEmail,
  makeMockAuthEmailState,
  type AuthEmailShape,
  type MockAuthEmailState,
  type SentAuthEmail,
} from "effect-auth/email/mock";
import {
  AuthApi,
  AuthApiEndpoints,
  AuthHttp,
  AuthHttpConfig,
  AuthHttpError,
  AuthHttpErrorMapper,
  AuthHttpHandlersLive,
  AuthHttpToken,
  AuthSession,
  CurrentAuthSession,
  SessionCookie,
  SessionTokenExtractResult,
  StateChangingRequest,
  TrustedOriginPolicy,
  TrustedOrigins,
  optionalAuth,
  requireAuth,
  type AuthHttpConfigInput,
  type AuthHttpConfigShape,
  type AuthHttpErrorMapperShape,
  type AuthHttpErrorResponse,
  type AuthHttpMountOptions,
  type AuthHttpOkResponse,
  type AuthHttpOptionalAuthOptions,
  type AuthHttpRequireAuthOptions,
  type AuthHttpSession,
  type AuthHttpSessionResponse,
  type AuthHttpSignInResponse,
  type AuthHttpTokenExtractor,
  type AuthHttpUserResponse,
  type AuthSessionShape,
  type SessionTokenExtractResult as SessionTokenExtractResultType,
  type TrustedOriginPolicyShape,
} from "effect-auth/http";
import {
  NativeScryptPasswordHasher,
  PasswordHash,
  PasswordHashFailure,
  PasswordHasher,
  PasswordPolicy,
  PasswordPolicyFailure,
  SecureDefaultPasswordPolicy,
  makeNativeScryptPasswordHasher,
  type NativeScryptRuntime,
  type PasswordHash as PasswordHashValue,
  type PasswordHasherShape,
  type PasswordPolicyShape,
} from "effect-auth/password";
import {
  BoundedDevRateLimiter,
  PermissiveDevRateLimiter,
  RateLimitBucket,
  RateLimitExceeded,
  RateLimiter,
  deriveRateLimitKey,
  makeBoundedDevRateLimiter,
  type BoundedDevRateLimiterOptions,
  type RateLimitAttempt,
  type RateLimiterShape,
} from "effect-auth/rate-limit";
import {
  AuthStorage,
  AuthStorageFailure,
  type AuthStorageShape,
  type AuthUser,
  type AuthUserId,
  type ChangePasswordSession,
  type CompletePasswordReset,
  type ConsumeVerificationToken,
  type CreateSession,
  type CreateUserWithCredential,
  type CredentialId,
  type EmailPasswordCredential,
  type EmailPasswordCredentialLookup,
  type RevokeAllUserSessions,
  type RevokeOtherSessions,
  type RevokeSession,
  type RotateSessionToken,
  type SessionId,
  type StoreVerificationToken,
  type StoredSession,
  type StoredSessionLookup,
  type UpdatePasswordHash,
  type VerificationTokenLookup,
  type VerificationTokenPurpose,
} from "effect-auth/storage";
import {
  DevMemoryAuthStorage,
  makeDevMemoryStorage,
  makeDevMemoryStorageState,
  type DevMemoryStorageState,
} from "effect-auth/storage/dev-memory";
import {
  AuthToken,
  AuthTokenLive,
  SessionToken,
  TokenGenerationFailure,
  TokenHash,
  VerificationToken,
  hashTokenValue,
  type AuthTokenShape,
  type SessionToken as SessionTokenValue,
  type TokenHash as TokenHashValue,
  type VerificationToken as VerificationTokenValue,
} from "effect-auth/token";

type PublicApiContract = {
  readonly root:
    | typeof Auth
    | typeof AuthLive
    | typeof VerificationTokenConfig
    | typeof VerificationTokenConfigLive
    | typeof createEffectAuthClient
    | typeof packageName
    | AuthShape
    | EffectAuthClient
    | EffectAuthClientOptions
    | PublicAuthError
    | VerificationTokenConfigInput
    | VerificationTokenConfigShape;
  readonly domain:
    | typeof AuthBoundary
    | typeof AuthBoundaryLive
    | typeof BoundaryParseError
    | typeof CallbackUrl
    | typeof OriginUrl
    | typeof PasswordText
    | typeof emailNotVerified
    | typeof invalidCredentials
    | typeof invalidToken
    | typeof normalizeEmail
    | typeof normalizePassword
    | typeof parseCallbackUrl
    | typeof parseOrigin
    | typeof rateLimited
    | typeof unauthorized
    | AuthBoundaryShape
    | NormalizedEmail;
  readonly email:
    | typeof AuthEmail
    | typeof AuthEmailFailure
    | typeof MockAuthEmail
    | typeof makeMockAuthEmail
    | typeof makeMockAuthEmailState
    | AuthEmailShape
    | MockAuthEmailState
    | SentAuthEmail;
  readonly http:
    | typeof AuthApi
    | typeof AuthApiEndpoints
    | typeof AuthHttp
    | typeof AuthHttpConfig
    | typeof AuthHttpError
    | typeof AuthHttpErrorMapper
    | typeof AuthHttpHandlersLive
    | typeof AuthHttpToken
    | typeof AuthSession
    | typeof CurrentAuthSession
    | typeof SessionCookie
    | typeof SessionTokenExtractResult
    | typeof StateChangingRequest
    | typeof TrustedOriginPolicy
    | typeof TrustedOrigins
    | typeof optionalAuth
    | typeof requireAuth
    | AuthHttpConfigInput
    | AuthHttpConfigShape
    | AuthHttpErrorMapperShape
    | AuthHttpErrorResponse
    | AuthHttpMountOptions
    | AuthHttpOkResponse
    | AuthHttpOptionalAuthOptions
    | AuthHttpRequireAuthOptions
    | AuthHttpSession
    | AuthHttpSessionResponse
    | AuthHttpSignInResponse
    | AuthHttpTokenExtractor
    | AuthHttpUserResponse
    | AuthSessionShape
    | SessionTokenExtractResultType
    | TrustedOriginPolicyShape;
  readonly password:
    | typeof NativeScryptPasswordHasher
    | typeof PasswordHash
    | typeof PasswordHashFailure
    | typeof PasswordHasher
    | typeof PasswordPolicy
    | typeof PasswordPolicyFailure
    | typeof SecureDefaultPasswordPolicy
    | typeof makeNativeScryptPasswordHasher
    | NativeScryptRuntime
    | PasswordHashValue
    | PasswordHasherShape
    | PasswordPolicyShape;
  readonly rateLimit:
    | typeof BoundedDevRateLimiter
    | typeof PermissiveDevRateLimiter
    | typeof RateLimitBucket
    | typeof RateLimitExceeded
    | typeof RateLimiter
    | typeof deriveRateLimitKey
    | typeof makeBoundedDevRateLimiter
    | BoundedDevRateLimiterOptions
    | RateLimitAttempt
    | RateLimiterShape;
  readonly storage:
    | typeof AuthStorage
    | typeof AuthStorageFailure
    | AuthStorageShape
    | AuthUser
    | AuthUserId
    | ChangePasswordSession
    | CompletePasswordReset
    | ConsumeVerificationToken
    | CreateSession
    | CreateUserWithCredential
    | CredentialId
    | EmailPasswordCredential
    | EmailPasswordCredentialLookup
    | RevokeAllUserSessions
    | RevokeOtherSessions
    | RevokeSession
    | RotateSessionToken
    | SessionId
    | StoreVerificationToken
    | StoredSession
    | StoredSessionLookup
    | UpdatePasswordHash
    | VerificationTokenLookup
    | VerificationTokenPurpose;
  readonly devMemoryStorage:
    | typeof DevMemoryAuthStorage
    | typeof makeDevMemoryStorage
    | typeof makeDevMemoryStorageState
    | DevMemoryStorageState;
  readonly token:
    | typeof AuthToken
    | typeof AuthTokenLive
    | typeof SessionToken
    | typeof TokenGenerationFailure
    | typeof TokenHash
    | typeof VerificationToken
    | typeof hashTokenValue
    | AuthTokenShape
    | SessionTokenValue
    | TokenHashValue
    | VerificationTokenValue;
};

export type { PublicApiContract };
