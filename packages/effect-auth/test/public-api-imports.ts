import {
  Auth,
  AuthLive,
  SessionPolicy,
  SessionPolicyLive,
  VerificationTokenConfig,
  VerificationTokenConfigLive,
  createEffectAuthClient,
  packageName,
  type AuthShape,
  type ChangePasswordInput,
  type EffectAuthClient,
  type EffectAuthClientOptions,
  type ListedSession,
  type ListSessionsInput,
  type ListSessionsResult,
  type PublicAuthError,
  type RequestPasswordResetInput,
  type RevokeUserSessionInput,
  type ResetPasswordInput,
  type SessionPolicyInput,
  type SessionPolicyShape,
  type SignInInput,
  type SignUpInput,
  type VerificationTokenConfigInput,
  type VerificationTokenConfigShape,
} from "effect-auth";
import {
  AuthBoundary,
  AuthBoundaryLive,
  BoundaryParseError,
  CallbackUrl,
  ClientIp,
  OriginUrl,
  PasswordText,
  emailNotVerified,
  invalidCredentials,
  invalidToken,
  normalizeEmail,
  normalizePassword,
  parseCallbackUrl,
  parseClientIp,
  parseOrigin,
  rateLimited,
  unauthorized,
  type AuthBoundaryShape,
  type ClientIp as ClientIpValue,
  type NormalizedEmail,
} from "effect-auth/domain";
import {
  AuthEmail,
  AuthEmailFailure,
  type AuthEmailShape,
  type SentAuthEmail,
} from "effect-auth/email";
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
  type AuthHttpListSessionsResponse,
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
  type ListUserSessions,
  type RevokeAllUserSessions,
  type RevokeOtherSessions,
  type RevokeSession,
  type RevokeUserSession,
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
    | typeof SessionPolicy
    | typeof SessionPolicyLive
    | typeof VerificationTokenConfig
    | typeof VerificationTokenConfigLive
    | typeof createEffectAuthClient
    | typeof packageName
    | AuthShape
    | ChangePasswordInput
    | EffectAuthClient
    | EffectAuthClientOptions
    | ListedSession
    | ListSessionsInput
    | ListSessionsResult
    | PublicAuthError
    | RequestPasswordResetInput
    | RevokeUserSessionInput
    | ResetPasswordInput
    | SessionPolicyInput
    | SessionPolicyShape
    | SignInInput
    | SignUpInput
    | VerificationTokenConfigInput
    | VerificationTokenConfigShape;
  readonly domain:
    | typeof AuthBoundary
    | typeof AuthBoundaryLive
    | typeof BoundaryParseError
    | typeof CallbackUrl
    | typeof ClientIp
    | typeof OriginUrl
    | typeof PasswordText
    | typeof emailNotVerified
    | typeof invalidCredentials
    | typeof invalidToken
    | typeof normalizeEmail
    | typeof normalizePassword
    | typeof parseCallbackUrl
    | typeof parseClientIp
    | typeof parseOrigin
    | typeof rateLimited
    | typeof unauthorized
    | AuthBoundaryShape
    | ClientIpValue
    | NormalizedEmail;
  readonly email: typeof AuthEmail | typeof AuthEmailFailure | AuthEmailShape | SentAuthEmail;
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
    | AuthHttpListSessionsResponse
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
    | ListUserSessions
    | RevokeAllUserSessions
    | RevokeOtherSessions
    | RevokeSession
    | RevokeUserSession
    | RotateSessionToken
    | SessionId
    | StoreVerificationToken
    | StoredSession
    | StoredSessionLookup
    | UpdatePasswordHash
    | VerificationTokenLookup
    | VerificationTokenPurpose;
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
