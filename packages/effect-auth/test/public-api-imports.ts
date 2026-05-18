import type { Layer } from "effect";
import {
  Auth,
  AuthLive,
  AuthLiveConfig,
  SessionPolicy,
  SessionPolicyLive,
  VerificationTokenConfig,
  VerificationTokenConfigLive,
  createEffectAuthClient,
  packageName,
  type AuthLiveConfigInput,
  type AuthLiveConfigShape,
  type AuthRevokeUserSessionInput,
  type AuthSessionTokenInput,
  type AuthShape,
  type AuthVerifyEmailInput,
  type ChangePasswordInput,
  type DeleteUserInput,
  type EffectAuthClient,
  type EffectAuthClientOptions,
  type ListedSession,
  type ListAccountsInput,
  type ListAccountsResult,
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
  type UpdateUserInput,
  type UpdateUserResult,
  type WorkflowDeleteUserInput,
  type WorkflowUpdateUserInput,
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
  MockAuthEmail,
  makeMockAuthEmail,
  makeMockAuthEmailState,
  type MockAuthEmailState,
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
  type AuthHttpListAccountsResponse,
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
  AuthEncryptedFeature,
  AuthEncryptionKeyId,
  AuthFeatureKeyMaterialFailure,
  AuthFeatureKeyMaterialService,
  OAuth,
  OAuthFlow,
  OAuthPkceMode,
  OAuthProviderConfigError,
  OAuthProviderId,
  OAuthProviderNotFound,
  OAuthProviderProfileMappingFailure,
  OAuthProviders,
  OAuthStartError,
  OAuthState,
  OAuthStateFailure,
  OAuthStateHandle,
  OAuthStateHash,
  OAuthTokenEndpointAuthMethod,
  normalizeOAuthScopes,
  type AuthEncryptedFeature as AuthEncryptedFeatureValue,
  type AuthEncryptionKeyId as AuthEncryptionKeyIdValue,
  type AuthFeatureKeyMaterial,
  type ConsumeOAuthState,
  type OAuthAuthorizationStartResult,
  type OAuthFlow as OAuthFlowValue,
  type OAuthPkceMode as OAuthPkceModeValue,
  type OAuthProfileMappingInput,
  type OAuthProviderConfigInput,
  type OAuthProviderConfigLayerInput,
  type OAuthProviderEndpointsInput,
  type OAuthProviderId as OAuthProviderIdValue,
  type OAuthProviderInput,
  type OAuthProviderProfile,
  type OAuthStartLinkInput,
  type OAuthStartSignInInput,
  type OAuthStateCreateInput,
  type OAuthStateCreateResult,
  type OAuthStateHash as OAuthStateHashValue,
  type OAuthStateHandle as OAuthStateHandleValue,
  type OAuthStateSecrets,
  type OAuthTokenEndpointAuthMethod as OAuthTokenEndpointAuthMethodValue,
  type OAuthTokenSet,
  type ResolvedOAuthProvider,
  type StoreOAuthState,
  type StoredOAuthState,
} from "effect-auth/oauth";
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
  type AuthAccount,
  type AccountId,
  type AuthUser,
  type AuthUserId,
  type ChangePasswordSession,
  type CompletePasswordReset,
  type ConsumeVerificationToken,
  type CreateSession,
  type CreateUserWithCredentialAccount,
  type CredentialAccountLookup,
  type DeleteUserStorageInput,
  type ListUserSessions,
  type PublicAuthAccount,
  type RevokeAllUserSessions,
  type RevokeOtherSessions,
  type RevokeSession,
  type RevokeUserSession,
  type RotateSessionToken,
  type SessionId,
  type StoreVerificationToken,
  type StoredSession,
  type StoredSessionLookup,
  type UpdateCredentialAccountPasswordHash,
  type UpdateUserStorageInput,
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
  DrizzlePg,
  layer as drizzlePgLayer,
  schema as drizzlePgSchema,
  type AuthDrizzlePgSchema,
  type LayerOptions as DrizzlePgLayerOptions,
  type SchemaOptions as DrizzlePgSchemaOptions,
} from "effect-auth/storage/drizzle-pg";
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

type ExpectTrue<T extends true> = T;

type AuthLiveCallableContract = ExpectTrue<
  typeof AuthLive extends (
    config?: AuthLiveConfigInput,
  ) => Layer.Layer<Auth | AuthLiveConfig, BoundaryParseError, AuthStorage | AuthEmail | RateLimiter>
    ? true
    : false
>;

type PublicApiContract = {
  readonly root:
    | typeof Auth
    | typeof AuthLive
    | typeof AuthLiveConfig
    | typeof SessionPolicy
    | typeof SessionPolicyLive
    | typeof VerificationTokenConfig
    | typeof VerificationTokenConfigLive
    | typeof createEffectAuthClient
    | typeof packageName
    | AuthLiveConfigInput
    | AuthLiveConfigShape
    | AuthRevokeUserSessionInput
    | AuthSessionTokenInput
    | AuthShape
    | AuthVerifyEmailInput
    | ChangePasswordInput
    | DeleteUserInput
    | EffectAuthClient
    | EffectAuthClientOptions
    | ListedSession
    | ListAccountsInput
    | ListAccountsResult
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
    | UpdateUserInput
    | UpdateUserResult
    | WorkflowDeleteUserInput
    | WorkflowUpdateUserInput
    | VerificationTokenConfigInput
    | VerificationTokenConfigShape
    | AuthLiveCallableContract;
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
  readonly mockEmail:
    | typeof MockAuthEmail
    | typeof makeMockAuthEmail
    | typeof makeMockAuthEmailState
    | MockAuthEmailState;
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
    | AuthHttpListAccountsResponse
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
  readonly oauth:
    | typeof AuthEncryptedFeature
    | typeof AuthEncryptionKeyId
    | typeof AuthFeatureKeyMaterialFailure
    | typeof AuthFeatureKeyMaterialService
    | typeof OAuth
    | typeof OAuthFlow
    | typeof OAuthPkceMode
    | typeof OAuthProviderConfigError
    | typeof OAuthProviderId
    | typeof OAuthProviderNotFound
    | typeof OAuthProviderProfileMappingFailure
    | typeof OAuthProviders
    | typeof OAuthStartError
    | typeof OAuthState
    | typeof OAuthStateFailure
    | typeof OAuthStateHandle
    | typeof OAuthStateHash
    | typeof OAuthTokenEndpointAuthMethod
    | typeof normalizeOAuthScopes
    | AuthEncryptedFeatureValue
    | AuthEncryptionKeyIdValue
    | AuthFeatureKeyMaterial
    | ConsumeOAuthState
    | OAuthAuthorizationStartResult
    | OAuthFlowValue
    | OAuthPkceModeValue
    | OAuthProfileMappingInput
    | OAuthProviderConfigInput
    | OAuthProviderConfigLayerInput
    | OAuthProviderEndpointsInput
    | OAuthProviderIdValue
    | OAuthProviderInput
    | OAuthProviderProfile
    | OAuthStartLinkInput
    | OAuthStartSignInInput
    | OAuthStateCreateInput
    | OAuthStateCreateResult
    | OAuthStateHashValue
    | OAuthStateHandleValue
    | OAuthStateSecrets
    | OAuthTokenEndpointAuthMethodValue
    | OAuthTokenSet
    | ResolvedOAuthProvider
    | StoreOAuthState
    | StoredOAuthState;
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
    | AccountId
    | AuthAccount
    | AuthStorageShape
    | AuthUser
    | AuthUserId
    | ChangePasswordSession
    | CompletePasswordReset
    | ConsumeVerificationToken
    | CreateSession
    | CreateUserWithCredentialAccount
    | CredentialAccountLookup
    | DeleteUserStorageInput
    | ListUserSessions
    | PublicAuthAccount
    | RevokeAllUserSessions
    | RevokeOtherSessions
    | RevokeSession
    | RevokeUserSession
    | RotateSessionToken
    | SessionId
    | StoreVerificationToken
    | StoredSession
    | StoredSessionLookup
    | UpdateCredentialAccountPasswordHash
    | UpdateUserStorageInput
    | VerificationTokenLookup
    | VerificationTokenPurpose;
  readonly devMemoryStorage:
    | typeof DevMemoryAuthStorage
    | typeof makeDevMemoryStorage
    | typeof makeDevMemoryStorageState
    | DevMemoryStorageState;
  readonly drizzlePg:
    | typeof DrizzlePg
    | typeof drizzlePgLayer
    | typeof drizzlePgSchema
    | AuthDrizzlePgSchema
    | DrizzlePgLayerOptions
    | DrizzlePgSchemaOptions;
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
