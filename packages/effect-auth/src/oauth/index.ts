import { Clock, Config, Context, Effect, Layer, Option, Predicate, Redacted, Schema } from "effect";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPublicKey,
  createVerify,
  randomBytes,
  type webcrypto,
} from "node:crypto";
import * as HttpClient from "effect/unstable/http/HttpClient";
import * as HttpClientRequest from "effect/unstable/http/HttpClientRequest";
import * as HttpClientResponse from "effect/unstable/http/HttpClientResponse";
import { AuthLiveConfig } from "../auth.js";
import { BoundaryParseError, normalizeEmail, type PublicAuthError } from "../domain/index.js";
import {
  AuthStorage,
  AuthStorageFailure,
  type AuthUser,
  type AuthUserId,
  type OAuthSessionStorageFailure,
  type OAuthAccountStorageFailure,
  type OAuthProviderAccount,
  type StoredSession,
} from "../storage/index.js";
import { AuthTokenLive, SessionToken, type TokenGenerationFailure } from "../token/index.js";
import { AuthToken } from "../token/index.js";

export const AuthEncryptedFeature = Schema.Literals(["ProviderTokens", "OAuthStateSecrets"]);
export type AuthEncryptedFeature = typeof AuthEncryptedFeature.Type;

export const AuthEncryptionKeyId = Schema.String.pipe(
  Schema.check(
    Schema.makeFilter((value) =>
      /^[A-Za-z0-9._-]{1,128}$/u.test(value)
        ? undefined
        : "Expected key id matching ^[A-Za-z0-9._-]{1,128}$",
    ),
  ),
  Schema.brand("AuthEncryptionKeyId"),
);
export type AuthEncryptionKeyId = typeof AuthEncryptionKeyId.Type;

export interface AuthFeatureKeyMaterial {
  readonly feature: AuthEncryptedFeature;
  readonly keyId: AuthEncryptionKeyId;
  readonly keyBytes: Redacted.Redacted<Uint8Array>;
}

export class AuthFeatureKeyMaterialFailure extends Schema.TaggedErrorClass<AuthFeatureKeyMaterialFailure>()(
  "AuthFeatureKeyMaterialFailure",
  {
    feature: AuthEncryptedFeature,
    reason: Schema.Literals([
      "MissingEncryptionKey",
      "InvalidEncryptionKey",
      "InvalidEncryptionKeyId",
    ]),
  },
) {}

const decodeAuthEncryptionKeyId = Schema.decodeUnknownEffect(AuthEncryptionKeyId);

const selectedKey = (feature: AuthEncryptedFeature, config: typeof AuthLiveConfig.Service) => {
  if (feature === "ProviderTokens") {
    return {
      key: Option.isSome(config.providerTokens.encryptionKey)
        ? config.providerTokens.encryptionKey.value
        : Option.isSome(config.encryptionKey)
          ? config.encryptionKey.value
          : undefined,
      keyId: config.providerTokens.encryptionKeyId,
    };
  }
  return {
    key: Option.isSome(config.oauthState.encryptionKey)
      ? config.oauthState.encryptionKey.value
      : Option.isSome(config.encryptionKey)
        ? config.encryptionKey.value
        : undefined,
    keyId: config.oauthState.encryptionKeyId,
  };
};

const decodeKeyBytes = (
  feature: AuthEncryptedFeature,
  key: Redacted.Redacted<string>,
): Effect.Effect<Redacted.Redacted<Uint8Array>, AuthFeatureKeyMaterialFailure> => {
  const encoded = Redacted.value(key);
  if (!/^[A-Za-z0-9_-]+$/u.test(encoded)) {
    return Effect.fail(
      new AuthFeatureKeyMaterialFailure({ feature, reason: "InvalidEncryptionKey" }),
    );
  }
  const decoded = Buffer.from(encoded, "base64url");
  return decoded.length === 32
    ? Effect.succeed(Redacted.make(new Uint8Array(decoded)))
    : Effect.fail(new AuthFeatureKeyMaterialFailure({ feature, reason: "InvalidEncryptionKey" }));
};

export class AuthFeatureKeyMaterialService extends Context.Service<
  AuthFeatureKeyMaterialService,
  {
    readonly requireForFeature: (
      feature: AuthEncryptedFeature,
    ) => Effect.Effect<AuthFeatureKeyMaterial, AuthFeatureKeyMaterialFailure>;
  }
>()("effect-auth/AuthFeatureKeyMaterialService") {
  static readonly layer = Layer.effect(AuthFeatureKeyMaterialService)(
    Effect.gen(function* () {
      const config = yield* AuthLiveConfig;
      return {
        requireForFeature: Effect.fn("AuthFeatureKeyMaterial.requireForFeature")(
          function* (feature) {
            const resolved = selectedKey(feature, config);
            const keyId = yield* decodeAuthEncryptionKeyId(resolved.keyId).pipe(
              Effect.mapError(
                () =>
                  new AuthFeatureKeyMaterialFailure({
                    feature,
                    reason: "InvalidEncryptionKeyId",
                  }),
              ),
            );
            if (resolved.key === undefined) {
              return yield* new AuthFeatureKeyMaterialFailure({
                feature,
                reason: "MissingEncryptionKey",
              });
            }
            const keyBytes = yield* decodeKeyBytes(feature, resolved.key);
            return { feature, keyId, keyBytes };
          },
        ),
      };
    }),
  );
}

export const ProviderTokenKind = Schema.Literals(["AccessToken", "RefreshToken", "IdToken"]);
export type ProviderTokenKind = typeof ProviderTokenKind.Type;

export const ProtectedProviderToken = Schema.String.pipe(Schema.brand("ProtectedProviderToken"));
export type ProtectedProviderToken = typeof ProtectedProviderToken.Type;

export interface ProtectedProviderTokenSet {
  readonly accessToken?: ProtectedProviderToken;
  readonly refreshToken?: ProtectedProviderToken;
  readonly idToken?: ProtectedProviderToken;
  readonly tokenType?: string;
  readonly scope?: string;
  readonly accessTokenExpiresAt?: number;
  readonly refreshTokenExpiresAt?: number;
}

export interface ProviderTokenAad {
  readonly providerId: OAuthProviderId;
  readonly providerAccountId: string;
  readonly kind: ProviderTokenKind;
}

export interface ProtectProviderTokenInput extends ProviderTokenAad {
  readonly plaintext: Redacted.Redacted<string>;
}

export interface UnprotectProviderTokenInput extends ProviderTokenAad {
  readonly protectedToken: ProtectedProviderToken;
}

export class ProviderTokenProtectionFailure extends Schema.TaggedErrorClass<ProviderTokenProtectionFailure>()(
  "ProviderTokenProtectionFailure",
  {
    reason: Schema.Literals([
      "EncryptFailed",
      "DecryptFailed",
      "InvalidEnvelope",
      "UnsupportedVersion",
      "UnknownKeyId",
      "ContextMismatch",
    ]),
  },
) {}

const protectedProviderTokenEnvelopeVersion = "ea_pt_v1";
const decodeProtectedProviderToken = Schema.decodeUnknownEffect(ProtectedProviderToken);

const aadPart = (label: string, value: string) => `${label}:${value.length}:${value}`;

const providerTokenAad = (input: ProviderTokenAad) =>
  Buffer.from(
    [
      aadPart("provider", String(input.providerId)),
      aadPart("account", input.providerAccountId),
      aadPart("kind", input.kind),
    ].join("|"),
    "utf8",
  );

export class ProviderTokenProtection extends Context.Service<
  ProviderTokenProtection,
  {
    readonly protect: (
      input: ProtectProviderTokenInput,
    ) => Effect.Effect<ProtectedProviderToken, ProviderTokenProtectionFailure>;
    readonly unprotect: (
      input: UnprotectProviderTokenInput,
    ) => Effect.Effect<Redacted.Redacted<string>, ProviderTokenProtectionFailure>;
  }
>()("effect-auth/oauth/ProviderTokenProtection") {
  static readonly layer = Layer.effect(ProviderTokenProtection)(
    Effect.gen(function* () {
      const keyMaterial = yield* AuthFeatureKeyMaterialService;
      const material = yield* keyMaterial.requireForFeature("ProviderTokens");
      return {
        protect: Effect.fn("ProviderTokenProtection.protect")(function* (input) {
          const envelope = yield* Effect.try({
            try: () => {
              const nonce = randomBytes(12);
              const cipher = createCipheriv(
                "aes-256-gcm",
                Redacted.value(material.keyBytes),
                nonce,
              );
              cipher.setAAD(providerTokenAad(input));
              const ciphertext = Buffer.concat([
                cipher.update(Redacted.value(input.plaintext), "utf8"),
                cipher.final(),
              ]);
              const tag = cipher.getAuthTag();
              return [
                protectedProviderTokenEnvelopeVersion,
                String(material.keyId),
                nonce.toString("base64url"),
                ciphertext.toString("base64url"),
                tag.toString("base64url"),
              ].join(".");
            },
            catch: () => new ProviderTokenProtectionFailure({ reason: "EncryptFailed" }),
          });
          return yield* decodeProtectedProviderToken(envelope).pipe(
            Effect.mapError(() => new ProviderTokenProtectionFailure({ reason: "EncryptFailed" })),
          );
        }),
        unprotect: Effect.fn("ProviderTokenProtection.unprotect")(function* (input) {
          const parts = input.protectedToken.split(".");
          if (parts.length !== 5) {
            return yield* new ProviderTokenProtectionFailure({ reason: "InvalidEnvelope" });
          }
          const version = parts[0];
          const keyId = parts[1];
          const nonce = parts[2];
          const ciphertext = parts[3];
          const tag = parts[4];
          if (
            version === undefined ||
            keyId === undefined ||
            nonce === undefined ||
            ciphertext === undefined ||
            tag === undefined
          ) {
            return yield* new ProviderTokenProtectionFailure({ reason: "InvalidEnvelope" });
          }
          if (version !== protectedProviderTokenEnvelopeVersion) {
            return yield* new ProviderTokenProtectionFailure({ reason: "UnsupportedVersion" });
          }
          if (keyId !== String(material.keyId)) {
            return yield* new ProviderTokenProtectionFailure({ reason: "UnknownKeyId" });
          }
          if (nonce === "" || ciphertext === "" || tag === "") {
            return yield* new ProviderTokenProtectionFailure({ reason: "InvalidEnvelope" });
          }
          return yield* Effect.try({
            try: () => {
              const decipher = createDecipheriv(
                "aes-256-gcm",
                Redacted.value(material.keyBytes),
                Buffer.from(nonce, "base64url"),
              );
              decipher.setAAD(providerTokenAad(input));
              decipher.setAuthTag(Buffer.from(tag, "base64url"));
              const plaintext = Buffer.concat([
                decipher.update(Buffer.from(ciphertext, "base64url")),
                decipher.final(),
              ]).toString("utf8");
              return Redacted.make(plaintext);
            },
            catch: () => new ProviderTokenProtectionFailure({ reason: "ContextMismatch" }),
          });
        }),
      };
    }),
  );
}

export const OAuthProviderId = Schema.String.pipe(
  Schema.check(
    Schema.makeFilter((value) =>
      /^[a-z0-9_-]{1,64}$/u.test(value)
        ? undefined
        : "Expected OAuth provider id matching ^[a-z0-9_-]{1,64}$",
    ),
  ),
  Schema.brand("OAuthProviderId"),
);
export type OAuthProviderId = typeof OAuthProviderId.Type;

export const OAuthTokenEndpointAuthMethod = Schema.Literals([
  "client_secret_basic",
  "client_secret_post",
]);
export type OAuthTokenEndpointAuthMethod = typeof OAuthTokenEndpointAuthMethod.Type;

export const OAuthPkceMode = Schema.Literals(["S256", "disabled"]);
export type OAuthPkceMode = typeof OAuthPkceMode.Type;

export interface OAuthTokenSet {
  readonly accessToken?: Redacted.Redacted<string>;
  readonly refreshToken?: Redacted.Redacted<string>;
  readonly idToken?: Redacted.Redacted<string>;
  readonly tokenType?: string;
  readonly scope?: string;
  readonly accessTokenExpiresAt?: number;
  readonly refreshTokenExpiresAt?: number;
}

export interface ValidatedOidcIdentity {
  readonly issuer: string;
  readonly subject: string;
  readonly audience: ReadonlyArray<string>;
  readonly expiresAt: number;
  readonly issuedAt?: number;
  readonly nonce: string;
  readonly email?: string;
  readonly emailVerified?: boolean;
  readonly name?: string;
  readonly image?: string;
  readonly rawClaims: Readonly<Record<string, unknown>>;
}

export interface OAuthProfileMappingInput {
  readonly provider: ResolvedOAuthProvider;
  readonly tokenSet: OAuthTokenSet;
  readonly validatedOidcIdentity?: ValidatedOidcIdentity;
  readonly userInfo?: Readonly<Record<string, unknown>>;
}

export interface OAuthProviderProfile {
  readonly providerAccountId: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name: string;
  readonly image: string | null;
}

export class OAuthProviderProfileMappingFailure extends Schema.TaggedErrorClass<OAuthProviderProfileMappingFailure>()(
  "OAuthProviderProfileMappingFailure",
  {
    reason: Schema.String,
  },
) {}

export interface OAuthProviderEndpointsInput {
  readonly authorizationUrl: URL;
  readonly tokenUrl: URL;
  readonly userInfoUrl?: URL;
  readonly jwksUrl?: URL;
  readonly issuer?: string;
}

export interface OAuthProviderInput {
  readonly id: string;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly defaultScopes?: ReadonlyArray<string>;
  readonly endpoints?: OAuthProviderEndpointsInput;
  readonly discoveryUrl?: URL;
  readonly pkce?: OAuthPkceMode;
  readonly tokenEndpointAuthMethod?: OAuthTokenEndpointAuthMethod;
  readonly extraAuthorizationParams?: Readonly<Record<string, string>>;
  readonly trustedEmail?: boolean;
  readonly mapProfile?: (
    input: OAuthProfileMappingInput,
  ) => Effect.Effect<OAuthProviderProfile, OAuthProviderProfileMappingFailure>;
}

export interface OAuthProviderConfigInput {
  readonly providers: ReadonlyArray<OAuthProviderInput>;
}

export type OAuthProviderConfigLayerInput =
  | OAuthProviderConfigInput
  | Config.Wrap<OAuthProviderConfigInput>;

export interface ResolvedOAuthProvider {
  readonly id: OAuthProviderId;
  readonly clientId: string;
  readonly clientSecret: Redacted.Redacted<string>;
  readonly defaultScopes: ReadonlyArray<string>;
  readonly authorizationUrl: URL;
  readonly tokenUrl: URL;
  readonly userInfoUrl?: URL;
  readonly issuer?: string;
  readonly jwksUrl?: URL;
  readonly isOidc: boolean;
  readonly pkce: OAuthPkceMode;
  readonly tokenEndpointAuthMethod: OAuthTokenEndpointAuthMethod;
  readonly extraAuthorizationParams: Readonly<Record<string, string>>;
  readonly trustedEmail: boolean;
  readonly mapProfile?: OAuthProviderInput["mapProfile"];
}

export class OAuthProviderConfigError extends Schema.TaggedErrorClass<OAuthProviderConfigError>()(
  "OAuthProviderConfigError",
  {
    reason: Schema.Literals([
      "InvalidProviderId",
      "DuplicateProviderId",
      "MissingEndpoints",
      "DiscoveryFailed",
      "InvalidScope",
      "ReservedAuthorizationParam",
      "GenericProviderRequiresProfileMapper",
    ]),
    providerId: Schema.optional(Schema.String),
  },
) {}

export class OAuthProviderNotFound extends Schema.TaggedErrorClass<OAuthProviderNotFound>()(
  "OAuthProviderNotFound",
  {
    providerId: Schema.String,
  },
) {}

export interface OAuthAuthorizationCodeExchangeInput {
  readonly provider: ResolvedOAuthProvider;
  readonly code: Redacted.Redacted<string>;
  readonly redirectUri: URL;
  readonly codeVerifier?: Redacted.Redacted<string>;
}

export interface OAuthProviderIdentityResult {
  readonly providerId: OAuthProviderId;
  readonly providerAccountId: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly name: string;
  readonly image: string | null;
  readonly tokenSet: OAuthTokenSet;
}

export class OAuthProviderClientError extends Schema.TaggedErrorClass<OAuthProviderClientError>()(
  "OAuthProviderClientError",
  {
    reason: Schema.Literals([
      "TokenRequestFailed",
      "TokenResponseInvalid",
      "MissingAccessToken",
      "MissingIdentityToken",
      "UserInfoRequestFailed",
      "UserInfoResponseInvalid",
      "ProfileMappingFailed",
      "MissingProviderEmail",
      "UnsupportedTokenEndpointAuthMethod",
    ]),
  },
) {}

export interface OidcValidationInput {
  readonly provider: ResolvedOAuthProvider;
  readonly idToken: Redacted.Redacted<string>;
  readonly expectedNonce: Redacted.Redacted<string>;
  readonly now?: number;
}

export class OidcValidationError extends Schema.TaggedErrorClass<OidcValidationError>()(
  "OidcValidationError",
  {
    reason: Schema.Literals([
      "ProviderNotOidc",
      "MissingIssuer",
      "MissingJwksUrl",
      "MalformedIdToken",
      "UnsupportedAlgorithm",
      "MissingKeyId",
      "UnknownKeyId",
      "JwksFetchFailed",
      "InvalidSignature",
      "IssuerMismatch",
      "AudienceMismatch",
      "ExpiredToken",
      "IssuedAtInFuture",
      "NonceMismatch",
      "ClaimValidationFailed",
    ]),
  },
) {}

const OidcJwtHeader = Schema.Struct({
  alg: Schema.String,
  kid: Schema.optional(Schema.String),
  typ: Schema.optional(Schema.String),
});

const OidcJwk = Schema.Struct({
  kty: Schema.String,
  kid: Schema.optional(Schema.String),
  use: Schema.optional(Schema.String),
  alg: Schema.optional(Schema.String),
  n: Schema.optional(Schema.String),
  e: Schema.optional(Schema.String),
  crv: Schema.optional(Schema.String),
  x: Schema.optional(Schema.String),
  y: Schema.optional(Schema.String),
});

const OidcJwksResponse = Schema.Struct({ keys: Schema.Array(OidcJwk) });

type OidcJwkShape = typeof OidcJwk.Type;

type DecodedJwt = {
  readonly header: typeof OidcJwtHeader.Type;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly signingInput: string;
  readonly signature: Buffer;
};

const isReadonlyRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const decodeJsonString = Schema.decodeUnknownEffect(Schema.UnknownFromJsonString);

const decodeBase64UrlJson = (value: string): Effect.Effect<unknown, OidcValidationError> =>
  decodeJsonString(Buffer.from(value, "base64url").toString("utf8")).pipe(
    Effect.mapError(() => new OidcValidationError({ reason: "MalformedIdToken" })),
  );

const decodeIdToken: (
  idToken: Redacted.Redacted<string>,
) => Effect.Effect<DecodedJwt, OidcValidationError> = Effect.fn(
  "OidcIdTokenValidator.decodeIdToken",
)(function* (idToken: Redacted.Redacted<string>) {
  const parts = Redacted.value(idToken).split(".");
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  if (
    parts.length !== 3 ||
    encodedHeader === undefined ||
    encodedPayload === undefined ||
    encodedSignature === undefined ||
    encodedHeader === "" ||
    encodedPayload === "" ||
    encodedSignature === ""
  ) {
    return yield* new OidcValidationError({ reason: "MalformedIdToken" });
  }
  const header = yield* decodeBase64UrlJson(encodedHeader).pipe(
    Effect.flatMap(Schema.decodeUnknownEffect(OidcJwtHeader)),
    Effect.mapError(() => new OidcValidationError({ reason: "MalformedIdToken" })),
  );
  const claims = yield* decodeBase64UrlJson(encodedPayload).pipe(
    Effect.flatMap((value) =>
      isReadonlyRecord(value)
        ? Effect.succeed(value)
        : Effect.fail(new OidcValidationError({ reason: "MalformedIdToken" })),
    ),
  );
  const signature = yield* Effect.try({
    try: () => Buffer.from(encodedSignature, "base64url"),
    catch: () => new OidcValidationError({ reason: "MalformedIdToken" }),
  });
  return { header, claims, signingInput: `${encodedHeader}.${encodedPayload}`, signature };
});

const stringClaim = (claims: Readonly<Record<string, unknown>>, key: string) => {
  const value = claims[key];
  return typeof value === "string" ? value : undefined;
};

const booleanClaim = (claims: Readonly<Record<string, unknown>>, key: string) => {
  const value = claims[key];
  return typeof value === "boolean" ? value : undefined;
};

const numberClaim = (claims: Readonly<Record<string, unknown>>, key: string) => {
  const value = claims[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
};

const audienceClaim = (
  claims: Readonly<Record<string, unknown>>,
): ReadonlyArray<string> | undefined => {
  const value = claims.aud;
  if (typeof value === "string") return [value];
  if (Array.isArray(value) && value.every((entry) => typeof entry === "string")) return value;
  return undefined;
};

const jwkToJsonWebKey = (jwk: OidcJwkShape): webcrypto.JsonWebKey => ({
  kty: jwk.kty,
  ...(jwk.kid === undefined ? {} : { kid: jwk.kid }),
  ...(jwk.use === undefined ? {} : { use: jwk.use }),
  ...(jwk.alg === undefined ? {} : { alg: jwk.alg }),
  ...(jwk.n === undefined ? {} : { n: jwk.n }),
  ...(jwk.e === undefined ? {} : { e: jwk.e }),
  ...(jwk.crv === undefined ? {} : { crv: jwk.crv }),
  ...(jwk.x === undefined ? {} : { x: jwk.x }),
  ...(jwk.y === undefined ? {} : { y: jwk.y }),
});

const verifyRs256Signature = (input: {
  readonly jwk: OidcJwkShape;
  readonly signingInput: string;
  readonly signature: Buffer;
}): Effect.Effect<void, OidcValidationError> =>
  Effect.try({
    try: () => {
      const verifier = createVerify("RSA-SHA256");
      verifier.update(input.signingInput);
      verifier.end();
      return verifier.verify(
        createPublicKey({ key: jwkToJsonWebKey(input.jwk), format: "jwk" }),
        input.signature,
      );
    },
    catch: () => new OidcValidationError({ reason: "InvalidSignature" }),
  }).pipe(
    Effect.flatMap((valid) =>
      valid ? Effect.void : Effect.fail(new OidcValidationError({ reason: "InvalidSignature" })),
    ),
  );

const validatedOidcIdentity = (input: {
  readonly provider: ResolvedOAuthProvider;
  readonly claims: Readonly<Record<string, unknown>>;
  readonly expectedNonce: Redacted.Redacted<string>;
  readonly now: number;
}): Effect.Effect<ValidatedOidcIdentity, OidcValidationError> => {
  const issuer = stringClaim(input.claims, "iss");
  if (issuer === undefined)
    return Effect.fail(new OidcValidationError({ reason: "ClaimValidationFailed" }));
  if (issuer !== input.provider.issuer)
    return Effect.fail(new OidcValidationError({ reason: "IssuerMismatch" }));
  const subject = stringClaim(input.claims, "sub");
  if (subject === undefined || subject === "") {
    return Effect.fail(new OidcValidationError({ reason: "ClaimValidationFailed" }));
  }
  const audience = audienceClaim(input.claims);
  if (audience === undefined) {
    return Effect.fail(new OidcValidationError({ reason: "AudienceMismatch" }));
  }
  if (!audience.includes(input.provider.clientId)) {
    return Effect.fail(new OidcValidationError({ reason: "AudienceMismatch" }));
  }
  const expiresAtSeconds = numberClaim(input.claims, "exp");
  if (expiresAtSeconds === undefined) {
    return Effect.fail(new OidcValidationError({ reason: "ClaimValidationFailed" }));
  }
  const expiresAt = expiresAtSeconds * 1000;
  if (expiresAt <= input.now) {
    return Effect.fail(new OidcValidationError({ reason: "ExpiredToken" }));
  }
  const issuedAtSeconds = numberClaim(input.claims, "iat");
  if (issuedAtSeconds !== undefined && issuedAtSeconds * 1000 > input.now) {
    return Effect.fail(new OidcValidationError({ reason: "IssuedAtInFuture" }));
  }
  const notBeforeSeconds = numberClaim(input.claims, "nbf");
  if (notBeforeSeconds !== undefined && notBeforeSeconds * 1000 > input.now) {
    return Effect.fail(new OidcValidationError({ reason: "IssuedAtInFuture" }));
  }
  const nonce = stringClaim(input.claims, "nonce");
  if (nonce === undefined || nonce !== Redacted.value(input.expectedNonce)) {
    return Effect.fail(new OidcValidationError({ reason: "NonceMismatch" }));
  }
  const issuedAt = issuedAtSeconds === undefined ? undefined : issuedAtSeconds * 1000;
  const email = stringClaim(input.claims, "email");
  const emailVerified = booleanClaim(input.claims, "email_verified");
  const name = stringClaim(input.claims, "name");
  const image = stringClaim(input.claims, "picture");
  return Effect.succeed({
    issuer,
    subject,
    audience,
    expiresAt,
    ...(issuedAt === undefined ? {} : { issuedAt }),
    nonce,
    ...(email === undefined ? {} : { email }),
    ...(emailVerified === undefined ? {} : { emailVerified }),
    ...(name === undefined ? {} : { name }),
    ...(image === undefined ? {} : { image }),
    rawClaims: input.claims,
  });
};

export class OidcIdTokenValidator extends Context.Service<
  OidcIdTokenValidator,
  {
    readonly validate: (
      input: OidcValidationInput,
    ) => Effect.Effect<ValidatedOidcIdentity, OidcValidationError>;
  }
>()("effect-auth/oauth/OidcIdTokenValidator") {
  static readonly layer = Layer.effect(OidcIdTokenValidator)(
    Effect.gen(function* () {
      const client = yield* HttpClient.HttpClient;
      const cache = new Map<OAuthProviderId, ReadonlyArray<OidcJwkShape>>();
      const fetchJwks = Effect.fn("OidcIdTokenValidator.fetchJwks")(function* (
        provider: ResolvedOAuthProvider,
      ) {
        if (provider.jwksUrl === undefined) {
          return yield* new OidcValidationError({ reason: "MissingJwksUrl" });
        }
        const response = yield* client.get(provider.jwksUrl).pipe(
          Effect.flatMap(HttpClientResponse.filterStatusOk),
          Effect.mapError(() => new OidcValidationError({ reason: "JwksFetchFailed" })),
        );
        const decoded = yield* HttpClientResponse.schemaJson(
          Schema.Struct({ body: OidcJwksResponse }),
        )(response).pipe(
          Effect.mapError(() => new OidcValidationError({ reason: "JwksFetchFailed" })),
        );
        cache.set(provider.id, decoded.body.keys);
        return decoded.body.keys;
      });
      const cachedJwks = Effect.fn("OidcIdTokenValidator.cachedJwks")(function* (
        provider: ResolvedOAuthProvider,
      ) {
        const cached = cache.get(provider.id);
        return cached ?? (yield* fetchJwks(provider));
      });
      const findKey = (keys: ReadonlyArray<OidcJwkShape>, kid: string) =>
        keys.find((key) => key.kid === kid);
      return {
        validate: Effect.fn("OidcIdTokenValidator.validate")(function* (input) {
          if (!input.provider.isOidc) {
            return yield* new OidcValidationError({ reason: "ProviderNotOidc" });
          }
          if (input.provider.issuer === undefined) {
            return yield* new OidcValidationError({ reason: "MissingIssuer" });
          }
          if (input.provider.jwksUrl === undefined) {
            return yield* new OidcValidationError({ reason: "MissingJwksUrl" });
          }
          const decoded = yield* decodeIdToken(input.idToken);
          if (decoded.header.alg !== "RS256") {
            return yield* new OidcValidationError({ reason: "UnsupportedAlgorithm" });
          }
          if (decoded.header.kid === undefined || decoded.header.kid === "") {
            return yield* new OidcValidationError({ reason: "MissingKeyId" });
          }
          const keys = yield* cachedJwks(input.provider);
          const key =
            findKey(keys, decoded.header.kid) ??
            findKey(yield* fetchJwks(input.provider), decoded.header.kid);
          if (key === undefined) {
            return yield* new OidcValidationError({ reason: "UnknownKeyId" });
          }
          yield* verifyRs256Signature({
            jwk: key,
            signingInput: decoded.signingInput,
            signature: decoded.signature,
          });
          const now = input.now ?? (yield* Clock.currentTimeMillis);
          return yield* validatedOidcIdentity({
            provider: input.provider,
            claims: decoded.claims,
            expectedNonce: input.expectedNonce,
            now,
          });
        }),
      };
    }),
  );
}

const OAuthTokenEndpointResponse = Schema.Struct({
  access_token: Schema.optional(Schema.String),
  refresh_token: Schema.optional(Schema.String),
  id_token: Schema.optional(Schema.String),
  token_type: Schema.optional(Schema.String),
  scope: Schema.optional(Schema.String),
  expires_in: Schema.optional(Schema.Number),
  refresh_expires_in: Schema.optional(Schema.Number),
  refresh_token_expires_in: Schema.optional(Schema.Number),
});
const OAuthUserInfoResponse = Schema.Record(Schema.String, Schema.Unknown);

const tokenExpiry = (
  now: number,
  seconds: number | undefined,
): Effect.Effect<number | undefined, OAuthProviderClientError> => {
  if (seconds === undefined) return Effect.sync((): number | undefined => undefined);
  return Number.isFinite(seconds) && seconds >= 0
    ? Effect.succeed(now + seconds * 1000)
    : Effect.fail(new OAuthProviderClientError({ reason: "TokenResponseInvalid" }));
};

const tokenRequest = (input: OAuthAuthorizationCodeExchangeInput) => {
  const baseParams: Record<string, string> = {
    grant_type: "authorization_code",
    code: Redacted.value(input.code),
    redirect_uri: input.redirectUri.href,
    ...(input.codeVerifier === undefined
      ? {}
      : { code_verifier: Redacted.value(input.codeVerifier) }),
  };
  if (input.provider.tokenEndpointAuthMethod === "client_secret_basic") {
    return HttpClientRequest.post(input.provider.tokenUrl).pipe(
      HttpClientRequest.bodyUrlParams(baseParams),
      HttpClientRequest.basicAuth(input.provider.clientId, input.provider.clientSecret),
      HttpClientRequest.accept("application/json"),
    );
  }
  if (input.provider.tokenEndpointAuthMethod === "client_secret_post") {
    return HttpClientRequest.post(input.provider.tokenUrl).pipe(
      HttpClientRequest.bodyUrlParams({
        ...baseParams,
        client_id: input.provider.clientId,
        client_secret: Redacted.value(input.provider.clientSecret),
      }),
      HttpClientRequest.accept("application/json"),
    );
  }
  return undefined;
};

export class OAuthProviderClient extends Context.Service<
  OAuthProviderClient,
  {
    readonly exchangeCode: (
      input: OAuthAuthorizationCodeExchangeInput,
    ) => Effect.Effect<OAuthTokenSet, OAuthProviderClientError>;
    readonly resolveIdentity: (
      input: OAuthProfileMappingInput,
    ) => Effect.Effect<OAuthProviderIdentityResult, OAuthProviderClientError>;
  }
>()("effect-auth/oauth/OAuthProviderClient") {
  static readonly layer = Layer.effect(OAuthProviderClient)(
    Effect.gen(function* () {
      const client = yield* HttpClient.HttpClient;
      return {
        exchangeCode: Effect.fn("OAuthProviderClient.exchangeCode")(function* (input) {
          const request = tokenRequest(input);
          if (request === undefined) {
            return yield* new OAuthProviderClientError({
              reason: "UnsupportedTokenEndpointAuthMethod",
            });
          }
          const response = yield* client.execute(request).pipe(
            Effect.flatMap(HttpClientResponse.filterStatusOk),
            Effect.mapError(() => new OAuthProviderClientError({ reason: "TokenRequestFailed" })),
          );
          const decoded = yield* HttpClientResponse.schemaJson(
            Schema.Struct({ body: OAuthTokenEndpointResponse }),
          )(response).pipe(
            Effect.mapError(() => new OAuthProviderClientError({ reason: "TokenResponseInvalid" })),
          );
          const accessToken = decoded.body.access_token;
          if (accessToken === undefined || accessToken === "") {
            return yield* new OAuthProviderClientError({ reason: "MissingAccessToken" });
          }
          const now = yield* Clock.currentTimeMillis;
          const accessTokenExpiresAt = yield* tokenExpiry(now, decoded.body.expires_in);
          const refreshTokenExpiresAt = yield* tokenExpiry(
            now,
            decoded.body.refresh_expires_in ?? decoded.body.refresh_token_expires_in,
          );
          return {
            accessToken: Redacted.make(accessToken),
            ...(decoded.body.refresh_token === undefined
              ? {}
              : { refreshToken: Redacted.make(decoded.body.refresh_token) }),
            ...(decoded.body.id_token === undefined
              ? {}
              : { idToken: Redacted.make(decoded.body.id_token) }),
            ...(decoded.body.token_type === undefined
              ? {}
              : { tokenType: decoded.body.token_type }),
            ...(decoded.body.scope === undefined ? {} : { scope: decoded.body.scope }),
            ...(accessTokenExpiresAt === undefined ? {} : { accessTokenExpiresAt }),
            ...(refreshTokenExpiresAt === undefined ? {} : { refreshTokenExpiresAt }),
          };
        }),
        resolveIdentity: Effect.fn("OAuthProviderClient.resolveIdentity")(function* (input) {
          let userInfo = input.userInfo;
          const fetchUserInfo = Effect.fn("OAuthProviderClient.fetchUserInfo")(function* () {
            const userInfoUrl = input.provider.userInfoUrl;
            if (userInfoUrl === undefined) {
              return undefined;
            }
            const accessToken = input.tokenSet.accessToken;
            if (accessToken === undefined) {
              return yield* new OAuthProviderClientError({ reason: "MissingAccessToken" });
            }
            const request = HttpClientRequest.get(userInfoUrl).pipe(
              HttpClientRequest.bearerToken(accessToken),
              HttpClientRequest.accept("application/json"),
            );
            const response = yield* client.execute(request).pipe(
              Effect.flatMap(HttpClientResponse.filterStatusOk),
              Effect.mapError(
                () => new OAuthProviderClientError({ reason: "UserInfoRequestFailed" }),
              ),
            );
            const decoded = yield* HttpClientResponse.schemaJson(
              Schema.Struct({ body: OAuthUserInfoResponse }),
            )(response).pipe(
              Effect.mapError(
                () => new OAuthProviderClientError({ reason: "UserInfoResponseInvalid" }),
              ),
            );
            return decoded.body;
          });
          if (
            input.provider.isOidc &&
            input.validatedOidcIdentity !== undefined &&
            input.provider.mapProfile === undefined
          ) {
            const identity = input.validatedOidcIdentity;
            if (identity.email !== undefined && identity.email.trim() !== "") {
              return {
                providerId: input.provider.id,
                providerAccountId: identity.subject,
                email: identity.email,
                emailVerified: identity.emailVerified ?? false,
                name:
                  identity.name === undefined || identity.name.trim() === ""
                    ? identity.email
                    : identity.name,
                image:
                  identity.image === undefined || identity.image.trim() === ""
                    ? null
                    : identity.image,
                tokenSet: input.tokenSet,
              } satisfies OAuthProviderIdentityResult;
            }
            if (userInfo === undefined) {
              userInfo = yield* fetchUserInfo();
            }
            if (userInfo === undefined) {
              return yield* new OAuthProviderClientError({ reason: "MissingProviderEmail" });
            }
            const userInfoSubject = stringClaim(userInfo, "sub");
            if (userInfoSubject !== undefined && userInfoSubject !== identity.subject) {
              return yield* new OAuthProviderClientError({ reason: "ProfileMappingFailed" });
            }
            const email = stringClaim(userInfo, "email");
            if (email === undefined || email.trim() === "") {
              return yield* new OAuthProviderClientError({ reason: "MissingProviderEmail" });
            }
            const name = stringClaim(userInfo, "name");
            const picture = stringClaim(userInfo, "picture") ?? stringClaim(userInfo, "image");
            return {
              providerId: input.provider.id,
              providerAccountId: identity.subject,
              email,
              emailVerified: booleanClaim(userInfo, "email_verified") ?? false,
              name: name === undefined || name.trim() === "" ? email : name,
              image: picture === undefined || picture.trim() === "" ? null : picture,
              tokenSet: input.tokenSet,
            } satisfies OAuthProviderIdentityResult;
          }
          if (userInfo === undefined) {
            userInfo = yield* fetchUserInfo();
          }
          if (input.provider.mapProfile === undefined) {
            return yield* new OAuthProviderClientError({ reason: "ProfileMappingFailed" });
          }
          const profileInput = {
            provider: input.provider,
            tokenSet: input.tokenSet,
            ...(input.validatedOidcIdentity === undefined
              ? {}
              : { validatedOidcIdentity: input.validatedOidcIdentity }),
            ...(userInfo === undefined ? {} : { userInfo }),
          } satisfies OAuthProfileMappingInput;
          const profile = yield* input.provider
            .mapProfile(profileInput)
            .pipe(
              Effect.mapError(
                () => new OAuthProviderClientError({ reason: "ProfileMappingFailed" }),
              ),
            );
          if (profile.email.trim() === "") {
            return yield* new OAuthProviderClientError({ reason: "MissingProviderEmail" });
          }
          return {
            providerId: input.provider.id,
            providerAccountId: profile.providerAccountId,
            email: profile.email,
            emailVerified: profile.emailVerified,
            name: profile.name,
            image: profile.image,
            tokenSet: input.tokenSet,
          };
        }),
      };
    }),
  );
}

const decodeOAuthProviderId = Schema.decodeUnknownEffect(OAuthProviderId);
const reservedAuthorizationParams = new Set([
  "client_id",
  "redirect_uri",
  "response_type",
  "state",
  "scope",
  "code_challenge",
  "code_challenge_method",
  "nonce",
]);

const OAuthDiscoveryDocument = Schema.Struct({
  authorization_endpoint: Schema.String,
  token_endpoint: Schema.String,
  userinfo_endpoint: Schema.optional(Schema.String),
  jwks_uri: Schema.optional(Schema.String),
  issuer: Schema.optional(Schema.String),
});

const isOAuthScopeToken = (scope: string) => /^[\x21\x23-\x5B\x5D-\x7E]+$/u.test(scope);

export const normalizeOAuthScopes: (
  scopes: ReadonlyArray<string>,
) => Effect.Effect<ReadonlyArray<string>, OAuthProviderConfigError> = Effect.fn(
  "OAuth.normalizeOAuthScopes",
)(function* (scopes) {
  const normalized: Array<string> = [];
  for (const scope of scopes) {
    const valid = isOAuthScopeToken(scope);
    if (!valid) {
      return yield* new OAuthProviderConfigError({ reason: "InvalidScope" });
    }
    if (!normalized.includes(scope)) {
      normalized.push(scope);
    }
  }
  return normalized;
});

const parseUrl = (
  value: string,
  providerId: string,
): Effect.Effect<URL, OAuthProviderConfigError> =>
  Effect.try({
    try: () => new URL(value),
    catch: () => new OAuthProviderConfigError({ reason: "DiscoveryFailed", providerId }),
  });

const resolveDiscovery = (
  provider: OAuthProviderInput,
): Effect.Effect<OAuthProviderEndpointsInput, OAuthProviderConfigError, HttpClient.HttpClient> => {
  if (provider.discoveryUrl === undefined) {
    return provider.endpoints === undefined
      ? Effect.fail(
          new OAuthProviderConfigError({ reason: "MissingEndpoints", providerId: provider.id }),
        )
      : Effect.succeed(provider.endpoints);
  }
  return HttpClient.get(provider.discoveryUrl).pipe(
    Effect.flatMap(HttpClientResponse.schemaJson(Schema.Struct({ body: OAuthDiscoveryDocument }))),
    Effect.flatMap(({ body }) =>
      Effect.gen(function* () {
        const authorizationUrl = yield* parseUrl(body.authorization_endpoint, provider.id);
        const tokenUrl = yield* parseUrl(body.token_endpoint, provider.id);
        const userInfoUrl =
          body.userinfo_endpoint === undefined
            ? undefined
            : yield* parseUrl(body.userinfo_endpoint, provider.id);
        const jwksUrl =
          body.jwks_uri === undefined ? undefined : yield* parseUrl(body.jwks_uri, provider.id);
        return {
          authorizationUrl,
          tokenUrl,
          ...(userInfoUrl === undefined ? {} : { userInfoUrl }),
          ...(jwksUrl === undefined ? {} : { jwksUrl }),
          ...(body.issuer === undefined ? {} : { issuer: body.issuer }),
        };
      }),
    ),
    Effect.mapError(
      () => new OAuthProviderConfigError({ reason: "DiscoveryFailed", providerId: provider.id }),
    ),
  );
};

const PlainOAuthProviderConfigInput = Schema.Struct({
  providers: Schema.Array(Schema.Unknown),
});
const isPlainOAuthProviderConfigRecord = Schema.is(PlainOAuthProviderConfigInput);

const isPlainOAuthProviderConfigInput = (
  input: OAuthProviderConfigLayerInput,
): input is OAuthProviderConfigInput => isPlainOAuthProviderConfigRecord(input);

const resolveProviderConfig = (
  input: OAuthProviderConfigLayerInput,
): Effect.Effect<OAuthProviderConfigInput, Config.ConfigError> =>
  isPlainOAuthProviderConfigInput(input) ? Effect.succeed(input) : Config.unwrap(input).asEffect();

const validateExtraAuthorizationParams = (
  provider: OAuthProviderInput,
): Effect.Effect<Readonly<Record<string, string>>, OAuthProviderConfigError> => {
  const params = provider.extraAuthorizationParams ?? {};
  for (const key of Object.keys(params)) {
    if (reservedAuthorizationParams.has(key.toLowerCase())) {
      return Effect.fail(
        new OAuthProviderConfigError({
          reason: "ReservedAuthorizationParam",
          providerId: provider.id,
        }),
      );
    }
  }
  return Effect.succeed(params);
};

const resolveProvider = Effect.fn("OAuthProviders.resolveProvider")(function* (
  provider: OAuthProviderInput,
) {
  const id = yield* decodeOAuthProviderId(provider.id).pipe(
    Effect.mapError(
      () => new OAuthProviderConfigError({ reason: "InvalidProviderId", providerId: provider.id }),
    ),
  );
  const endpoints = yield* resolveDiscovery(provider);
  const defaultScopes = yield* normalizeOAuthScopes(provider.defaultScopes ?? []).pipe(
    Effect.mapError(
      (error) => new OAuthProviderConfigError({ reason: error.reason, providerId: provider.id }),
    ),
  );
  const extraAuthorizationParams = yield* validateExtraAuthorizationParams(provider);
  const isOidc =
    provider.discoveryUrl !== undefined ||
    endpoints.issuer !== undefined ||
    endpoints.jwksUrl !== undefined;
  if (!isOidc && provider.mapProfile === undefined) {
    return yield* new OAuthProviderConfigError({
      reason: "GenericProviderRequiresProfileMapper",
      providerId: provider.id,
    });
  }
  return {
    id,
    clientId: provider.clientId,
    clientSecret: provider.clientSecret,
    defaultScopes,
    authorizationUrl: endpoints.authorizationUrl,
    tokenUrl: endpoints.tokenUrl,
    ...(endpoints.userInfoUrl === undefined ? {} : { userInfoUrl: endpoints.userInfoUrl }),
    ...(endpoints.issuer === undefined ? {} : { issuer: endpoints.issuer }),
    ...(endpoints.jwksUrl === undefined ? {} : { jwksUrl: endpoints.jwksUrl }),
    isOidc,
    pkce: provider.pkce ?? "S256",
    tokenEndpointAuthMethod: provider.tokenEndpointAuthMethod ?? "client_secret_basic",
    extraAuthorizationParams,
    trustedEmail: provider.trustedEmail ?? false,
    ...(provider.mapProfile === undefined ? {} : { mapProfile: provider.mapProfile }),
  } satisfies ResolvedOAuthProvider;
});

export class OAuthProviders extends Context.Service<
  OAuthProviders,
  {
    readonly get: (
      providerId: OAuthProviderId,
    ) => Effect.Effect<ResolvedOAuthProvider, OAuthProviderNotFound>;
    readonly list: Effect.Effect<ReadonlyArray<ResolvedOAuthProvider>>;
  }
>()("effect-auth/oauth/OAuthProviders") {
  static readonly layer = (
    input: OAuthProviderConfigLayerInput,
  ): Layer.Layer<
    OAuthProviders,
    OAuthProviderConfigError | Config.ConfigError,
    HttpClient.HttpClient
  > =>
    Layer.effect(OAuthProviders)(
      Effect.gen(function* () {
        const config = yield* resolveProviderConfig(input);
        const providers = yield* Effect.all(config.providers.map(resolveProvider));
        const byId = new Map<string, ResolvedOAuthProvider>();
        for (const provider of providers) {
          const key = String(provider.id);
          if (byId.has(key)) {
            return yield* new OAuthProviderConfigError({
              reason: "DuplicateProviderId",
              providerId: key,
            });
          }
          byId.set(key, provider);
        }
        return {
          get: (providerId) =>
            Effect.suspend(() => {
              const provider = byId.get(String(providerId));
              return provider === undefined
                ? Effect.fail(new OAuthProviderNotFound({ providerId: String(providerId) }))
                : Effect.succeed(provider);
            }),
          list: Effect.succeed(providers),
        };
      }),
    );
}

export const OAuthFlow = Schema.Literals(["SignIn", "Link"]);
export type OAuthFlow = typeof OAuthFlow.Type;

export const OAuthStateHandle = Schema.RedactedFromValue(
  Schema.String.pipe(
    Schema.check(
      Schema.makeFilter((value) =>
        /^[A-Za-z0-9_-]{43,128}$/u.test(value)
          ? undefined
          : "Expected generated OAuth state handle",
      ),
    ),
  ),
  { label: "OAuthStateHandle" },
);
export type OAuthStateHandle = typeof OAuthStateHandle.Type;

export const OAuthStateHash = Schema.RedactedFromValue(Schema.String, {
  label: "OAuthStateHash",
});
export type OAuthStateHash = typeof OAuthStateHash.Type;

export interface OAuthStateSecrets {
  readonly codeVerifier?: Redacted.Redacted<string>;
  readonly nonce?: Redacted.Redacted<string>;
}

export interface StoredOAuthState {
  readonly id: string;
  readonly stateHash: OAuthStateHash;
  readonly providerId: OAuthProviderId;
  readonly flow: OAuthFlow;
  readonly redirectUri: URL;
  readonly scopes: ReadonlyArray<string>;
  readonly allowSignUp: boolean;
  readonly linkUserId?: AuthUserId;
  readonly encryptedCodeVerifier?: string;
  readonly encryptedNonce?: string;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly consumedAt?: number;
}

export interface StoreOAuthState {
  readonly stateHash: OAuthStateHash;
  readonly providerId: OAuthProviderId;
  readonly flow: OAuthFlow;
  readonly redirectUri: URL;
  readonly scopes: ReadonlyArray<string>;
  readonly allowSignUp: boolean;
  readonly linkUserId?: AuthUserId;
  readonly encryptedCodeVerifier?: string;
  readonly encryptedNonce?: string;
  readonly now: number;
  readonly expiresAt: number;
}

export interface ConsumeOAuthState {
  readonly stateHash: OAuthStateHash;
  readonly providerId: OAuthProviderId;
  readonly flow: OAuthFlow;
  readonly now: number;
}

export interface OAuthStateCreateInput {
  readonly providerId: OAuthProviderId;
  readonly flow: OAuthFlow;
  readonly redirectUri: URL;
  readonly scopes: ReadonlyArray<string>;
  readonly allowSignUp: boolean;
  readonly linkUserId?: AuthUserId;
  readonly secrets: OAuthStateSecrets;
}

export interface OAuthStateCreateResult {
  readonly handle: OAuthStateHandle;
  readonly record: StoredOAuthState;
}

export class OAuthStateFailure extends Schema.TaggedErrorClass<OAuthStateFailure>()(
  "OAuthStateFailure",
  {
    reason: Schema.Literals([
      "UnavailableEntropy",
      "HashingFailed",
      "SecretProtectionFailed",
      "SecretUnprotectFailed",
    ]),
  },
) {}

const decodeOAuthStateHandle = Schema.decodeUnknownEffect(OAuthStateHandle);
const decodeOAuthStateHash = Schema.decodeUnknownEffect(OAuthStateHash);
const stateEnvelopeVersion = "ea_os_v1";

const sha256Base64Url = (value: string) =>
  createHash("sha256").update(value, "utf8").digest("base64url");
const sha256Hex = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

const makeRandomSecret = Effect.fn("OAuth.makeRandomSecret")(function* () {
  return yield* Effect.try({
    try: () => Redacted.make(randomBytes(32).toString("base64url")),
    catch: () => new OAuthStateFailure({ reason: "UnavailableEntropy" }),
  });
});

const makeStateHandle = Effect.fn("OAuthState.makeStateHandle")(function* () {
  const handle = yield* Effect.try({
    try: () => randomBytes(32).toString("base64url"),
    catch: () => new OAuthStateFailure({ reason: "UnavailableEntropy" }),
  });
  return yield* decodeOAuthStateHandle(handle).pipe(
    Effect.mapError(() => new OAuthStateFailure({ reason: "UnavailableEntropy" })),
  );
});

const hashStateHandle = (
  handle: OAuthStateHandle,
): Effect.Effect<OAuthStateHash, OAuthStateFailure> =>
  decodeOAuthStateHash(sha256Hex(Redacted.value(handle))).pipe(
    Effect.mapError(() => new OAuthStateFailure({ reason: "HashingFailed" })),
  );

const stateSecretAad = (input: {
  readonly providerId: OAuthProviderId;
  readonly flow: OAuthFlow;
  readonly stateHash: OAuthStateHash;
  readonly kind: "codeVerifier" | "nonce";
}) =>
  Buffer.from(
    `provider=${String(input.providerId)};flow=${input.flow};state=${Redacted.value(
      input.stateHash,
    )};kind=${input.kind}`,
    "utf8",
  );

const protectStateSecret = (
  material: AuthFeatureKeyMaterial,
  input: {
    readonly providerId: OAuthProviderId;
    readonly flow: OAuthFlow;
    readonly stateHash: OAuthStateHash;
    readonly kind: "codeVerifier" | "nonce";
    readonly plaintext: Redacted.Redacted<string>;
  },
): Effect.Effect<string, OAuthStateFailure> =>
  Effect.try({
    try: () => {
      const nonce = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", Redacted.value(material.keyBytes), nonce);
      cipher.setAAD(stateSecretAad(input));
      const ciphertext = Buffer.concat([
        cipher.update(Redacted.value(input.plaintext), "utf8"),
        cipher.final(),
      ]);
      const tag = cipher.getAuthTag();
      return [
        stateEnvelopeVersion,
        String(material.keyId),
        nonce.toString("base64url"),
        ciphertext.toString("base64url"),
        tag.toString("base64url"),
      ].join(".");
    },
    catch: () => new OAuthStateFailure({ reason: "SecretProtectionFailed" }),
  });

const unprotectStateSecret = (
  material: AuthFeatureKeyMaterial,
  input: {
    readonly providerId: OAuthProviderId;
    readonly flow: OAuthFlow;
    readonly stateHash: OAuthStateHash;
    readonly kind: "codeVerifier" | "nonce";
    readonly ciphertext: string;
  },
): Effect.Effect<Redacted.Redacted<string>, OAuthStateFailure> => {
  const [version, keyId, nonce, ciphertext, tag] = input.ciphertext.split(".");
  if (
    version !== stateEnvelopeVersion ||
    keyId !== String(material.keyId) ||
    nonce === undefined ||
    ciphertext === undefined ||
    tag === undefined
  ) {
    return Effect.fail(new OAuthStateFailure({ reason: "SecretUnprotectFailed" }));
  }
  return Effect.try({
    try: () => {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        Redacted.value(material.keyBytes),
        Buffer.from(nonce, "base64url"),
      );
      decipher.setAAD(stateSecretAad(input));
      decipher.setAuthTag(Buffer.from(tag, "base64url"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "base64url")),
        decipher.final(),
      ]).toString("utf8");
      return Redacted.make(plaintext);
    },
    catch: () => new OAuthStateFailure({ reason: "SecretUnprotectFailed" }),
  });
};

export class OAuthState extends Context.Service<
  OAuthState,
  {
    readonly create: (
      input: OAuthStateCreateInput,
    ) => Effect.Effect<OAuthStateCreateResult, OAuthStateFailure | AuthStorageFailure>;
    readonly consume: (input: {
      readonly providerId: OAuthProviderId;
      readonly flow: OAuthFlow;
      readonly handle: OAuthStateHandle;
    }) => Effect.Effect<
      StoredOAuthState & { readonly secrets: OAuthStateSecrets },
      OAuthStateFailure | AuthStorageFailure
    >;
  }
>()("effect-auth/oauth/OAuthState") {
  static readonly layer = Layer.effect(OAuthState)(
    Effect.gen(function* () {
      const storage = yield* AuthStorage;
      const authConfig = yield* AuthLiveConfig;
      const keyMaterial = yield* AuthFeatureKeyMaterialService;
      const material = yield* keyMaterial.requireForFeature("OAuthStateSecrets");
      return {
        create: Effect.fn("OAuthState.create")(function* (input) {
          const handle = yield* makeStateHandle();
          const stateHash = yield* hashStateHandle(handle);
          const now = yield* Clock.currentTimeMillis;
          const secretContext = {
            providerId: input.providerId,
            flow: input.flow,
            stateHash,
          };
          const encryptedCodeVerifier =
            input.secrets.codeVerifier === undefined
              ? undefined
              : yield* protectStateSecret(material, {
                  ...secretContext,
                  kind: "codeVerifier",
                  plaintext: input.secrets.codeVerifier,
                });
          const encryptedNonce =
            input.secrets.nonce === undefined
              ? undefined
              : yield* protectStateSecret(material, {
                  ...secretContext,
                  kind: "nonce",
                  plaintext: input.secrets.nonce,
                });
          const record = yield* storage.storeOAuthState({
            stateHash,
            providerId: input.providerId,
            flow: input.flow,
            redirectUri: input.redirectUri,
            scopes: input.scopes,
            allowSignUp: input.allowSignUp,
            ...(input.linkUserId === undefined ? {} : { linkUserId: input.linkUserId }),
            ...(encryptedCodeVerifier === undefined ? {} : { encryptedCodeVerifier }),
            ...(encryptedNonce === undefined ? {} : { encryptedNonce }),
            now,
            expiresAt: now + authConfig.oauthState.ttlMillis,
          });
          return { handle, record };
        }),
        consume: Effect.fn("OAuthState.consume")(function* (input) {
          const stateHash = yield* hashStateHandle(input.handle);
          const now = yield* Clock.currentTimeMillis;
          const record = yield* storage.consumeOAuthState({
            stateHash,
            providerId: input.providerId,
            flow: input.flow,
            now,
          });
          const secretContext = {
            providerId: record.providerId,
            flow: record.flow,
            stateHash: record.stateHash,
          };
          const codeVerifier =
            record.encryptedCodeVerifier === undefined
              ? undefined
              : yield* unprotectStateSecret(material, {
                  ...secretContext,
                  kind: "codeVerifier",
                  ciphertext: record.encryptedCodeVerifier,
                });
          const nonce =
            record.encryptedNonce === undefined
              ? undefined
              : yield* unprotectStateSecret(material, {
                  ...secretContext,
                  kind: "nonce",
                  ciphertext: record.encryptedNonce,
                });
          return {
            ...record,
            secrets: {
              ...(codeVerifier === undefined ? {} : { codeVerifier }),
              ...(nonce === undefined ? {} : { nonce }),
            },
          };
        }),
      };
    }),
  );
}

const OAuthStateDefaultLayer = OAuthState.layer.pipe(
  Layer.provide(AuthFeatureKeyMaterialService.layer),
);
const OAuthDependenciesLayer = Layer.mergeAll(
  AuthTokenLive,
  OAuthStateDefaultLayer,
  OidcIdTokenValidator.layer,
);

export interface OAuthStartSignInInput {
  readonly providerId: unknown;
  readonly redirectUri: URL;
  readonly scopes?: ReadonlyArray<string>;
  readonly allowSignUp?: boolean;
  readonly ip?: unknown;
}

export interface OAuthStartLinkInput {
  readonly providerId: unknown;
  readonly redirectUri: URL;
  readonly sessionToken: unknown;
  readonly scopes?: ReadonlyArray<string>;
  readonly ip?: unknown;
}

export interface OAuthAuthorizationStartResult {
  readonly providerId: OAuthProviderId;
  readonly authorizationUrl: URL;
  readonly state: OAuthStateHandle;
  readonly scopes: ReadonlyArray<string>;
  readonly flow: OAuthFlow;
}

export class OAuthStartError extends Schema.TaggedErrorClass<OAuthStartError>()("OAuthStartError", {
  reason: Schema.Literals([
    "UnknownProvider",
    "InvalidScope",
    "ReservedAuthorizationParam",
    "InvalidRedirectUri",
    "UnauthorizedLinkFlow",
    "StateCreationFailed",
  ]),
}) {}

export interface OAuthCallbackInput {
  readonly providerId: unknown;
  readonly state: unknown;
  readonly code?: unknown;
  readonly error?: unknown;
  readonly errorDescription?: unknown;
  readonly callbackMethod: "GET" | "POST";
  readonly ip?: unknown;
  readonly userAgent?: string;
}

export interface OAuthSignInCallbackSuccess {
  readonly flow: "SignIn";
  readonly user: AuthUser;
  readonly account: OAuthProviderAccount;
  readonly session: StoredSession;
  readonly sessionToken: SessionToken;
  readonly isNewUser: boolean;
}

export interface OAuthLinkCallbackSuccess {
  readonly flow: "Link";
  readonly user: AuthUser;
  readonly account: OAuthProviderAccount;
  readonly isNewUser: false;
}

export type OAuthCallbackSuccess = OAuthSignInCallbackSuccess | OAuthLinkCallbackSuccess;

export class OAuthCallbackError extends Schema.TaggedErrorClass<OAuthCallbackError>()(
  "OAuthCallbackError",
  {
    reason: Schema.Literals([
      "ProviderReturnedError",
      "MissingAuthorizationCode",
      "InvalidState",
      "ExpiredState",
      "ConsumedState",
      "ProviderMismatch",
      "TokenExchangeFailed",
      "IdentityValidationFailed",
      "ProviderEmailRequired",
      "ProviderTokenProtectionFailed",
      "StorageFailed",
      "SessionCreationFailed",
    ]),
  },
) {}

const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);

const parseStartProvider = Effect.fn("OAuth.parseStartProvider")(function* (
  providers: typeof OAuthProviders.Service,
  input: unknown,
) {
  const providerId = yield* decodeOAuthProviderId(input).pipe(
    Effect.mapError(() => new OAuthStartError({ reason: "UnknownProvider" })),
  );
  const provider = yield* providers
    .get(providerId)
    .pipe(Effect.mapError(() => new OAuthStartError({ reason: "UnknownProvider" })));
  return provider;
});

const parseRequestedScopes = (
  provider: ResolvedOAuthProvider,
  scopes: ReadonlyArray<string> | undefined,
): Effect.Effect<ReadonlyArray<string>, OAuthStartError> =>
  normalizeOAuthScopes([...provider.defaultScopes, ...(scopes ?? [])]).pipe(
    Effect.mapError(() => new OAuthStartError({ reason: "InvalidScope" })),
  );

const validateRedirectUri = (redirectUri: URL): Effect.Effect<URL, OAuthStartError> =>
  redirectUri instanceof URL
    ? Effect.succeed(redirectUri)
    : Effect.fail(new OAuthStartError({ reason: "InvalidRedirectUri" }));

const parseCallbackProvider = Effect.fn("OAuth.parseCallbackProvider")(function* (
  providers: typeof OAuthProviders.Service,
  input: unknown,
) {
  const providerId = yield* decodeOAuthProviderId(input).pipe(
    Effect.mapError(() => new OAuthCallbackError({ reason: "ProviderMismatch" })),
  );
  return yield* providers
    .get(providerId)
    .pipe(Effect.mapError(() => new OAuthCallbackError({ reason: "ProviderMismatch" })));
});

const parseCallbackStateHandle = (
  input: unknown,
): Effect.Effect<OAuthStateHandle, OAuthCallbackError> =>
  decodeOAuthStateHandle(Redacted.isRedacted(input) ? Redacted.value(input) : input).pipe(
    Effect.mapError(() => new OAuthCallbackError({ reason: "InvalidState" })),
  );

const parseCallbackCode = (
  input: unknown,
): Effect.Effect<Redacted.Redacted<string>, OAuthCallbackError> => {
  if (input === undefined) {
    return Effect.fail(new OAuthCallbackError({ reason: "MissingAuthorizationCode" }));
  }
  const value = Redacted.isRedacted(input) ? Redacted.value(input) : input;
  return typeof value === "string" && value.length > 0
    ? Effect.succeed(Redacted.make(value))
    : Effect.fail(new OAuthCallbackError({ reason: "MissingAuthorizationCode" }));
};

const mapOAuthStateConsumeFailure = (error: OAuthStateFailure | AuthStorageFailure) => {
  if (Predicate.isTagged(error, "AuthStorageFailure")) {
    if (error.reason === "TokenExpired") return new OAuthCallbackError({ reason: "ExpiredState" });
    if (error.reason === "TokenConsumed")
      return new OAuthCallbackError({ reason: "ConsumedState" });
    if (error.reason === "NotFound") return new OAuthCallbackError({ reason: "InvalidState" });
  }
  return error;
};

const mapOAuthAtomicStorageFailure = (error: OAuthAccountStorageFailure | AuthStorageFailure) =>
  Predicate.isTagged(error, "AuthStorageFailure")
    ? new OAuthCallbackError({ reason: "StorageFailed" })
    : error;

const mapOAuthSignInWithSessionStorageFailure = (
  error: OAuthAccountStorageFailure | AuthStorageFailure | OAuthSessionStorageFailure,
) =>
  Predicate.isTagged(error, "OAuthSessionStorageFailure")
    ? new OAuthCallbackError({ reason: "SessionCreationFailed" })
    : mapOAuthAtomicStorageFailure(error);

const protectProviderTokenSet: (
  protection: typeof ProviderTokenProtection.Service,
  input: {
    readonly providerId: OAuthProviderId;
    readonly providerAccountId: string;
    readonly tokenSet: OAuthTokenSet;
  },
) => Effect.Effect<ProtectedProviderTokenSet, ProviderTokenProtectionFailure> = Effect.fn(
  "OAuth.protectProviderTokenSet",
)(function* (protection, input) {
  const accessToken =
    input.tokenSet.accessToken === undefined
      ? undefined
      : yield* protection.protect({
          providerId: input.providerId,
          providerAccountId: input.providerAccountId,
          kind: "AccessToken",
          plaintext: input.tokenSet.accessToken,
        });
  const refreshToken =
    input.tokenSet.refreshToken === undefined
      ? undefined
      : yield* protection.protect({
          providerId: input.providerId,
          providerAccountId: input.providerAccountId,
          kind: "RefreshToken",
          plaintext: input.tokenSet.refreshToken,
        });
  const idToken =
    input.tokenSet.idToken === undefined
      ? undefined
      : yield* protection.protect({
          providerId: input.providerId,
          providerAccountId: input.providerAccountId,
          kind: "IdToken",
          plaintext: input.tokenSet.idToken,
        });
  return {
    ...(accessToken === undefined ? {} : { accessToken }),
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(idToken === undefined ? {} : { idToken }),
    ...(input.tokenSet.tokenType === undefined ? {} : { tokenType: input.tokenSet.tokenType }),
    ...(input.tokenSet.scope === undefined ? {} : { scope: input.tokenSet.scope }),
    ...(input.tokenSet.accessTokenExpiresAt === undefined
      ? {}
      : { accessTokenExpiresAt: input.tokenSet.accessTokenExpiresAt }),
    ...(input.tokenSet.refreshTokenExpiresAt === undefined
      ? {}
      : { refreshTokenExpiresAt: input.tokenSet.refreshTokenExpiresAt }),
  };
});

const makePkceChallenge = (verifier: Redacted.Redacted<string>) =>
  sha256Base64Url(Redacted.value(verifier));

const buildAuthorizationUrl = (input: {
  readonly provider: ResolvedOAuthProvider;
  readonly redirectUri: URL;
  readonly state: OAuthStateHandle;
  readonly scopes: ReadonlyArray<string>;
  readonly codeVerifier?: Redacted.Redacted<string>;
  readonly nonce?: Redacted.Redacted<string>;
}) => {
  const url = new URL(input.provider.authorizationUrl.href);
  for (const [key, value] of Object.entries(input.provider.extraAuthorizationParams)) {
    url.searchParams.set(key, value);
  }
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", input.provider.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri.href);
  url.searchParams.set("state", Redacted.value(input.state));
  if (input.scopes.length > 0) {
    url.searchParams.set("scope", input.scopes.join(" "));
  }
  if (input.codeVerifier !== undefined) {
    url.searchParams.set("code_challenge", makePkceChallenge(input.codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");
  }
  if (input.nonce !== undefined) {
    url.searchParams.set("nonce", Redacted.value(input.nonce));
  }
  return url;
};

export class OAuth extends Context.Service<
  OAuth,
  {
    readonly startSignIn: (
      input: OAuthStartSignInInput,
    ) => Effect.Effect<
      OAuthAuthorizationStartResult,
      | OAuthStartError
      | BoundaryParseError
      | AuthStorageFailure
      | OAuthStateFailure
      | TokenGenerationFailure
    >;
    readonly startLink: (
      input: OAuthStartLinkInput,
    ) => Effect.Effect<
      OAuthAuthorizationStartResult,
      | OAuthStartError
      | BoundaryParseError
      | PublicAuthError
      | AuthStorageFailure
      | OAuthStateFailure
      | TokenGenerationFailure
    >;
    readonly completeCallback: (
      input: OAuthCallbackInput,
    ) => Effect.Effect<
      OAuthCallbackSuccess,
      | OAuthCallbackError
      | BoundaryParseError
      | OAuthStateFailure
      | AuthStorageFailure
      | OAuthAccountStorageFailure
      | OAuthProviderClientError
      | ProviderTokenProtectionFailure
      | TokenGenerationFailure
    >;
  }
>()("effect-auth/OAuth") {
  static readonly layer = Layer.effect(OAuth)(
    Effect.gen(function* () {
      const providers = yield* OAuthProviders;
      const state = yield* OAuthState;
      const token = yield* AuthToken;
      const storage = yield* AuthStorage;
      const authConfig = yield* AuthLiveConfig;
      const providerClient = yield* OAuthProviderClient;
      const tokenProtection = yield* ProviderTokenProtection;
      const oidcValidator = yield* OidcIdTokenValidator;

      const start = Effect.fn("OAuth.start")(function* (input: {
        readonly providerId: unknown;
        readonly redirectUri: URL;
        readonly scopes?: ReadonlyArray<string>;
        readonly allowSignUp: boolean;
        readonly flow: OAuthFlow;
        readonly linkUserId?: AuthUserId;
      }) {
        const provider = yield* parseStartProvider(providers, input.providerId);
        const redirectUri = yield* validateRedirectUri(input.redirectUri);
        const scopes = yield* parseRequestedScopes(provider, input.scopes);
        const codeVerifier = provider.pkce === "disabled" ? undefined : yield* makeRandomSecret();
        const nonce = provider.isOidc ? yield* makeRandomSecret() : undefined;
        const created = yield* state.create({
          providerId: provider.id,
          flow: input.flow,
          redirectUri,
          scopes,
          allowSignUp: input.allowSignUp,
          ...(input.linkUserId === undefined ? {} : { linkUserId: input.linkUserId }),
          secrets: {
            ...(codeVerifier === undefined ? {} : { codeVerifier }),
            ...(nonce === undefined ? {} : { nonce }),
          },
        });
        return {
          providerId: provider.id,
          authorizationUrl: buildAuthorizationUrl({
            provider,
            redirectUri,
            state: created.handle,
            scopes,
            ...(codeVerifier === undefined ? {} : { codeVerifier }),
            ...(nonce === undefined ? {} : { nonce }),
          }),
          state: created.handle,
          scopes,
          flow: input.flow,
        };
      });

      const consumeCallbackState = Effect.fn("OAuth.consumeCallbackState")(function* (
        providerId: OAuthProviderId,
        handle: OAuthStateHandle,
      ) {
        const consumeFlow = (flow: OAuthFlow) => state.consume({ providerId, flow, handle });
        return yield* consumeFlow("SignIn").pipe(
          Effect.catchTag("AuthStorageFailure", (error) =>
            error.reason === "NotFound" ? consumeFlow("Link") : Effect.fail(error),
          ),
          Effect.mapError(mapOAuthStateConsumeFailure),
        );
      });

      const resolveCallbackIdentity = Effect.fn("OAuth.resolveCallbackIdentity")(function* (
        provider: ResolvedOAuthProvider,
        consumedState: StoredOAuthState & { readonly secrets: OAuthStateSecrets },
        code: Redacted.Redacted<string>,
      ) {
        const tokenSet = yield* providerClient
          .exchangeCode({
            provider,
            code,
            redirectUri: consumedState.redirectUri,
            ...(consumedState.secrets.codeVerifier === undefined
              ? {}
              : { codeVerifier: consumedState.secrets.codeVerifier }),
          })
          .pipe(Effect.mapError(() => new OAuthCallbackError({ reason: "TokenExchangeFailed" })));
        const validatedOidcIdentity = provider.isOidc
          ? yield* Effect.gen(function* () {
              if (tokenSet.idToken === undefined || consumedState.secrets.nonce === undefined) {
                return yield* new OAuthCallbackError({ reason: "IdentityValidationFailed" });
              }
              return yield* oidcValidator
                .validate({
                  provider,
                  idToken: tokenSet.idToken,
                  expectedNonce: consumedState.secrets.nonce,
                })
                .pipe(
                  Effect.mapError(
                    () => new OAuthCallbackError({ reason: "IdentityValidationFailed" }),
                  ),
                );
            })
          : undefined;
        const identity = yield* providerClient
          .resolveIdentity({
            provider,
            tokenSet,
            ...(validatedOidcIdentity === undefined ? {} : { validatedOidcIdentity }),
          })
          .pipe(
            Effect.mapError((error) =>
              error.reason === "MissingProviderEmail"
                ? new OAuthCallbackError({ reason: "ProviderEmailRequired" })
                : new OAuthCallbackError({ reason: "TokenExchangeFailed" }),
            ),
          );
        const email = yield* normalizeEmail(identity.email).pipe(
          Effect.mapError(() => new OAuthCallbackError({ reason: "ProviderEmailRequired" })),
        );
        const providerTokens = yield* protectProviderTokenSet(tokenProtection, {
          providerId: identity.providerId,
          providerAccountId: identity.providerAccountId,
          tokenSet: identity.tokenSet,
        }).pipe(
          Effect.mapError(
            () => new OAuthCallbackError({ reason: "ProviderTokenProtectionFailed" }),
          ),
        );
        return { identity, email, providerTokens };
      });

      return {
        startSignIn: Effect.fn("OAuth.startSignIn")(function* (input) {
          return yield* start({
            providerId: input.providerId,
            redirectUri: input.redirectUri,
            ...(input.scopes === undefined ? {} : { scopes: input.scopes }),
            allowSignUp: input.allowSignUp ?? true,
            flow: "SignIn",
          });
        }),
        startLink: Effect.fn("OAuth.startLink")(function* (input) {
          const sessionToken = yield* decodeSessionToken(
            Redacted.isRedacted(input.sessionToken)
              ? Redacted.value(input.sessionToken)
              : input.sessionToken,
          ).pipe(
            Effect.mapError(
              () =>
                new BoundaryParseError({
                  field: "sessionToken",
                  reason: "Invalid session token",
                }),
            ),
          );
          const hash = yield* token.hashToken(sessionToken);
          const current = yield* storage
            .findSessionByTokenHash(hash)
            .pipe(Effect.mapError(() => new OAuthStartError({ reason: "UnauthorizedLinkFlow" })));
          return yield* start({
            providerId: input.providerId,
            redirectUri: input.redirectUri,
            ...(input.scopes === undefined ? {} : { scopes: input.scopes }),
            allowSignUp: false,
            flow: "Link",
            linkUserId: current.user.id,
          });
        }),
        completeCallback: Effect.fn("OAuth.completeCallback")(function* (input) {
          if (input.error !== undefined) {
            return yield* new OAuthCallbackError({ reason: "ProviderReturnedError" });
          }
          const provider = yield* parseCallbackProvider(providers, input.providerId);
          const handle = yield* parseCallbackStateHandle(input.state);
          const code = yield* parseCallbackCode(input.code);
          const consumedState = yield* consumeCallbackState(provider.id, handle);
          const { identity, email, providerTokens } = yield* resolveCallbackIdentity(
            provider,
            consumedState,
            code,
          );
          const now = yield* Clock.currentTimeMillis;
          if (consumedState.flow === "Link") {
            if (consumedState.linkUserId === undefined) {
              return yield* new OAuthCallbackError({ reason: "InvalidState" });
            }
            const result = yield* storage
              .completeOAuthLink({
                userId: consumedState.linkUserId,
                providerId: provider.id,
                providerAccountId: identity.providerAccountId,
                providerEmail: email,
                scopes: consumedState.scopes,
                providerTokens,
                allowDifferentEmail: authConfig.oauth.allowDifferentEmailLinking,
                now,
              })
              .pipe(Effect.mapError(mapOAuthAtomicStorageFailure));
            const success: OAuthLinkCallbackSuccess = {
              flow: "Link",
              user: result.user,
              account: result.account,
              isNewUser: false,
            };
            return success;
          }
          const pair = yield* token.makeSessionToken();
          const signIn = yield* storage
            .completeOAuthSignInWithSession({
              providerId: provider.id,
              providerAccountId: identity.providerAccountId,
              email,
              emailVerified: identity.emailVerified || provider.trustedEmail,
              name: identity.name,
              image: identity.image,
              scopes: consumedState.scopes,
              providerTokens,
              allowImplicitSignUp: consumedState.allowSignUp,
              allowAutomaticSameEmailLinking: identity.emailVerified || provider.trustedEmail,
              now,
              sessionTokenHash: pair.hash,
              sessionExpiresAt: now + authConfig.session.ttlMillis,
              ...(typeof input.ip === "string" ? { sessionIpAddress: input.ip } : {}),
              ...(input.userAgent === undefined ? {} : { sessionUserAgent: input.userAgent }),
            })
            .pipe(Effect.mapError(mapOAuthSignInWithSessionStorageFailure));
          const success: OAuthSignInCallbackSuccess = {
            flow: "SignIn",
            user: signIn.user,
            account: signIn.account,
            session: signIn.session,
            sessionToken: pair.token,
            isNewUser: signIn.isNewUser,
          };
          return success;
        }),
      };
    }),
  ).pipe(Layer.provide(OAuthDependenciesLayer));
}
