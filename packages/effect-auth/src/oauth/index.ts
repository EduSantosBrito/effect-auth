import { Clock, Config, Context, Effect, Layer, Option, Redacted, Schema } from "effect";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import * as HttpClient from "effect/unstable/http/HttpClient";
import * as HttpClientResponse from "effect/unstable/http/HttpClientResponse";
import { AuthLiveConfig } from "../auth.js";
import { BoundaryParseError, type PublicAuthError } from "../domain/index.js";
import { AuthStorage, AuthStorageFailure, type AuthUserId } from "../storage/index.js";
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

export interface OAuthProfileMappingInput {
  readonly provider: ResolvedOAuthProvider;
  readonly tokenSet: OAuthTokenSet;
  readonly validatedOidcIdentity?: unknown;
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
const OAuthStartDependenciesLayer = Layer.mergeAll(AuthTokenLive, OAuthStateDefaultLayer);

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
  }
>()("effect-auth/OAuth") {
  static readonly layer = Layer.effect(OAuth)(
    Effect.gen(function* () {
      const providers = yield* OAuthProviders;
      const state = yield* OAuthState;
      const token = yield* AuthToken;
      const storage = yield* AuthStorage;

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
      };
    }),
  ).pipe(Layer.provide(OAuthStartDependenciesLayer));
}
