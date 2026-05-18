import { assert, it } from "@effect/vitest";
import { Duration, Effect, Layer, Predicate, Redacted, Schema } from "effect";
import * as HttpClient from "effect/unstable/http/HttpClient";
import * as HttpClientError from "effect/unstable/http/HttpClientError";
import * as HttpClientResponse from "effect/unstable/http/HttpClientResponse";
import { AuthLiveConfig } from "../src/auth";
import { NormalizedEmail } from "../src/domain/index";
import {
  AuthFeatureKeyMaterialFailure,
  AuthFeatureKeyMaterialService,
  OAuth,
  OAuthCallbackError,
  OAuthProviderClient,
  OAuthProviderClientError,
  OAuthProviderConfigError,
  OAuthProviderId,
  OAuthProviderProfileMappingFailure,
  OAuthProviders,
  OAuthStartError,
  OAuthState,
  ProtectedProviderToken,
  ProviderTokenProtection,
  ProviderTokenProtectionFailure,
  type OAuthProviderInput,
} from "../src/oauth/index";
import { PasswordHash } from "../src/password/index";
import {
  DevMemoryAuthStorage,
  makeDevMemoryStorage,
  makeDevMemoryStorageState,
  type DevMemoryStorageState,
} from "../src/storage/dev-memory";
import { AuthStorage, AuthStorageFailure, OAuthAccountStorageFailure } from "../src/storage/index";
import { AuthToken, AuthTokenLive } from "../src/token/index";

const encryptionKey = Redacted.make("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
const decodeEmail = Schema.decodeUnknownEffect(NormalizedEmail);
const decodeOAuthProviderId = Schema.decodeUnknownEffect(OAuthProviderId);
const decodePasswordHash = Schema.decodeUnknownEffect(PasswordHash);
const decodeProtectedProviderToken = Schema.decodeUnknownEffect(ProtectedProviderToken);

class MissingOAuthTestFixture extends Schema.TaggedErrorClass<MissingOAuthTestFixture>()(
  "MissingOAuthTestFixture",
  {
    message: Schema.String,
  },
) {}

const UnexpectedHttpClientLive = Layer.succeed(HttpClient.HttpClient)(
  HttpClient.make((request) =>
    Effect.fail(
      new HttpClientError.HttpClientError({
        reason: new HttpClientError.TransportError({
          request,
          description: "unexpected OAuth discovery request",
        }),
      }),
    ),
  ),
);

const githubProvider: OAuthProviderInput = {
  id: "github",
  clientId: "github-client",
  clientSecret: Redacted.make("github-secret"),
  defaultScopes: ["read:user", "user:email"],
  endpoints: {
    authorizationUrl: new URL("https://github.example/authorize"),
    tokenUrl: new URL("https://github.example/token"),
  },
  mapProfile: () =>
    Effect.succeed({
      providerAccountId: "github-user",
      email: "github@example.com",
      emailVerified: true,
      name: "GitHub User",
      image: null,
    }),
};

const oidcProvider: OAuthProviderInput = {
  id: "oidc",
  clientId: "oidc-client",
  clientSecret: Redacted.make("oidc-secret"),
  defaultScopes: ["openid", "email"],
  endpoints: {
    authorizationUrl: new URL("https://oidc.example/authorize"),
    tokenUrl: new URL("https://oidc.example/token"),
    issuer: "https://oidc.example",
    jwksUrl: new URL("https://oidc.example/jwks"),
  },
};

const callbackProvider: OAuthProviderInput = {
  ...githubProvider,
  endpoints: {
    authorizationUrl: new URL("https://github.example/authorize"),
    tokenUrl: new URL("https://github.example/token"),
    userInfoUrl: new URL("https://github.example/user"),
  },
  mapProfile: ({ userInfo }) =>
    Effect.succeed({
      providerAccountId: String(userInfo?.id ?? ""),
      email: String(userInfo?.email ?? ""),
      emailVerified: userInfo?.email_verified === true,
      name: String(userInfo?.name ?? "GitHub User"),
      image: typeof userInfo?.avatar_url === "string" ? userInfo.avatar_url : null,
    }),
};

const jsonResponse = (
  request: Parameters<typeof HttpClientResponse.fromWeb>[0],
  body: unknown,
  status = 200,
) =>
  HttpClientResponse.fromWeb(
    request,
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    }),
  );

const defaultTokenResponse = {
  access_token: "provider-access-token",
  refresh_token: "provider-refresh-token",
  token_type: "Bearer",
  scope: "read:user user:email repo",
  expires_in: 3600,
};

const defaultUserInfo = {
  id: "github-user-1",
  email: "oauth@example.com",
  email_verified: true,
  name: "OAuth User",
  avatar_url: "https://github.example/avatar.png",
};

const makeFakeOAuthHttpClientLive = (
  options: {
    readonly tokenResponses?: ReadonlyArray<Readonly<Record<string, unknown>>>;
    readonly userInfo?: Readonly<Record<string, unknown>>;
  } = {},
) => {
  let tokenRequestCount = 0;
  const tokenResponses = options.tokenResponses ?? [defaultTokenResponse];
  const userInfo = options.userInfo ?? defaultUserInfo;
  return Layer.succeed(HttpClient.HttpClient)(
    HttpClient.make((request, url) => {
      if (url.href === "https://github.example/token") {
        const response =
          tokenResponses[tokenRequestCount] ?? tokenResponses[tokenResponses.length - 1];
        tokenRequestCount += 1;
        return Effect.succeed(jsonResponse(request, response));
      }
      if (url.href === "https://github.example/user") {
        return Effect.succeed(jsonResponse(request, userInfo));
      }
      return Effect.fail(
        new HttpClientError.HttpClientError({
          reason: new HttpClientError.TransportError({
            request,
            description: `unexpected OAuth fake request: ${url.href}`,
          }),
        }),
      );
    }),
  );
};

const FakeOAuthHttpClientLive = makeFakeOAuthHttpClientLive();

const makeOAuthLayer = (
  storageState: DevMemoryStorageState,
  options: {
    readonly providers?: ReadonlyArray<OAuthProviderInput>;
    readonly oauthStateTtl?: Duration.Input;
    readonly httpClientLive?: Layer.Layer<HttpClient.HttpClient>;
    readonly storageLive?: Layer.Layer<AuthStorage>;
    readonly providerTokenProtectionLive?: Layer.Layer<ProviderTokenProtection>;
  } = {},
) => {
  const HttpLive = options.httpClientLive ?? UnexpectedHttpClientLive;
  const ProvidersLive = OAuthProviders.layer({
    providers: options.providers ?? [githubProvider, oidcProvider],
  }).pipe(Layer.provide(HttpLive));
  const DependenciesLive = Layer.mergeAll(
    AuthLiveConfig.layer({
      encryptionKey,
      ...(options.oauthStateTtl === undefined
        ? {}
        : { oauthState: { ttl: options.oauthStateTtl } }),
    }),
    options.storageLive ?? DevMemoryAuthStorage(storageState),
    ProvidersLive,
    HttpLive,
  );
  const OAuthStateLive = OAuthState.layer.pipe(Layer.provide(AuthFeatureKeyMaterialService.layer));
  const ProviderTokenProtectionLive =
    options.providerTokenProtectionLive ??
    ProviderTokenProtection.layer.pipe(Layer.provide(AuthFeatureKeyMaterialService.layer));
  const OAuthLive = OAuth.layer.pipe(
    Layer.provideMerge(ProviderTokenProtectionLive),
    Layer.provideMerge(OAuthProviderClient.layer),
  );
  return Layer.mergeAll(OAuthLive, OAuthStateLive, AuthTokenLive).pipe(
    Layer.provideMerge(DependenciesLive),
  );
};

const latestStoredState = Effect.fn("oauth.test.latestStoredState")(function* (
  storageState: DevMemoryStorageState,
) {
  const states = Array.from(storageState.oauthStatesByHash.values());
  const state = states[states.length - 1];
  if (state === undefined) {
    return yield* new MissingOAuthTestFixture({
      message: "expected OAuth state to be stored",
    });
  }
  return state;
});

const latestProviderAccount = Effect.fn("oauth.test.latestProviderAccount")(function* (
  storageState: DevMemoryStorageState,
) {
  const accounts = Array.from(storageState.providerAccountsByKey.values());
  const account = accounts[accounts.length - 1];
  if (account === undefined) {
    return yield* new MissingOAuthTestFixture({
      message: "expected OAuth provider account to be stored",
    });
  }
  return account;
});

const s256 = (value: string) => new Bun.CryptoHasher("sha256").update(value).digest("base64url");

const createCredentialSession = Effect.fn("oauth.test.createCredentialSession")(function* (input: {
  readonly email: string;
  readonly name: string;
}) {
  const storage = yield* AuthStorage;
  const token = yield* AuthToken;
  const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
  const email = yield* decodeEmail(input.email);
  const passwordHash = yield* decodePasswordHash("hash:oauth-link");
  const user = yield* storage.createUserWithCredentialAccount({
    email,
    name: input.name,
    image: null,
    passwordHash,
    now,
  });
  const sessionToken = yield* token.makeSessionToken();
  const session = yield* storage.createSession({
    userId: user.id,
    tokenHash: sessionToken.hash,
    expiresAt: now + 60_000,
    now,
  });
  return { user, session, sessionToken: sessionToken.token };
});

it.effect("starts OAuth sign-in with storage-backed encrypted PKCE state", () => {
  const storageState = makeDevMemoryStorageState();
  return Effect.gen(function* () {
    const oauth = yield* OAuth;
    const stateService = yield* OAuthState;
    const redirectUri = new URL("https://app.example.com/auth/callback/github");

    const result = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri,
      scopes: ["repo", "read:user"],
      allowSignUp: false,
    });

    const authorizationUrl = result.authorizationUrl;
    const stored = yield* latestStoredState(storageState);

    assert.strictEqual(result.providerId, "github");
    assert.strictEqual(result.flow, "SignIn");
    assert.deepStrictEqual(result.scopes, ["read:user", "user:email", "repo"]);
    assert.strictEqual(authorizationUrl.searchParams.get("response_type"), "code");
    assert.strictEqual(authorizationUrl.searchParams.get("client_id"), "github-client");
    assert.strictEqual(authorizationUrl.searchParams.get("redirect_uri"), redirectUri.href);
    assert.strictEqual(authorizationUrl.searchParams.get("state"), Redacted.value(result.state));
    assert.strictEqual(authorizationUrl.searchParams.get("scope"), "read:user user:email repo");
    assert.strictEqual(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
    assert.equal(authorizationUrl.searchParams.get("code_challenge")?.length ?? 0, 43);
    assert.strictEqual(authorizationUrl.searchParams.has("nonce"), false);

    assert.notStrictEqual(Redacted.value(stored.stateHash), Redacted.value(result.state));
    assert.strictEqual(stored.redirectUri.href, redirectUri.href);
    assert.strictEqual(stored.allowSignUp, false);
    assert.strictEqual(stored.encryptedCodeVerifier?.includes("github"), false);
    assert.strictEqual(stored.encryptedNonce, undefined);
    assert.strictEqual(
      stored.expiresAt - stored.createdAt,
      Duration.toMillis(Duration.minutes(10)),
    );

    const consumed = yield* stateService.consume({
      providerId: result.providerId,
      flow: "SignIn",
      handle: result.state,
    });
    const verifier = consumed.secrets.codeVerifier;
    if (verifier === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected PKCE verifier in consumed state",
      });
    }
    assert.strictEqual(
      authorizationUrl.searchParams.get("code_challenge"),
      s256(Redacted.value(verifier)),
    );
    assert.strictEqual(consumed.secrets.nonce, undefined);
  }).pipe(Effect.provide(makeOAuthLayer(storageState)));
});

it.effect("adds and encrypts OIDC nonce state for OIDC providers", () => {
  const storageState = makeDevMemoryStorageState();
  return Effect.gen(function* () {
    const oauth = yield* OAuth;
    const stateService = yield* OAuthState;

    const result = yield* oauth.startSignIn({
      providerId: "oidc",
      redirectUri: new URL("https://app.example.com/auth/callback/oidc"),
    });
    const stored = yield* latestStoredState(storageState);
    const nonce = result.authorizationUrl.searchParams.get("nonce");

    assert.strictEqual(result.flow, "SignIn");
    assert.strictEqual(result.authorizationUrl.searchParams.get("scope"), "openid email");
    assert.equal(nonce?.length ?? 0, 43);
    assert.notStrictEqual(stored.encryptedNonce, undefined);
    assert.notStrictEqual(stored.encryptedNonce, nonce);

    const consumed = yield* stateService.consume({
      providerId: result.providerId,
      flow: "SignIn",
      handle: result.state,
    });
    const consumedNonce = consumed.secrets.nonce;
    if (consumedNonce === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected OIDC nonce in consumed state",
      });
    }
    assert.strictEqual(Redacted.value(consumedNonce), nonce);
  }).pipe(Effect.provide(makeOAuthLayer(storageState)));
});

it.effect("validates provider IDs, scopes, and reserved authorization params", () => {
  const storageState = makeDevMemoryStorageState();
  return Effect.gen(function* () {
    const oauth = yield* OAuth;

    const unknownProvider = yield* Effect.flip(
      oauth.startSignIn({
        providerId: "missing",
        redirectUri: new URL("https://app.example.com/auth/callback/missing"),
      }),
    );
    assert.deepStrictEqual(unknownProvider, new OAuthStartError({ reason: "UnknownProvider" }));

    const invalidScope = yield* Effect.flip(
      oauth.startSignIn({
        providerId: "github",
        redirectUri: new URL("https://app.example.com/auth/callback/github"),
        scopes: ["bad scope"],
      }),
    );
    assert.deepStrictEqual(invalidScope, new OAuthStartError({ reason: "InvalidScope" }));

    const reservedProviders = OAuthProviders.layer({
      providers: [{ ...githubProvider, extraAuthorizationParams: { state: "override" } }],
    }).pipe(Layer.provide(UnexpectedHttpClientLive));
    const reserved = yield* Effect.flip(
      OAuthProviders.asEffect().pipe(Effect.asVoid, Effect.provide(reservedProviders)),
    );
    assert.strictEqual(Predicate.isTagged(reserved, "OAuthProviderConfigError"), true);
    if (Predicate.isTagged(reserved, "OAuthProviderConfigError")) {
      assert.deepStrictEqual(
        reserved,
        new OAuthProviderConfigError({
          reason: "ReservedAuthorizationParam",
          providerId: "github",
        }),
      );
    }
  }).pipe(Effect.provide(makeOAuthLayer(storageState)));
});

it.effect("requires a valid current session for OAuth link state", () => {
  const storageState = makeDevMemoryStorageState();
  return Effect.gen(function* () {
    const oauth = yield* OAuth;
    const storage = yield* AuthStorage;
    const token = yield* AuthToken;
    const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
    const passwordHash = yield* decodePasswordHash("hash:link");
    const email = yield* decodeEmail("link@example.com");
    const user = yield* storage.createUserWithCredentialAccount({
      email,
      name: "Link User",
      image: null,
      passwordHash,
      now,
    });
    const sessionToken = yield* token.makeSessionToken();
    yield* storage.createSession({
      userId: user.id,
      tokenHash: sessionToken.hash,
      expiresAt: now + 60_000,
      now,
    });

    const result = yield* oauth.startLink({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
      sessionToken: sessionToken.token,
      scopes: ["repo"],
    });
    const stored = yield* latestStoredState(storageState);

    assert.strictEqual(result.flow, "Link");
    assert.strictEqual(stored.flow, "Link");
    assert.strictEqual(stored.allowSignUp, false);
    assert.strictEqual(stored.linkUserId, user.id);

    const missingSession = yield* token.makeSessionToken();
    const unauthorized = yield* Effect.flip(
      oauth.startLink({
        providerId: "github",
        redirectUri: new URL("https://app.example.com/auth/callback/github"),
        sessionToken: missingSession.token,
      }),
    );
    assert.deepStrictEqual(unauthorized, new OAuthStartError({ reason: "UnauthorizedLinkFlow" }));
  }).pipe(Effect.provide(makeOAuthLayer(storageState)));
});

it.effect("consumes dev-memory OAuth state once and reports mismatch or expiry", () => {
  const storageState = makeDevMemoryStorageState();
  return Effect.gen(function* () {
    const oauth = yield* OAuth;
    const stateService = yield* OAuthState;
    const github = yield* decodeOAuthProviderId("github");
    const oidc = yield* decodeOAuthProviderId("oidc");

    const first = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
    });
    const mismatch = yield* Effect.flip(
      stateService.consume({ providerId: oidc, flow: "SignIn", handle: first.state }),
    );
    assert.deepStrictEqual(mismatch, new AuthStorageFailure({ reason: "NotFound" }));

    yield* stateService.consume({ providerId: github, flow: "SignIn", handle: first.state });
    const consumedAgain = yield* Effect.flip(
      stateService.consume({ providerId: github, flow: "SignIn", handle: first.state }),
    );
    assert.deepStrictEqual(consumedAgain, new AuthStorageFailure({ reason: "TokenConsumed" }));

    const expired = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
    });
    for (const [key, state] of storageState.oauthStatesByHash) {
      if (state.providerId === github && state.consumedAt === undefined) {
        storageState.oauthStatesByHash.set(key, { ...state, expiresAt: 0 });
      }
    }
    const expiredFailure = yield* Effect.flip(
      stateService.consume({ providerId: github, flow: "SignIn", handle: expired.state }),
    );
    assert.deepStrictEqual(expiredFailure, new AuthStorageFailure({ reason: "TokenExpired" }));
  }).pipe(Effect.provide(makeOAuthLayer(storageState)));
});

it.effect("protects provider tokens with context-bound encrypted envelopes", () =>
  Effect.gen(function* () {
    const protection = yield* ProviderTokenProtection;
    const providerId = yield* decodeOAuthProviderId("github");
    const protectedToken = yield* protection.protect({
      providerId,
      providerAccountId: "github-user",
      kind: "AccessToken",
      plaintext: Redacted.make("provider-access-token"),
    });

    assert.strictEqual(protectedToken.startsWith("ea_pt_v1.default."), true);
    assert.strictEqual(protectedToken.includes("provider-access-token"), false);

    const plaintext = yield* protection.unprotect({
      providerId,
      providerAccountId: "github-user",
      kind: "AccessToken",
      protectedToken,
    });
    assert.strictEqual(Redacted.value(plaintext), "provider-access-token");

    const mismatch = yield* Effect.flip(
      protection.unprotect({
        providerId,
        providerAccountId: "other-user",
        kind: "AccessToken",
        protectedToken,
      }),
    );
    assert.deepStrictEqual(
      mismatch,
      new ProviderTokenProtectionFailure({ reason: "ContextMismatch" }),
    );

    const malformed = yield* Effect.flip(
      protection.unprotect({
        providerId,
        providerAccountId: "github-user",
        kind: "AccessToken",
        protectedToken: yield* decodeProtectedProviderToken("not-an-envelope"),
      }),
    );
    assert.deepStrictEqual(
      malformed,
      new ProviderTokenProtectionFailure({ reason: "InvalidEnvelope" }),
    );

    const unknownKeyToken = yield* decodeProtectedProviderToken(
      protectedToken.replace(".default.", ".rotated."),
    );
    const unknownKey = yield* Effect.flip(
      protection.unprotect({
        providerId,
        providerAccountId: "github-user",
        kind: "AccessToken",
        protectedToken: unknownKeyToken,
      }),
    );
    assert.deepStrictEqual(
      unknownKey,
      new ProviderTokenProtectionFailure({ reason: "UnknownKeyId" }),
    );
  }).pipe(
    Effect.provide(
      ProviderTokenProtection.layer.pipe(
        Layer.provide(AuthFeatureKeyMaterialService.layer),
        Layer.provide(AuthLiveConfig.layer({ encryptionKey })),
      ),
    ),
  ),
);

it.effect("OAuthProviderClient exchanges codes and maps fake provider profile data", () =>
  Effect.gen(function* () {
    const providers = yield* OAuthProviders;
    const providerId = yield* decodeOAuthProviderId("github");
    const provider = yield* providers.get(providerId);
    const client = yield* OAuthProviderClient;

    const tokenSet = yield* client.exchangeCode({
      provider,
      code: Redacted.make("provider-code"),
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
      codeVerifier: Redacted.make("pkce-verifier"),
    });
    assert.strictEqual(
      Redacted.value(tokenSet.accessToken ?? Redacted.make("")),
      "provider-access-token",
    );
    assert.strictEqual(
      Redacted.value(tokenSet.refreshToken ?? Redacted.make("")),
      "provider-refresh-token",
    );
    assert.strictEqual(tokenSet.tokenType, "Bearer");
    assert.strictEqual(tokenSet.scope, "read:user user:email repo");

    const identity = yield* client.resolveIdentity({ provider, tokenSet });
    assert.strictEqual(identity.providerAccountId, "github-user-1");
    assert.strictEqual(identity.email, "oauth@example.com");
    assert.strictEqual(identity.emailVerified, true);
    assert.strictEqual(identity.name, "OAuth User");

    const mappingFailure = yield* Effect.flip(
      client.resolveIdentity({
        provider: {
          ...provider,
          mapProfile: () => Effect.fail(new OAuthProviderProfileMappingFailure({ reason: "boom" })),
        },
        tokenSet,
      }),
    );
    assert.deepStrictEqual(
      mappingFailure,
      new OAuthProviderClientError({ reason: "ProfileMappingFailed" }),
    );
  }).pipe(
    Effect.provide(
      Layer.mergeAll(
        OAuthProviderClient.layer,
        OAuthProviders.layer({ providers: [callbackProvider] }),
      ).pipe(Layer.provide(FakeOAuthHttpClientLive)),
    ),
  ),
);

it.effect("completes generic OAuth callback for a new user with protected provider tokens", () => {
  const storageState = makeDevMemoryStorageState();
  return Effect.gen(function* () {
    const oauth = yield* OAuth;
    const storage = yield* AuthStorage;
    const protection = yield* ProviderTokenProtection;

    const started = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
      scopes: ["repo"],
    });
    const result = yield* oauth.completeCallback({
      providerId: "github",
      state: started.state,
      code: "provider-code",
      callbackMethod: "GET",
      userAgent: "oauth-test",
    });

    if (result.flow !== "SignIn") {
      return yield* new MissingOAuthTestFixture({
        message: "expected sign-in callback result",
      });
    }
    assert.strictEqual(result.isNewUser, true);
    assert.strictEqual(result.user.email, "oauth@example.com");
    assert.strictEqual(result.user.emailVerified, true);
    assert.strictEqual(result.account.providerId, "github");
    assert.strictEqual(result.account.accountId, "github-user-1");
    assert.strictEqual(result.session.userId, result.user.id);
    assert.strictEqual(result.session.userAgent, "oauth-test");
    assert.strictEqual(started.authorizationUrl.href.includes("provider-access-token"), false);
    assert.strictEqual(started.authorizationUrl.href.includes("provider-refresh-token"), false);
    assert.notStrictEqual(result.account.providerTokens.accessToken, "provider-access-token");
    assert.notStrictEqual(result.account.providerTokens.refreshToken, "provider-refresh-token");

    const storedAccount = yield* latestProviderAccount(storageState);
    const protectedAccessToken = storedAccount.providerTokens.accessToken;
    if (protectedAccessToken === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected protected access token",
      });
    }
    assert.strictEqual(protectedAccessToken.startsWith("ea_pt_v1.default."), true);
    assert.strictEqual(protectedAccessToken.includes("provider-access-token"), false);

    const clearAccessToken = yield* protection.unprotect({
      providerId: storedAccount.providerId,
      providerAccountId: storedAccount.accountId,
      kind: "AccessToken",
      protectedToken: protectedAccessToken,
    });
    assert.strictEqual(Redacted.value(clearAccessToken), "provider-access-token");

    const listed = yield* storage.listUserAccounts({ userId: result.user.id });
    const publicAccount = listed[0];
    if (publicAccount === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected public OAuth account",
      });
    }
    assert.strictEqual(publicAccount.providerId, "github");
    assert.strictEqual(Object.hasOwn(publicAccount, "providerTokens"), false);
    assert.strictEqual(Object.hasOwn(publicAccount, "passwordHash"), false);

    const consumedAgain = yield* Effect.flip(
      oauth.completeCallback({
        providerId: "github",
        state: started.state,
        code: "provider-code",
        callbackMethod: "GET",
      }),
    );
    assert.deepStrictEqual(consumedAgain, new OAuthCallbackError({ reason: "ConsumedState" }));
  }).pipe(
    Effect.provide(
      makeOAuthLayer(storageState, {
        providers: [callbackProvider],
        httpClientLive: FakeOAuthHttpClientLive,
      }),
    ),
  );
});

it.effect("signs in returning OAuth provider accounts and preserves omitted token fields", () => {
  const storageState = makeDevMemoryStorageState();
  const HttpLive = makeFakeOAuthHttpClientLive({
    tokenResponses: [
      {
        access_token: "first-access-token",
        refresh_token: "first-refresh-token",
        id_token: "first-id-token",
        token_type: "Bearer",
        scope: "read:user",
        expires_in: 3600,
      },
      {
        access_token: "second-access-token",
        token_type: "Bearer",
        scope: "read:user repo",
        expires_in: 7200,
      },
    ],
  });

  return Effect.gen(function* () {
    const oauth = yield* OAuth;
    const storage = yield* AuthStorage;
    const protection = yield* ProviderTokenProtection;

    const firstStart = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
    });
    const first = yield* oauth.completeCallback({
      providerId: "github",
      state: firstStart.state,
      code: "first-provider-code",
      callbackMethod: "GET",
    });
    if (first.flow !== "SignIn") {
      return yield* new MissingOAuthTestFixture({
        message: "expected first sign-in callback result",
      });
    }
    assert.strictEqual(first.isNewUser, true);
    const firstAccount = yield* latestProviderAccount(storageState);
    const firstRefreshToken = firstAccount.providerTokens.refreshToken;
    const firstIdToken = firstAccount.providerTokens.idToken;
    if (firstRefreshToken === undefined || firstIdToken === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected initial refresh and id tokens",
      });
    }

    const secondStart = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
      scopes: ["repo"],
    });
    const second = yield* oauth.completeCallback({
      providerId: "github",
      state: secondStart.state,
      code: "second-provider-code",
      callbackMethod: "GET",
    });
    if (second.flow !== "SignIn") {
      return yield* new MissingOAuthTestFixture({
        message: "expected returning sign-in callback result",
      });
    }

    assert.strictEqual(second.isNewUser, false);
    assert.strictEqual(second.user.id, first.user.id);
    assert.notStrictEqual(second.session.id, first.session.id);
    assert.notStrictEqual(Redacted.value(second.sessionToken), Redacted.value(first.sessionToken));
    assert.strictEqual(storageState.users.size, 1);
    assert.strictEqual(storageState.providerAccountsByKey.size, 1);
    assert.strictEqual(storageState.sessionsByHash.size, 2);

    const updatedAccount = yield* latestProviderAccount(storageState);
    const updatedAccessToken = updatedAccount.providerTokens.accessToken;
    const updatedRefreshToken = updatedAccount.providerTokens.refreshToken;
    const updatedIdToken = updatedAccount.providerTokens.idToken;
    if (
      updatedAccessToken === undefined ||
      updatedRefreshToken === undefined ||
      updatedIdToken === undefined
    ) {
      return yield* new MissingOAuthTestFixture({
        message: "expected updated token fields",
      });
    }
    assert.notStrictEqual(updatedAccessToken, firstAccount.providerTokens.accessToken);
    assert.strictEqual(updatedRefreshToken, firstRefreshToken);
    assert.strictEqual(updatedIdToken, firstIdToken);
    assert.strictEqual(updatedAccount.providerTokens.scope, "read:user repo");
    assert.ok(
      (updatedAccount.providerTokens.accessTokenExpiresAt ?? 0) >
        (firstAccount.providerTokens.accessTokenExpiresAt ?? 0),
    );

    const clearAccessToken = yield* protection.unprotect({
      providerId: updatedAccount.providerId,
      providerAccountId: updatedAccount.accountId,
      kind: "AccessToken",
      protectedToken: updatedAccessToken,
    });
    const clearRefreshToken = yield* protection.unprotect({
      providerId: updatedAccount.providerId,
      providerAccountId: updatedAccount.accountId,
      kind: "RefreshToken",
      protectedToken: updatedRefreshToken,
    });
    const clearIdToken = yield* protection.unprotect({
      providerId: updatedAccount.providerId,
      providerAccountId: updatedAccount.accountId,
      kind: "IdToken",
      protectedToken: updatedIdToken,
    });
    assert.strictEqual(Redacted.value(clearAccessToken), "second-access-token");
    assert.strictEqual(Redacted.value(clearRefreshToken), "first-refresh-token");
    assert.strictEqual(Redacted.value(clearIdToken), "first-id-token");

    const publicAccounts = yield* storage.listUserAccounts({ userId: first.user.id });
    const publicAccount = publicAccounts[0];
    if (publicAccount === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected public account projection",
      });
    }
    assert.strictEqual(publicAccount.providerId, "github");
    assert.strictEqual(Object.hasOwn(publicAccount, "providerTokens"), false);
  }).pipe(
    Effect.provide(
      makeOAuthLayer(storageState, {
        providers: [callbackProvider],
        httpClientLive: HttpLive,
      }),
    ),
  );
});

it.effect("completes manual OAuth link callbacks without issuing new sessions", () => {
  const storageState = makeDevMemoryStorageState();
  const HttpLive = makeFakeOAuthHttpClientLive({
    tokenResponses: [
      {
        access_token: "first-link-access-token",
        refresh_token: "first-link-refresh-token",
        token_type: "Bearer",
        scope: "read:user",
        expires_in: 3600,
      },
      {
        access_token: "second-link-access-token",
        token_type: "Bearer",
        scope: "read:user repo",
        expires_in: 7200,
      },
    ],
  });

  return Effect.gen(function* () {
    const oauth = yield* OAuth;
    const storage = yield* AuthStorage;
    const protection = yield* ProviderTokenProtection;
    const credential = yield* createCredentialSession({
      email: "oauth@example.com",
      name: "Credential User",
    });

    const firstStart = yield* oauth.startLink({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
      sessionToken: credential.sessionToken,
    });
    const first = yield* oauth.completeCallback({
      providerId: "github",
      state: firstStart.state,
      code: "first-link-code",
      callbackMethod: "GET",
    });
    if (first.flow !== "Link") {
      return yield* new MissingOAuthTestFixture({
        message: "expected first link callback result",
      });
    }
    assert.strictEqual(first.user.id, credential.user.id);
    assert.strictEqual(first.isNewUser, false);
    assert.strictEqual(Object.hasOwn(first, "session"), false);
    assert.strictEqual(Object.hasOwn(first, "sessionToken"), false);
    assert.strictEqual(storageState.sessionsByHash.size, 1);
    assert.strictEqual(storageState.providerAccountsByKey.size, 1);

    const firstAccount = yield* latestProviderAccount(storageState);
    const firstRefreshToken = firstAccount.providerTokens.refreshToken;
    if (firstRefreshToken === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected linked refresh token",
      });
    }

    const secondStart = yield* oauth.startLink({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
      sessionToken: credential.sessionToken,
      scopes: ["repo"],
    });
    const second = yield* oauth.completeCallback({
      providerId: "github",
      state: secondStart.state,
      code: "second-link-code",
      callbackMethod: "GET",
    });
    if (second.flow !== "Link") {
      return yield* new MissingOAuthTestFixture({
        message: "expected idempotent link callback result",
      });
    }
    assert.strictEqual(second.user.id, credential.user.id);
    assert.strictEqual(Object.hasOwn(second, "session"), false);
    assert.strictEqual(Object.hasOwn(second, "sessionToken"), false);
    assert.strictEqual(storageState.sessionsByHash.size, 1);
    assert.strictEqual(storageState.providerAccountsByKey.size, 1);

    const updatedAccount = yield* latestProviderAccount(storageState);
    const updatedAccessToken = updatedAccount.providerTokens.accessToken;
    const updatedRefreshToken = updatedAccount.providerTokens.refreshToken;
    if (updatedAccessToken === undefined || updatedRefreshToken === undefined) {
      return yield* new MissingOAuthTestFixture({
        message: "expected idempotent link token fields",
      });
    }
    assert.notStrictEqual(updatedAccessToken, firstAccount.providerTokens.accessToken);
    assert.strictEqual(updatedRefreshToken, firstRefreshToken);
    assert.strictEqual(updatedAccount.providerTokens.scope, "read:user repo");

    const clearAccessToken = yield* protection.unprotect({
      providerId: updatedAccount.providerId,
      providerAccountId: updatedAccount.accountId,
      kind: "AccessToken",
      protectedToken: updatedAccessToken,
    });
    const clearRefreshToken = yield* protection.unprotect({
      providerId: updatedAccount.providerId,
      providerAccountId: updatedAccount.accountId,
      kind: "RefreshToken",
      protectedToken: updatedRefreshToken,
    });
    assert.strictEqual(Redacted.value(clearAccessToken), "second-link-access-token");
    assert.strictEqual(Redacted.value(clearRefreshToken), "first-link-refresh-token");

    const publicAccounts = yield* storage.listUserAccounts({ userId: credential.user.id });
    assert.strictEqual(publicAccounts.length, 2);
    for (const account of publicAccounts) {
      assert.strictEqual(Object.hasOwn(account, "providerTokens"), false);
    }
  }).pipe(
    Effect.provide(
      makeOAuthLayer(storageState, {
        providers: [callbackProvider],
        httpClientLive: HttpLive,
      }),
    ),
  );
});

it.effect("fails manual OAuth link callbacks without partial writes", () => {
  const mismatchState = makeDevMemoryStorageState();
  const conflictState = makeDevMemoryStorageState();

  return Effect.gen(function* () {
    const mismatch = yield* Effect.gen(function* () {
      const oauth = yield* OAuth;
      const credential = yield* createCredentialSession({
        email: "mismatch@example.com",
        name: "Mismatch User",
      });
      const started = yield* oauth.startLink({
        providerId: "github",
        redirectUri: new URL("https://app.example.com/auth/callback/github"),
        sessionToken: credential.sessionToken,
      });
      return yield* Effect.flip(
        oauth.completeCallback({
          providerId: "github",
          state: started.state,
          code: "mismatch-code",
          callbackMethod: "GET",
        }),
      );
    }).pipe(
      Effect.provide(
        makeOAuthLayer(mismatchState, {
          providers: [callbackProvider],
          httpClientLive: FakeOAuthHttpClientLive,
        }),
      ),
    );
    assert.deepStrictEqual(
      mismatch,
      new OAuthAccountStorageFailure({ reason: "LinkEmailMismatch" }),
    );
    assert.strictEqual(mismatchState.providerAccountsByKey.size, 0);
    assert.strictEqual(mismatchState.sessionsByHash.size, 1);

    const conflict = yield* Effect.gen(function* () {
      const oauth = yield* OAuth;
      const first = yield* createCredentialSession({
        email: "oauth@example.com",
        name: "First User",
      });
      const firstStart = yield* oauth.startLink({
        providerId: "github",
        redirectUri: new URL("https://app.example.com/auth/callback/github"),
        sessionToken: first.sessionToken,
      });
      const linked = yield* oauth.completeCallback({
        providerId: "github",
        state: firstStart.state,
        code: "first-link-code",
        callbackMethod: "GET",
      });
      if (linked.flow !== "Link") {
        return yield* new MissingOAuthTestFixture({
          message: "expected setup link callback result",
        });
      }

      const second = yield* createCredentialSession({
        email: "second@example.com",
        name: "Second User",
      });
      const secondStart = yield* oauth.startLink({
        providerId: "github",
        redirectUri: new URL("https://app.example.com/auth/callback/github"),
        sessionToken: second.sessionToken,
      });
      return yield* Effect.flip(
        oauth.completeCallback({
          providerId: "github",
          state: secondStart.state,
          code: "second-link-code",
          callbackMethod: "GET",
        }),
      );
    }).pipe(
      Effect.provide(
        makeOAuthLayer(conflictState, {
          providers: [callbackProvider],
          httpClientLive: FakeOAuthHttpClientLive,
        }),
      ),
    );
    assert.deepStrictEqual(
      conflict,
      new OAuthAccountStorageFailure({ reason: "ProviderAccountLinkedToDifferentUser" }),
    );
    assert.strictEqual(conflictState.providerAccountsByKey.size, 1);
    assert.strictEqual(conflictState.sessionsByHash.size, 2);
  });
});

it.effect("maps generic OAuth callback failures without partial public token exposure", () => {
  const storageState = makeDevMemoryStorageState();
  return Effect.gen(function* () {
    const oauth = yield* OAuth;

    const providerError = yield* Effect.flip(
      oauth.completeCallback({
        providerId: "github",
        state: "not-validated-before-provider-error",
        error: "access_denied",
        callbackMethod: "GET",
      }),
    );
    assert.deepStrictEqual(
      providerError,
      new OAuthCallbackError({ reason: "ProviderReturnedError" }),
    );

    const missingCodeStart = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
    });
    const missingCode = yield* Effect.flip(
      oauth.completeCallback({
        providerId: "github",
        state: missingCodeStart.state,
        callbackMethod: "GET",
      }),
    );
    assert.deepStrictEqual(
      missingCode,
      new OAuthCallbackError({ reason: "MissingAuthorizationCode" }),
    );

    const invalidState = yield* Effect.flip(
      oauth.completeCallback({
        providerId: "github",
        state: "bad-state",
        code: "provider-code",
        callbackMethod: "GET",
      }),
    );
    assert.deepStrictEqual(invalidState, new OAuthCallbackError({ reason: "InvalidState" }));

    const expiredStart = yield* oauth.startSignIn({
      providerId: "github",
      redirectUri: new URL("https://app.example.com/auth/callback/github"),
    });
    const stored = yield* latestStoredState(storageState);
    for (const [key, value] of storageState.oauthStatesByHash) {
      if (value.id === stored.id) {
        storageState.oauthStatesByHash.set(key, { ...value, expiresAt: 0 });
      }
    }
    const expired = yield* Effect.flip(
      oauth.completeCallback({
        providerId: "github",
        state: expiredStart.state,
        code: "provider-code",
        callbackMethod: "GET",
      }),
    );
    assert.deepStrictEqual(expired, new OAuthCallbackError({ reason: "ExpiredState" }));
  }).pipe(
    Effect.provide(
      makeOAuthLayer(storageState, {
        providers: [callbackProvider],
        httpClientLive: FakeOAuthHttpClientLive,
      }),
    ),
  );
});

it.effect(
  "fails generic OAuth callback for missing email, token protection, storage, and session errors",
  () => {
    const storageState = makeDevMemoryStorageState();
    const missingEmailProvider: OAuthProviderInput = {
      ...callbackProvider,
      id: "missing-email",
      mapProfile: () =>
        Effect.succeed({
          providerAccountId: "github-user-1",
          email: "",
          emailVerified: false,
          name: "Missing Email",
          image: null,
        }),
    };
    const failingProviderTokenProtectionLive = Layer.succeed(ProviderTokenProtection)({
      protect: () => Effect.fail(new ProviderTokenProtectionFailure({ reason: "EncryptFailed" })),
      unprotect: () => Effect.fail(new ProviderTokenProtectionFailure({ reason: "DecryptFailed" })),
    });
    const failingSessionStorage = makeDevMemoryStorage(storageState);
    const failingSessionStorageLive = Layer.succeed(AuthStorage)({
      ...failingSessionStorage,
      createSession: () => Effect.fail(new AuthStorageFailure({ reason: "BackendUnavailable" })),
    });

    return Effect.gen(function* () {
      const missingEmailOAuth = yield* OAuth;
      const missingEmailStart = yield* missingEmailOAuth.startSignIn({
        providerId: "missing-email",
        redirectUri: new URL("https://app.example.com/auth/callback/missing-email"),
      });
      const missingEmail = yield* Effect.flip(
        missingEmailOAuth.completeCallback({
          providerId: "missing-email",
          state: missingEmailStart.state,
          code: "provider-code",
          callbackMethod: "GET",
        }),
      );
      assert.deepStrictEqual(
        missingEmail,
        new OAuthCallbackError({ reason: "ProviderEmailRequired" }),
      );
    }).pipe(
      Effect.provide(
        makeOAuthLayer(storageState, {
          providers: [missingEmailProvider],
          httpClientLive: FakeOAuthHttpClientLive,
        }),
      ),
      Effect.flatMap(() =>
        Effect.gen(function* () {
          const oauth = yield* OAuth;
          const start = yield* oauth.startSignIn({
            providerId: "github",
            redirectUri: new URL("https://app.example.com/auth/callback/github"),
          });
          const failure = yield* Effect.flip(
            oauth.completeCallback({
              providerId: "github",
              state: start.state,
              code: "provider-code",
              callbackMethod: "GET",
            }),
          );
          assert.deepStrictEqual(
            failure,
            new OAuthCallbackError({ reason: "ProviderTokenProtectionFailed" }),
          );
        }).pipe(
          Effect.provide(
            makeOAuthLayer(makeDevMemoryStorageState(), {
              providers: [callbackProvider],
              httpClientLive: FakeOAuthHttpClientLive,
              providerTokenProtectionLive: failingProviderTokenProtectionLive,
            }),
          ),
        ),
      ),
      Effect.flatMap(() =>
        Effect.gen(function* () {
          const oauth = yield* OAuth;
          const start = yield* oauth.startSignIn({
            providerId: "github",
            redirectUri: new URL("https://app.example.com/auth/callback/github"),
            allowSignUp: false,
          });
          const failure = yield* Effect.flip(
            oauth.completeCallback({
              providerId: "github",
              state: start.state,
              code: "provider-code",
              callbackMethod: "GET",
            }),
          );
          assert.deepStrictEqual(
            failure,
            new OAuthAccountStorageFailure({ reason: "ImplicitSignUpDisabled" }),
          );
        }).pipe(
          Effect.provide(
            makeOAuthLayer(makeDevMemoryStorageState(), {
              providers: [callbackProvider],
              httpClientLive: FakeOAuthHttpClientLive,
            }),
          ),
        ),
      ),
      Effect.flatMap(() =>
        Effect.gen(function* () {
          const oauth = yield* OAuth;
          const start = yield* oauth.startSignIn({
            providerId: "github",
            redirectUri: new URL("https://app.example.com/auth/callback/github"),
          });
          const failure = yield* Effect.flip(
            oauth.completeCallback({
              providerId: "github",
              state: start.state,
              code: "provider-code",
              callbackMethod: "GET",
            }),
          );
          assert.deepStrictEqual(
            failure,
            new OAuthCallbackError({ reason: "SessionCreationFailed" }),
          );
          assert.strictEqual(storageState.sessionsByHash.size, 0);
        }).pipe(
          Effect.provide(
            makeOAuthLayer(storageState, {
              providers: [callbackProvider],
              httpClientLive: FakeOAuthHttpClientLive,
              storageLive: failingSessionStorageLive,
            }),
          ),
        ),
      ),
    );
  },
);

it.effect("fails provider layer construction for duplicate IDs", () =>
  Effect.gen(function* () {
    const duplicated = OAuthProviders.layer({ providers: [githubProvider, githubProvider] }).pipe(
      Layer.provide(UnexpectedHttpClientLive),
    );
    const failure = yield* Effect.flip(
      OAuthProviders.asEffect().pipe(Effect.asVoid, Effect.provide(duplicated)),
    );

    assert.strictEqual(Predicate.isTagged(failure, "OAuthProviderConfigError"), true);
    if (Predicate.isTagged(failure, "OAuthProviderConfigError")) {
      assert.deepStrictEqual(
        failure,
        new OAuthProviderConfigError({ reason: "DuplicateProviderId", providerId: "github" }),
      );
    }
  }),
);

it.effect("requires OAuth state encryption key material at layer construction", () =>
  Effect.gen(function* () {
    const storageState = makeDevMemoryStorageState();
    const ProvidersLive = OAuthProviders.layer({ providers: [githubProvider] }).pipe(
      Layer.provide(UnexpectedHttpClientLive),
    );
    const ProviderTokenProtectionLive = ProviderTokenProtection.layer.pipe(
      Layer.provide(AuthFeatureKeyMaterialService.layer),
    );
    const layer = OAuth.layer.pipe(
      Layer.provideMerge(ProviderTokenProtectionLive),
      Layer.provideMerge(OAuthProviderClient.layer),
      Layer.provideMerge(
        Layer.mergeAll(
          AuthLiveConfig.layer(),
          DevMemoryAuthStorage(storageState),
          ProvidersLive,
          UnexpectedHttpClientLive,
        ),
      ),
    );
    const failure = yield* Effect.flip(OAuth.asEffect().pipe(Effect.asVoid, Effect.provide(layer)));

    assert.deepStrictEqual(
      failure,
      new AuthFeatureKeyMaterialFailure({
        feature: "OAuthStateSecrets",
        reason: "MissingEncryptionKey",
      }),
    );
  }),
);
