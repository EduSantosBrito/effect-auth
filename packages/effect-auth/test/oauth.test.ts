import { assert, it } from "@effect/vitest";
import { Duration, Effect, Layer, Predicate, Redacted, Schema } from "effect";
import * as HttpClient from "effect/unstable/http/HttpClient";
import * as HttpClientError from "effect/unstable/http/HttpClientError";
import { AuthLiveConfig } from "../src/auth";
import { NormalizedEmail } from "../src/domain/index";
import {
  AuthFeatureKeyMaterialFailure,
  AuthFeatureKeyMaterialService,
  OAuth,
  OAuthProviderConfigError,
  OAuthProviderId,
  OAuthProviders,
  OAuthStartError,
  OAuthState,
  type OAuthProviderInput,
} from "../src/oauth/index";
import { PasswordHash } from "../src/password/index";
import {
  DevMemoryAuthStorage,
  makeDevMemoryStorageState,
  type DevMemoryStorageState,
} from "../src/storage/dev-memory";
import { AuthStorage, AuthStorageFailure } from "../src/storage/index";
import { AuthToken, AuthTokenLive } from "../src/token/index";

const encryptionKey = Redacted.make("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
const decodeEmail = Schema.decodeUnknownEffect(NormalizedEmail);
const decodeOAuthProviderId = Schema.decodeUnknownEffect(OAuthProviderId);
const decodePasswordHash = Schema.decodeUnknownEffect(PasswordHash);

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

const makeOAuthLayer = (
  storageState: DevMemoryStorageState,
  options: {
    readonly providers?: ReadonlyArray<OAuthProviderInput>;
    readonly oauthStateTtl?: Duration.Input;
  } = {},
) => {
  const ProvidersLive = OAuthProviders.layer({
    providers: options.providers ?? [githubProvider, oidcProvider],
  }).pipe(Layer.provide(UnexpectedHttpClientLive));
  const DependenciesLive = Layer.mergeAll(
    AuthLiveConfig.layer({
      encryptionKey,
      ...(options.oauthStateTtl === undefined
        ? {}
        : { oauthState: { ttl: options.oauthStateTtl } }),
    }),
    DevMemoryAuthStorage(storageState),
    ProvidersLive,
  );
  const OAuthStateLive = OAuthState.layer.pipe(Layer.provide(AuthFeatureKeyMaterialService.layer));
  return Layer.mergeAll(OAuth.layer, OAuthStateLive, AuthTokenLive).pipe(
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

const s256 = (value: string) => new Bun.CryptoHasher("sha256").update(value).digest("base64url");

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
    const layer = OAuth.layer.pipe(
      Layer.provideMerge(
        Layer.mergeAll(AuthLiveConfig.layer(), DevMemoryAuthStorage(storageState), ProvidersLive),
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
