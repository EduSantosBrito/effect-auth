import { assert, it } from "@effect/vitest";
import { Schema } from "effect";
import * as HttpClient from "effect/unstable/http/HttpClient";
import * as HttpClientError from "effect/unstable/http/HttpClientError";
import * as HttpClientResponse from "effect/unstable/http/HttpClientResponse";
import {
  Auth,
  AuthApiEndpoints,
  AuthHttp,
  AuthHttpAdapter,
  AuthHttpConfig,
  AuthHttpErrorMapper,
  AuthHttpToken,
  AuthLiveConfig,
  AuthSession,
  AuthToken,
  AuthTokenLive,
  Context,
  Cookies,
  CurrentAuthSession,
  DevMemoryAuthStorage,
  Effect,
  HttpClientRequest,
  HttpEffect,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
  Layer,
  OAuthHttp,
  Option,
  Predicate,
  Redacted,
  SessionCookie,
  SessionWorkflows,
  TrustedOrigins,
  checkTrustedOrigin,
  checkTrustedRequestOrigin,
  decodePasswordHash,
  handleChangePassword,
  handleCompletePasswordReset,
  handleCurrentSession,
  handleDeleteUser,
  handleRequestPasswordReset,
  handleSignInEmail,
  handleSignOut,
  handleSignUpEmail,
  handleVerifyEmail,
  invalidCredentials,
  jsonString,
  jsonWithCookieInstruction,
  makeDevMemoryStorage,
  makeDevMemoryStorageState,
  makeWorkflowLayer,
  mapPublicHttpError,
  missingFixture,
  normalizeEmail,
  normalizePassword,
  parseCallbackUrl,
  rateLimited,
  unauthorized,
  type SessionToken,
} from "./support";
import {
  AuthFeatureKeyMaterialService,
  OAuth,
  OAuthProviderClient,
  OAuthProviders,
  ProviderTokenProtection,
  type OAuthProviderInput,
} from "../src/oauth/index";

const MountedListSessionsResponse = Schema.Struct({
  sessions: Schema.Array(
    Schema.Struct({
      id: Schema.String,
      isCurrent: Schema.Boolean,
    }),
  ),
});
const MountedListSessionsResponseJson = Schema.fromJsonString(MountedListSessionsResponse);
const decodeMountedListSessionsResponseJson = Schema.decodeUnknownEffect(
  MountedListSessionsResponseJson,
);

const OAuthAuthorizationResponse = Schema.Struct({ authorizationUrl: Schema.String });
const OAuthAuthorizationResponseJson = Schema.fromJsonString(OAuthAuthorizationResponse);
const decodeOAuthAuthorizationResponseJson = Schema.decodeUnknownEffect(
  OAuthAuthorizationResponseJson,
);

const oauthHttpEncryptionKey = Redacted.make("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

const oauthHttpProvider: OAuthProviderInput = {
  id: "github",
  clientId: "github-client",
  clientSecret: Redacted.make("github-secret"),
  defaultScopes: ["read:user"],
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

const jsonOAuthResponse = (
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

const defaultOAuthTokenResponse = {
  access_token: "provider-access-token",
  refresh_token: "provider-refresh-token",
  token_type: "Bearer",
  scope: "read:user repo",
  expires_in: 3600,
};

const makeFakeOAuthHttpClientLive = (
  options: {
    readonly tokenStatus?: number;
    readonly tokenResponse?: Readonly<Record<string, unknown>>;
  } = {},
) =>
  Layer.succeed(HttpClient.HttpClient)(
    HttpClient.make((request, url) => {
      if (url.href === "https://github.example/token") {
        return Effect.succeed(
          jsonOAuthResponse(
            request,
            options.tokenResponse ?? defaultOAuthTokenResponse,
            options.tokenStatus ?? 200,
          ),
        );
      }
      return Effect.fail(
        new HttpClientError.HttpClientError({
          reason: new HttpClientError.TransportError({
            request,
            description: `unexpected OAuth HTTP provider request: ${url.href}`,
          }),
        }),
      );
    }),
  );

const makeOAuthHttpWorkflowLayer = (
  storageState = makeDevMemoryStorageState(),
  options: {
    readonly httpClientLive?: Layer.Layer<HttpClient.HttpClient>;
  } = {},
) => {
  const HttpLive = options.httpClientLive ?? makeFakeOAuthHttpClientLive();
  const ProvidersLive = OAuthProviders.layer({ providers: [oauthHttpProvider] }).pipe(
    Layer.provide(HttpLive),
  );
  const ProviderTokenProtectionLive = ProviderTokenProtection.layer.pipe(
    Layer.provide(AuthFeatureKeyMaterialService.layer),
  );
  const OAuthLive = OAuth.layer.pipe(
    Layer.provideMerge(ProviderTokenProtectionLive),
    Layer.provideMerge(OAuthProviderClient.layer),
    Layer.provideMerge(
      Layer.mergeAll(
        AuthLiveConfig.layer({ encryptionKey: oauthHttpEncryptionKey }),
        DevMemoryAuthStorage(storageState),
        ProvidersLive,
        HttpLive,
      ),
    ),
  );
  return { storageState, layer: OAuthLive };
};

it.effect("AuthHttp.mount adds a token-free sign-in route under the configured base path", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "mounted-sign-in@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });

    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const response = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/sign-in/email", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
            "x-forwarded-for": "203.0.113.10",
            "user-agent": "Effect Auth Browser",
          },
          body: jsonString({
            email: "mounted-sign-in@example.com",
            password: "correct horse battery staple",
            ip: "198.51.100.99",
          }),
        }),
        Context.empty(),
      ),
    );
    const bodyText = yield* Effect.promise(() => response.text());
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(response.status, 200, bodyText);
    assert.equal(response.headers.get("set-cookie")?.includes("effect_auth_session="), true);
    assert.equal(response.headers.get("set-cookie")?.includes("HttpOnly"), true);
    assert.equal(response.headers.get("set-cookie")?.includes("SameSite=Lax"), true);
    assert.equal(bodyText.includes("sessionToken"), false);
    assert.equal(bodyText.includes("tokenHash"), false);
  }).pipe(Effect.provide(authLayer));
});

it.effect("OAuthHttp.mount starts OAuth sign-in and link with server-derived callbacks", () => {
  const { storageState, layer: oauthLayer } = makeOAuthHttpWorkflowLayer();
  return Effect.gen(function* () {
    const storage = makeDevMemoryStorage(storageState);
    const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
    const email = yield* normalizeEmail("oauth-http-link@example.com");
    const passwordHash = yield* decodePasswordHash("hash:oauth-http-link");
    const user = yield* storage.createUserWithCredentialAccount({
      email,
      name: "OAuth HTTP Link User",
      image: null,
      passwordHash,
      now,
    });
    const sessionToken = yield* Effect.gen(function* () {
      const token = yield* AuthToken;
      return yield* token.makeSessionToken();
    }).pipe(Effect.provide(AuthTokenLive));
    yield* storage.createSession({
      userId: user.id,
      tokenHash: sessionToken.hash,
      expiresAt: Number.MAX_SAFE_INTEGER,
      now,
    });
    const seededSession = yield* storage.findSessionByTokenHash(sessionToken.hash);
    assert.strictEqual(seededSession.user.id, user.id);

    const routes = OAuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          oauthLayer,
          AuthHttpConfig.layer({
            baseUrl: new URL("https://app.example.com"),
            trustedOrigins: [new URL("https://app.example.com")],
            defaultTokenExtractor: AuthHttpToken.bearer,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });

    const signInResponse = yield* Effect.promise(() =>
      web.handler(
        new Request("https://edge.example.net/api/auth/sign-in/oauth2", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
          },
          body: jsonString({
            providerId: "github",
            scopes: ["repo"],
            allowSignUp: false,
            disableRedirect: true,
          }),
        }),
        Context.empty(),
      ),
    );
    const signInBodyText = yield* Effect.promise(() => signInResponse.text());
    assert.strictEqual(signInResponse.status, 200, signInBodyText);
    const signInBody = yield* decodeOAuthAuthorizationResponseJson(signInBodyText);
    const signInUrl = new URL(signInBody.authorizationUrl);

    assert.strictEqual(signInResponse.headers.get("location"), null);
    assert.strictEqual(signInUrl.origin, "https://github.example");
    assert.strictEqual(signInUrl.searchParams.get("client_id"), "github-client");
    assert.strictEqual(signInUrl.searchParams.get("scope"), "read:user repo");
    assert.strictEqual(
      signInUrl.searchParams.get("redirect_uri"),
      "https://app.example.com/api/auth/oauth2/callback/github",
    );
    assert.strictEqual(signInBodyText.includes("sessionToken"), false);
    assert.strictEqual(signInBodyText.includes("provider-access-token"), false);
    assert.strictEqual(storageState.oauthStatesByHash.size, 1);

    const linkResponse = yield* Effect.promise(() =>
      web.handler(
        new Request("https://edge.example.net/api/auth/oauth2/link", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
            authorization: `Bearer ${Redacted.value(sessionToken.token)}`,
          },
          body: jsonString({ providerId: "github", scopes: ["repo"] }),
        }),
        Context.empty(),
      ),
    );
    const linkBodyText = yield* Effect.promise(() => linkResponse.text());
    assert.strictEqual(linkResponse.status, 200, linkBodyText);
    const linkBody = yield* decodeOAuthAuthorizationResponseJson(linkBodyText);
    const linkUrl = new URL(linkBody.authorizationUrl);
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(
      linkUrl.searchParams.get("redirect_uri"),
      "https://app.example.com/api/auth/oauth2/callback/github",
    );
    assert.strictEqual(linkBodyText.includes(Redacted.value(sessionToken.token)), false);
    assert.strictEqual(linkBodyText.includes("sessionToken"), false);
    assert.strictEqual(storageState.oauthStatesByHash.size, 2);
  });
});

it.effect("OAuthHttp.mount requires configured baseUrl and trusted origins", () => {
  const { layer: oauthLayer } = makeOAuthHttpWorkflowLayer();
  return Effect.gen(function* () {
    const routes = OAuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const withoutBaseUrl = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          oauthLayer,
          AuthHttpConfig.layer({ trustedOrigins: [new URL("https://app.example.com")] }),
        ),
      ),
    );
    const withoutBaseUrlWeb = HttpRouter.toWebHandler(withoutBaseUrl, { disableLogger: true });
    const missingBaseUrl = yield* Effect.promise(() =>
      withoutBaseUrlWeb.handler(
        new Request("https://edge.example.net/api/auth/sign-in/oauth2", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
          },
          body: jsonString({ providerId: "github" }),
        }),
        Context.empty(),
      ),
    );
    const missingBaseUrlBody = yield* Effect.promise(() => missingBaseUrl.text());
    yield* Effect.promise(() => withoutBaseUrlWeb.dispose());

    assert.strictEqual(missingBaseUrl.status, 400, missingBaseUrlBody);
    assert.strictEqual(missingBaseUrlBody.includes("OAuth baseUrl is required"), true);

    const withBaseUrl = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          oauthLayer,
          AuthHttpConfig.layer({
            baseUrl: new URL("https://app.example.com"),
            trustedOrigins: [new URL("https://app.example.com")],
          }),
        ),
      ),
    );
    const withBaseUrlWeb = HttpRouter.toWebHandler(withBaseUrl, { disableLogger: true });
    const untrustedOrigin = yield* Effect.promise(() =>
      withBaseUrlWeb.handler(
        new Request("https://edge.example.net/api/auth/sign-in/oauth2", {
          method: "POST",
          headers: { "content-type": "application/json", origin: "https://evil.example.com" },
          body: jsonString({ providerId: "github" }),
        }),
        Context.empty(),
      ),
    );
    yield* Effect.promise(() => withBaseUrlWeb.dispose());

    assert.strictEqual(untrustedOrigin.status, 401);
  });
});

it.effect("OAuthHttp.mount completes GET sign-in callbacks with a session cookie", () => {
  const { storageState, layer: oauthLayer } = makeOAuthHttpWorkflowLayer();
  return Effect.gen(function* () {
    const routes = OAuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          oauthLayer,
          AuthHttpConfig.layer({
            baseUrl: new URL("https://app.example.com"),
            trustedOrigins: [new URL("https://app.example.com")],
            oauth: { signInSuccessPath: "/signed-in", errorPath: "/auth/oauth-error" },
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });

    const signInStart = yield* Effect.promise(() =>
      web.handler(
        new Request("https://edge.example.net/api/auth/sign-in/oauth2", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
          },
          body: jsonString({ providerId: "github" }),
        }),
        Context.empty(),
      ),
    );
    const signInStartText = yield* Effect.promise(() => signInStart.text());
    assert.strictEqual(signInStart.status, 200, signInStartText);
    const signInStartBody = yield* decodeOAuthAuthorizationResponseJson(signInStartText);
    const state = new URL(signInStartBody.authorizationUrl).searchParams.get("state");
    if (state === null) return yield* missingFixture("missing OAuth state");

    const callback = yield* Effect.promise(() =>
      web.handler(
        new Request(
          `https://edge.example.net/api/auth/oauth2/callback/github?state=${state}&code=callback-code`,
          { headers: { "user-agent": "Effect Auth OAuth Browser" } },
        ),
        Context.empty(),
      ),
    );
    const callbackText = yield* Effect.promise(() => callback.text());
    yield* Effect.promise(() => web.dispose());

    const location = callback.headers.get("location") ?? "";
    const setCookie = callback.headers.get("set-cookie") ?? "";
    const account = Array.from(storageState.providerAccountsByKey.values())[0];
    if (account === undefined) return yield* missingFixture("missing OAuth provider account");

    assert.strictEqual(callback.status, 302, callbackText);
    assert.strictEqual(location, "/signed-in");
    assert.strictEqual(setCookie.includes("effect_auth_session="), true);
    assert.strictEqual(location.includes("sessionToken"), false);
    assert.strictEqual(location.includes("provider-access-token"), false);
    assert.strictEqual(callbackText.includes("provider-access-token"), false);
    assert.notStrictEqual(account.providerTokens.accessToken, "provider-access-token");
  });
});

it.effect("OAuthHttp.mount completes POST link callbacks without a new session cookie", () => {
  const { storageState, layer: oauthLayer } = makeOAuthHttpWorkflowLayer();
  return Effect.gen(function* () {
    const storage = makeDevMemoryStorage(storageState);
    const now = yield* Effect.clockWith((clock) => clock.currentTimeMillis);
    const email = yield* normalizeEmail("github@example.com");
    const passwordHash = yield* decodePasswordHash("hash:oauth-http-link-callback");
    const user = yield* storage.createUserWithCredentialAccount({
      email,
      name: "OAuth HTTP Link Callback User",
      image: null,
      passwordHash,
      now,
    });
    const sessionToken = yield* Effect.gen(function* () {
      const token = yield* AuthToken;
      return yield* token.makeSessionToken();
    }).pipe(Effect.provide(AuthTokenLive));
    yield* storage.createSession({
      userId: user.id,
      tokenHash: sessionToken.hash,
      expiresAt: Number.MAX_SAFE_INTEGER,
      now,
    });

    const routes = OAuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          oauthLayer,
          AuthHttpConfig.layer({
            baseUrl: new URL("https://app.example.com"),
            trustedOrigins: [new URL("https://app.example.com")],
            defaultTokenExtractor: AuthHttpToken.bearer,
            oauth: { linkSuccessPath: "/settings/accounts", errorPath: "/auth/oauth-error" },
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });

    const linkStart = yield* Effect.promise(() =>
      web.handler(
        new Request("https://edge.example.net/api/auth/oauth2/link", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
            authorization: `Bearer ${Redacted.value(sessionToken.token)}`,
          },
          body: jsonString({ providerId: "github" }),
        }),
        Context.empty(),
      ),
    );
    const linkStartText = yield* Effect.promise(() => linkStart.text());
    assert.strictEqual(linkStart.status, 200, linkStartText);
    const linkStartBody = yield* decodeOAuthAuthorizationResponseJson(linkStartText);
    const state = new URL(linkStartBody.authorizationUrl).searchParams.get("state");
    if (state === null) return yield* missingFixture("missing link OAuth state");

    const form = new URLSearchParams({ state, code: "link-code" }).toString();
    const callback = yield* Effect.promise(() =>
      web.handler(
        new Request("https://edge.example.net/api/auth/oauth2/callback/github", {
          method: "POST",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          body: form,
        }),
        Context.empty(),
      ),
    );
    const callbackText = yield* Effect.promise(() => callback.text());
    yield* Effect.promise(() => web.dispose());

    const location = callback.headers.get("location") ?? "";
    const account = Array.from(storageState.providerAccountsByKey.values())[0];
    if (account === undefined) return yield* missingFixture("missing linked provider account");

    assert.strictEqual(callback.status, 302, callbackText);
    assert.strictEqual(location, "/settings/accounts");
    assert.strictEqual(callback.headers.get("set-cookie"), null);
    assert.strictEqual(location.includes(Redacted.value(sessionToken.token)), false);
    assert.strictEqual(location.includes("provider-access-token"), false);
    assert.strictEqual(callbackText.includes("provider-access-token"), false);
    assert.strictEqual(account.userId, user.id);
  });
});

it.effect("OAuthHttp.mount redirects callback failures safely", () => {
  const makeWeb = (input?: Parameters<typeof makeOAuthHttpWorkflowLayer>[1]) => {
    const storageState = makeDevMemoryStorageState();
    const { layer: oauthLayer } = makeOAuthHttpWorkflowLayer(storageState, input);
    const routes = OAuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          oauthLayer,
          AuthHttpConfig.layer({
            baseUrl: new URL("https://app.example.com"),
            trustedOrigins: [new URL("https://app.example.com")],
            oauth: { errorPath: "/auth/oauth-error" },
          }),
        ),
      ),
    );
    return { storageState, web: HttpRouter.toWebHandler(appLayer, { disableLogger: true }) };
  };
  const startState = Effect.fn("http.test.startOAuthState")(function* (
    web: ReturnType<typeof makeWeb>["web"],
  ) {
    const response = yield* Effect.promise(() =>
      web.handler(
        new Request("https://edge.example.net/api/auth/sign-in/oauth2", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
          },
          body: jsonString({ providerId: "github" }),
        }),
        Context.empty(),
      ),
    );
    const text = yield* Effect.promise(() => response.text());
    const body = yield* decodeOAuthAuthorizationResponseJson(text);
    const state = new URL(body.authorizationUrl).searchParams.get("state");
    if (state === null) return yield* missingFixture("missing OAuth failure state");
    return state;
  });
  const expectSafeErrorRedirect = Effect.fn("http.test.expectSafeErrorRedirect")(function* (
    response: Response,
  ) {
    const body = yield* Effect.promise(() => response.text());
    const location = response.headers.get("location") ?? "";
    assert.strictEqual(response.status, 302, body);
    assert.strictEqual(location, "/auth/oauth-error");
    assert.strictEqual(location.includes("provider-access-token"), false);
    assert.strictEqual(location.includes("sessionToken"), false);
    assert.strictEqual(body.includes("provider-access-token"), false);
    assert.strictEqual(body.includes("sessionToken"), false);
  });

  return Effect.gen(function* () {
    const providerError = makeWeb();
    const providerErrorResponse = yield* Effect.promise(() =>
      providerError.web.handler(
        new Request("https://edge.example.net/api/auth/oauth2/callback/github", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: jsonString({ state: "ignored", error: "access_denied" }),
        }),
        Context.empty(),
      ),
    );
    yield* expectSafeErrorRedirect(providerErrorResponse);
    yield* Effect.promise(() => providerError.web.dispose());

    const missingCode = makeWeb();
    const missingCodeState = yield* startState(missingCode.web);
    const missingCodeResponse = yield* Effect.promise(() =>
      missingCode.web.handler(
        new Request(
          `https://edge.example.net/api/auth/oauth2/callback/github?state=${missingCodeState}`,
        ),
        Context.empty(),
      ),
    );
    yield* expectSafeErrorRedirect(missingCodeResponse);
    yield* Effect.promise(() => missingCode.web.dispose());

    const invalidState = makeWeb();
    const invalidStateResponse = yield* Effect.promise(() =>
      invalidState.web.handler(
        new Request("https://edge.example.net/api/auth/oauth2/callback/github?state=bad&code=code"),
        Context.empty(),
      ),
    );
    yield* expectSafeErrorRedirect(invalidStateResponse);
    yield* Effect.promise(() => invalidState.web.dispose());

    const consumed = makeWeb();
    const consumedState = yield* startState(consumed.web);
    const firstConsumedResponse = yield* Effect.promise(() =>
      consumed.web.handler(
        new Request(
          `https://edge.example.net/api/auth/oauth2/callback/github?state=${consumedState}&code=first-code`,
        ),
        Context.empty(),
      ),
    );
    assert.strictEqual(firstConsumedResponse.status, 302);
    yield* Effect.promise(() => firstConsumedResponse.text());
    const consumedAgainResponse = yield* Effect.promise(() =>
      consumed.web.handler(
        new Request(
          `https://edge.example.net/api/auth/oauth2/callback/github?state=${consumedState}&code=second-code`,
        ),
        Context.empty(),
      ),
    );
    yield* expectSafeErrorRedirect(consumedAgainResponse);
    yield* Effect.promise(() => consumed.web.dispose());

    const expired = makeWeb();
    const expiredState = yield* startState(expired.web);
    for (const [key, record] of expired.storageState.oauthStatesByHash) {
      expired.storageState.oauthStatesByHash.set(key, { ...record, expiresAt: 0 });
    }
    const expiredResponse = yield* Effect.promise(() =>
      expired.web.handler(
        new Request(
          `https://edge.example.net/api/auth/oauth2/callback/github?state=${expiredState}&code=expired-code`,
        ),
        Context.empty(),
      ),
    );
    yield* expectSafeErrorRedirect(expiredResponse);
    yield* Effect.promise(() => expired.web.dispose());

    const tokenFailure = makeWeb({
      httpClientLive: makeFakeOAuthHttpClientLive({ tokenStatus: 500 }),
    });
    const tokenFailureState = yield* startState(tokenFailure.web);
    const tokenFailureResponse = yield* Effect.promise(() =>
      tokenFailure.web.handler(
        new Request(
          `https://edge.example.net/api/auth/oauth2/callback/github?state=${tokenFailureState}&code=token-failure-code`,
        ),
        Context.empty(),
      ),
    );
    yield* expectSafeErrorRedirect(tokenFailureResponse);
    assert.strictEqual(tokenFailure.storageState.providerAccountsByKey.size, 0);
    yield* Effect.promise(() => tokenFailure.web.dispose());
  });
});

it.effect("AuthHttp.mount ignores malformed forwarded client IPs", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "mounted-malformed-ip@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });

    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const signIn = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/sign-in/email", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
            "x-forwarded-for": "not-an-ip, 203.0.113.10",
          },
          body: jsonString({
            email: "mounted-malformed-ip@example.com",
            password: "correct horse battery staple",
          }),
        }),
        Context.empty(),
      ),
    );
    const sessionCookie = signIn.headers.get("set-cookie");
    if (!sessionCookie) return yield* missingFixture("missing sign-in cookie");
    const listed = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/sessions", {
          headers: { cookie: sessionCookie },
        }),
        Context.empty(),
      ),
    );
    const listedBody = yield* Effect.promise(() => listed.text());
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(signIn.status, 200);
    assert.strictEqual(listed.status, 200);
    assert.equal(listedBody.includes("not-an-ip"), false);
    assert.equal(listedBody.includes("203.0.113.10"), false);
  }).pipe(Effect.provide(authLayer));
});

it.effect("AuthHttp.mount rejects cookie state changes without trusted origin or referer", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "mounted-origin@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });
    const signedIn = yield* auth.signIn({
      email: "mounted-origin@example.com",
      password: "correct horse battery staple",
    });

    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const cookie = `effect_auth_session=${Redacted.value(signedIn.sessionToken)}`;

    const missingOrigin = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/sign-out", {
          method: "POST",
          headers: { cookie },
        }),
        Context.empty(),
      ),
    );
    const nullOrigin = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/sign-out", {
          method: "POST",
          headers: { cookie, origin: "null" },
        }),
        Context.empty(),
      ),
    );
    const trustedReferer = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/sign-out", {
          method: "POST",
          headers: { cookie, referer: "https://app.example.com/settings" },
        }),
        Context.empty(),
      ),
    );
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(missingOrigin.status, 401);
    assert.strictEqual(nullOrigin.status, 401);
    assert.strictEqual(trustedReferer.status, 200);
    assert.equal(trustedReferer.headers.get("set-cookie")?.includes("Max-Age=0"), true);
  }).pipe(Effect.provide(authLayer));
});

it.effect("AuthHttp.mount uses custom HTTP error mapper when provided", () => {
  const { layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
          Layer.succeed(AuthHttpErrorMapper)({
            map: (error) =>
              Effect.succeed({
                status: 499,
                body: { envelope: "custom-auth-error", tag: error._tag },
              }),
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const response = yield* Effect.promise(() =>
      web.handler(new Request("https://auth.example.com/api/auth/session"), Context.empty()),
    );
    const body = yield* Effect.promise(() => response.text());
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(response.status, 499);
    assert.equal(body.includes("custom-auth-error"), true);
    assert.equal(body.includes("MissingSessionToken"), true);
  });
});

it.effect("AuthHttp.mount serves email, session, sign-out, and password routes", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const json = (body: unknown, cookie?: string) => ({
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example.com",
        "user-agent": "Effect Auth Browser",
        ...(cookie === undefined ? {} : { cookie }),
      },
      body: jsonString(body),
    });
    const call = (path: string, init?: RequestInit) =>
      Effect.promise(() =>
        web.handler(new Request(`https://auth.example.com${path}`, init), Context.empty()),
      );

    const signUp = yield* call(
      "/api/auth/sign-up/email",
      json({
        email: "mounted-flow@example.com",
        password: "correct horse battery staple",
        name: "Test User",
        verificationCallbackUrl: "https://app.example.com/verify",
      }),
    );
    assert.strictEqual(signUp.status, 200, yield* Effect.promise(() => signUp.clone().text()));

    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    const verified = yield* call(
      "/api/auth/verify-email",
      json({ token: Redacted.value(verification.token) }),
    );
    assert.strictEqual(verified.status, 200);

    const signIn = yield* call(
      "/api/auth/sign-in/email",
      json({
        email: "mounted-flow@example.com",
        password: "correct horse battery staple",
      }),
    );
    const sessionCookie = signIn.headers.get("set-cookie");
    if (!sessionCookie) return yield* missingFixture("missing sign-in cookie");
    const signInBody = yield* Effect.promise(() => signIn.text());
    assert.equal(signInBody.includes("sessionToken"), false);

    const current = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: sessionCookie },
    });
    const currentBody = yield* Effect.promise(() => current.text());
    assert.strictEqual(current.status, 200);
    assert.equal(currentBody.includes("mounted-flow@example.com"), true);
    assert.equal(currentBody.includes("tokenHash"), false);

    const secondSignIn = yield* call(
      "/api/auth/sign-in/email",
      json({
        email: "mounted-flow@example.com",
        password: "correct horse battery staple",
      }),
    );
    const secondCookie = secondSignIn.headers.get("set-cookie");
    if (!secondCookie) return yield* missingFixture("missing second sign-in cookie");

    const listed = yield* call("/api/auth/sessions", {
      method: "GET",
      headers: { cookie: sessionCookie },
    });
    const listedText = yield* Effect.promise(() => listed.text());
    const listedBody = yield* decodeMountedListSessionsResponseJson(listedText);
    const otherSession = listedBody.sessions.find((session) => !session.isCurrent);
    if (!otherSession) return yield* missingFixture("missing other listed session");
    assert.strictEqual(listed.status, 200);
    assert.equal(listedText.includes("tokenHash"), false);
    assert.equal(listedText.includes("Effect Auth Browser"), true);

    const revokedOne = yield* call(
      "/api/auth/sessions/revoke",
      json({ sessionId: otherSession.id }, sessionCookie),
    );
    assert.strictEqual(revokedOne.status, 200);
    const secondAfterRevoke = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: secondCookie },
    });
    assert.notStrictEqual(secondAfterRevoke.status, 200);

    const thirdSignIn = yield* call(
      "/api/auth/sign-in/email",
      json({
        email: "mounted-flow@example.com",
        password: "correct horse battery staple",
      }),
    );
    const thirdCookie = thirdSignIn.headers.get("set-cookie");
    if (!thirdCookie) return yield* missingFixture("missing third sign-in cookie");
    const revokedOthers = yield* call("/api/auth/sessions/revoke-others", json({}, sessionCookie));
    assert.strictEqual(revokedOthers.status, 200);
    const thirdAfterRevoke = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: thirdCookie },
    });
    assert.notStrictEqual(thirdAfterRevoke.status, 200);

    const resetRequested = yield* call(
      "/api/auth/password-reset/request",
      json({
        email: "mounted-flow@example.com",
        resetCallbackUrl: "https://app.example.com/reset",
      }),
    );
    assert.strictEqual(resetRequested.status, 200);
    const reset = emailState.sent.find((sent) => sent.kind === "PasswordReset");
    if (!reset) return yield* missingFixture("missing password reset email");
    const resetCompleted = yield* call(
      "/api/auth/password-reset/complete",
      json({ token: Redacted.value(reset.token), password: "new correct horse battery staple" }),
    );
    assert.strictEqual(resetCompleted.status, 200);

    const oldSession = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: sessionCookie },
    });
    assert.notStrictEqual(oldSession.status, 200);

    const signedInAgain = yield* call(
      "/api/auth/sign-in/email",
      json({
        email: "mounted-flow@example.com",
        password: "new correct horse battery staple",
      }),
    );
    const changedCookie = signedInAgain.headers.get("set-cookie");
    if (!changedCookie) return yield* missingFixture("missing changed sign-in cookie");

    const changed = yield* call(
      "/api/auth/password/change",
      json(
        {
          currentPassword: "new correct horse battery staple",
          newPassword: "newer correct horse battery staple",
          sessionToken: "client-supplied-token-is-ignored",
        },
        changedCookie,
      ),
    );
    const changedBody = yield* Effect.promise(() => changed.text());
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(changed.status, 200);
    assert.equal(changed.headers.get("set-cookie")?.includes("effect_auth_session="), true);
    assert.equal(changedBody.includes("sessionToken"), false);
  });
});

it.effect("mounted session revocation preserves rotated current cookies", () => {
  const { emailState, storageState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const json = (body: unknown, cookie?: string) => ({
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://app.example.com",
        ...(cookie === undefined ? {} : { cookie }),
      },
      body: jsonString(body),
    });
    const call = (path: string, init?: RequestInit) =>
      Effect.promise(() =>
        web.handler(new Request(`https://auth.example.com${path}`, init), Context.empty()),
      );

    yield* call(
      "/api/auth/sign-up/email",
      json({
        email: "mounted-stale-revoke@example.com",
        password: "correct horse battery staple",
        name: "Test User",
        verificationCallbackUrl: "https://app.example.com/verify",
      }),
    );
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* call("/api/auth/verify-email", json({ token: Redacted.value(verification.token) }));

    const signIn = yield* call(
      "/api/auth/sign-in/email",
      json({ email: "mounted-stale-revoke@example.com", password: "correct horse battery staple" }),
    );
    const currentCookie = signIn.headers.get("set-cookie");
    if (!currentCookie) return yield* missingFixture("missing current cookie");
    const otherSignIn = yield* call(
      "/api/auth/sign-in/email",
      json({ email: "mounted-stale-revoke@example.com", password: "correct horse battery staple" }),
    );
    const otherCookie = otherSignIn.headers.get("set-cookie");
    if (!otherCookie) return yield* missingFixture("missing other cookie");

    const listed = yield* call("/api/auth/sessions", {
      method: "GET",
      headers: { cookie: currentCookie },
    });
    const listedBody = yield* decodeMountedListSessionsResponseJson(
      yield* Effect.promise(() => listed.text()),
    );
    const otherSession = listedBody.sessions.find((session) => !session.isCurrent);
    if (!otherSession) return yield* missingFixture("missing listed other session");

    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }
    const revokedOne = yield* call(
      "/api/auth/sessions/revoke",
      json({ sessionId: otherSession.id }, currentCookie),
    );
    const rotatedCookie = revokedOne.headers.get("set-cookie");
    if (!rotatedCookie) return yield* missingFixture("missing rotated revoke cookie");
    const currentAfterRevoke = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: rotatedCookie },
    });
    const otherAfterRevoke = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: otherCookie },
    });

    const thirdSignIn = yield* call(
      "/api/auth/sign-in/email",
      json({ email: "mounted-stale-revoke@example.com", password: "correct horse battery staple" }),
    );
    const thirdCookie = thirdSignIn.headers.get("set-cookie");
    if (!thirdCookie) return yield* missingFixture("missing third cookie");
    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }
    const revokedOthers = yield* call("/api/auth/sessions/revoke-others", json({}, rotatedCookie));
    const rotatedOthersCookie = revokedOthers.headers.get("set-cookie");
    if (!rotatedOthersCookie) return yield* missingFixture("missing revoke-others rotated cookie");
    const currentAfterOthers = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: rotatedOthersCookie },
    });
    const thirdAfterOthers = yield* call("/api/auth/session", {
      method: "GET",
      headers: { cookie: thirdCookie },
    });
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(revokedOne.status, 200);
    assert.equal(rotatedCookie.includes("Max-Age=0"), false);
    assert.strictEqual(currentAfterRevoke.status, 200);
    assert.notStrictEqual(otherAfterRevoke.status, 200);
    assert.strictEqual(revokedOthers.status, 200);
    assert.equal(rotatedOthersCookie.includes("Max-Age=0"), false);
    assert.strictEqual(currentAfterOthers.status, 200);
    assert.notStrictEqual(thirdAfterOthers.status, 200);
  });
});

it.effect(
  "AuthHttp.requireAuth provides AuthSession from cookies and explicit bearer tokens",
  () => {
    const { emailState, layer: authLayer } = makeWorkflowLayer();
    return Effect.gen(function* () {
      const auth = yield* Auth;
      yield* auth.signUp({
        email: "protected-session@example.com",
        password: "correct horse battery staple",
        name: "Test User",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      });
      const verification = emailState.sent[0];
      if (!verification) return yield* missingFixture("missing verification email");
      yield* auth.verifyEmail({ token: verification.token });
      const signedIn = yield* auth.signIn({
        email: "protected-session@example.com",
        password: "correct horse battery staple",
      });

      const protectedProgram = Effect.gen(function* () {
        const session = yield* AuthSession;
        return {
          email: session.user.email,
          hasSessionToken: Object.hasOwn(session, "sessionToken"),
        };
      }).pipe(AuthHttp.requireAuth);

      const cookieSession = yield* protectedProgram.pipe(
        Effect.provideService(
          HttpServerRequest.HttpServerRequest,
          HttpServerRequest.fromClientRequest(
            HttpClientRequest.get("https://auth.example.com/me").pipe(
              HttpClientRequest.setHeader(
                "cookie",
                `effect_auth_session=${Redacted.value(signedIn.sessionToken)}`,
              ),
            ),
          ),
        ),
      );

      const bearerProgram = AuthHttp.requireAuth({ extractor: AuthHttpToken.bearer })(
        Effect.gen(function* () {
          const session = yield* AuthSession;
          return { email: session.user.email };
        }),
      );

      const bearerSession = yield* bearerProgram.pipe(
        Effect.provideService(
          HttpServerRequest.HttpServerRequest,
          HttpServerRequest.fromClientRequest(
            HttpClientRequest.get("https://auth.example.com/me").pipe(
              HttpClientRequest.bearerToken(signedIn.sessionToken),
            ),
          ),
        ),
      );

      const missing = yield* Effect.exit(
        protectedProgram.pipe(
          Effect.provideService(
            HttpServerRequest.HttpServerRequest,
            HttpServerRequest.fromClientRequest(
              HttpClientRequest.get("https://auth.example.com/me"),
            ),
          ),
        ),
      );

      assert.deepStrictEqual(cookieSession, {
        email: "protected-session@example.com",
        hasSessionToken: false,
      });
      assert.deepStrictEqual(bearerSession, { email: "protected-session@example.com" });
      assert.strictEqual(missing._tag, "Failure");
    }).pipe(
      Effect.provide(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
        ),
      ),
    );
  },
);

it.effect("AuthHttp.optionalAuth provides CurrentAuthSession and cleans stale cookies", () => {
  const { storageState, emailState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "optional-session@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });
    const signedIn = yield* auth.signIn({
      email: "optional-session@example.com",
      password: "correct horse battery staple",
    });
    yield* auth.signUp({
      email: "optional-bearer@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const bearerVerification = emailState.sent[1];
    if (!bearerVerification) return yield* missingFixture("missing bearer verification email");
    yield* auth.verifyEmail({ token: bearerVerification.token });
    const bearerSignedIn = yield* auth.signIn({
      email: "optional-bearer@example.com",
      password: "correct horse battery staple",
    });

    const optionalProgram = Effect.gen(function* () {
      const session = yield* CurrentAuthSession;
      return Option.match(session.current, {
        onNone: () => ({ signedIn: false }),
        onSome: ({ user }) => ({ signedIn: true, email: String(user.email) }),
      });
    }).pipe(AuthHttp.optionalAuth);

    const anonymous = yield* optionalProgram.pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.get("https://auth.example.com/navbar"),
        ),
      ),
    );
    const signedInState = yield* optionalProgram.pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.get("https://auth.example.com/navbar").pipe(
            HttpClientRequest.setHeader(
              "cookie",
              `effect_auth_session=${Redacted.value(signedIn.sessionToken)}`,
            ),
          ),
        ),
      ),
    );

    const combinedProgram = AuthHttp.optionalAuth({ extractor: AuthHttpToken.cookieOrBearer })(
      Effect.gen(function* () {
        const session = yield* CurrentAuthSession;
        return Option.match(session.current, {
          onNone: () => "anonymous",
          onSome: ({ user }) => String(user.email),
        });
      }),
    );
    const combined = yield* combinedProgram.pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.get("https://auth.example.com/navbar").pipe(
            HttpClientRequest.setHeader("authorization", "Bearer invalid-session-token"),
            HttpClientRequest.setHeader(
              "cookie",
              `effect_auth_session=${Redacted.value(signedIn.sessionToken)}`,
            ),
          ),
        ),
      ),
    );
    const bearerWins = yield* combinedProgram.pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.get("https://auth.example.com/navbar").pipe(
            HttpClientRequest.bearerToken(bearerSignedIn.sessionToken),
            HttpClientRequest.setHeader(
              "cookie",
              `effect_auth_session=${Redacted.value(signedIn.sessionToken)}`,
            ),
          ),
        ),
      ),
    );

    const clearCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      AuthHttp.optionalAuth(
        Effect.gen(function* () {
          yield* CurrentAuthSession;
          return HttpServerResponse.jsonUnsafe(null);
        }),
      ),
      (_request, response) =>
        Effect.sync(() => {
          clearCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.get("https://auth.example.com/navbar").pipe(
            HttpClientRequest.setHeader("cookie", `effect_auth_session=${"a".repeat(43)}`),
          ),
        ),
      ),
    );

    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }
    const rotationCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      AuthHttp.optionalAuth(
        Effect.gen(function* () {
          yield* CurrentAuthSession;
          return HttpServerResponse.jsonUnsafe(null);
        }),
      ),
      (_request, response) =>
        Effect.sync(() => {
          rotationCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.get("https://auth.example.com/navbar").pipe(
            HttpClientRequest.setHeader(
              "cookie",
              `effect_auth_session=${Redacted.value(signedIn.sessionToken)}`,
            ),
          ),
        ),
      ),
    );

    assert.deepStrictEqual(anonymous, { signedIn: false });
    assert.deepStrictEqual(signedInState, {
      signedIn: true,
      email: "optional-session@example.com",
    });
    assert.strictEqual(combined, "optional-session@example.com");
    assert.strictEqual(bearerWins, "optional-bearer@example.com");
    assert.equal(clearCookies[0]?.includes("Max-Age=0"), true);
    assert.equal(rotationCookies[0]?.includes("effect_auth_session="), true);
    assert.equal(rotationCookies[0]?.includes(Redacted.value(signedIn.sessionToken)), false);
  }).pipe(
    Effect.provide(
      Layer.mergeAll(
        authLayer,
        AuthHttpConfig.layer({
          trustedOrigins: [new URL("https://app.example.com")],
          secureCookies: true,
        }),
      ),
    ),
  );
});

it.effect("AuthHttp rejects malformed session tokens at HTTP boundaries", () => {
  const { layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            defaultTokenExtractor: AuthHttpToken.cookieOrBearer,
            secureCookies: true,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });

    const mountedBearer = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/session", {
          headers: { authorization: "Bearer malformed-session-token" },
        }),
        Context.empty(),
      ),
    );
    const mountedCookie = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/session", {
          headers: { cookie: "effect_auth_session=malformed-session-token" },
        }),
        Context.empty(),
      ),
    );
    yield* Effect.promise(() => web.dispose());

    const requireBearer = yield* Effect.exit(
      AuthHttp.requireAuth({ extractor: AuthHttpToken.bearer })(
        Effect.gen(function* () {
          const session = yield* AuthSession;
          return session.user.id;
        }),
      ).pipe(
        Effect.provideService(
          HttpServerRequest.HttpServerRequest,
          HttpServerRequest.fromClientRequest(
            HttpClientRequest.get("https://auth.example.com/me").pipe(
              HttpClientRequest.setHeader("authorization", "Bearer malformed-session-token"),
            ),
          ),
        ),
      ),
    );

    const clearCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      AuthHttp.optionalAuth(
        Effect.gen(function* () {
          const session = yield* CurrentAuthSession;
          return HttpServerResponse.jsonUnsafe({ signedIn: Option.isSome(session.current) });
        }),
      ),
      (_request, response) =>
        Effect.sync(() => {
          clearCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.get("https://auth.example.com/navbar").pipe(
            HttpClientRequest.setHeader("cookie", "effect_auth_session=malformed-session-token"),
          ),
        ),
      ),
    );

    assert.strictEqual(mountedBearer.status, 400);
    assert.strictEqual(mountedCookie.status, 400);
    assert.strictEqual(requireBearer._tag, "Failure");
    if (Predicate.isTagged(requireBearer, "Failure")) {
      assert.equal(String(requireBearer.cause).includes("InvalidSessionToken"), true);
    }
    assert.equal(clearCookies[0]?.includes("Max-Age=0"), true);
  }).pipe(
    Effect.provide(
      Layer.mergeAll(
        authLayer,
        AuthHttpConfig.layer({
          trustedOrigins: [new URL("https://app.example.com")],
          secureCookies: true,
        }),
      ),
    ),
  );
});

it.effect("HTTP token extraction treats bearer auth as a non-cookie source", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer({
    httpConfig: {
      trustedOrigins: [new URL("https://app.example.com")],
      defaultTokenExtractor: AuthHttpToken.cookieOrBearer,
      secureCookies: true,
    },
  });
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "bearer-revoke-all@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });
    const signedIn = yield* auth.signIn({
      email: "bearer-revoke-all@example.com",
      password: "correct horse battery staple",
    });

    const extracted = yield* AuthHttpToken.cookieOrBearer.extract.pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(
          HttpClientRequest.post("https://auth.example.com/api/auth/sessions/revoke-all").pipe(
            HttpClientRequest.bearerToken(signedIn.sessionToken),
            HttpClientRequest.setHeader("cookie", "effect_auth_session=malformed-session-token"),
          ),
        ),
      ),
    );

    assert.strictEqual(extracted._tag, "Found");
    if (Predicate.isTagged(extracted, "Found")) {
      assert.strictEqual(extracted.source, "Bearer");
    }
  }).pipe(Effect.provide(authLayer));
});

it.effect("AuthHttpConfig rejects invalid session cookie settings before use", () =>
  Effect.gen(function* () {
    const invalidName = yield* Effect.exit(
      Effect.gen(function* () {
        const config = yield* AuthHttpConfig;
        return config.sessionCookieName;
      }).pipe(
        Effect.provide(
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            sessionCookieName: "bad cookie name",
          }),
        ),
      ),
    );
    const invalidPath = yield* Effect.exit(
      Effect.gen(function* () {
        const config = yield* AuthHttpConfig;
        return config.sessionCookiePath;
      }).pipe(
        Effect.provide(
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            sessionCookiePath: "not/absolute",
          }),
        ),
      ),
    );
    const invalidOAuthRedirectPath = yield* Effect.exit(
      Effect.gen(function* () {
        const config = yield* AuthHttpConfig;
        return config.oauth.errorPath;
      }).pipe(
        Effect.provide(
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            oauth: { errorPath: "https://evil.example.com/auth/error" },
          }),
        ),
      ),
    );

    assert.strictEqual(invalidName._tag, "Failure");
    assert.strictEqual(invalidPath._tag, "Failure");
    assert.strictEqual(invalidOAuthRedirectPath._tag, "Failure");
  }),
);

it.effect("http helpers preserve cookie defaults and public error mapping", () => {
  const { layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const tokenService = yield* AuthToken;
    const session = yield* tokenService.makeSessionToken();
    const setCookie = SessionCookie.make(session.token);
    const clearCookie = SessionCookie.clear();

    assert.strictEqual(setCookie.name, "effect_auth_session");
    assert.strictEqual(setCookie.httpOnly, true);
    assert.strictEqual(setCookie.sameSite, "Lax");
    assert.strictEqual(setCookie.path, "/");
    assert.strictEqual(setCookie.secure, true);
    assert.strictEqual(clearCookie.maxAge, 0);
    assert.deepStrictEqual(
      Cookies.toSetCookieHeaders(jsonWithCookieInstruction(null, setCookie).cookies),
      [
        `effect_auth_session=${Redacted.value(session.token)}; Path=/; HttpOnly; Secure; SameSite=Lax`,
      ],
    );
    assert.deepStrictEqual(
      Cookies.toSetCookieHeaders(jsonWithCookieInstruction(null, clearCookie).cookies),
      ["effect_auth_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax"],
    );
    assert.deepStrictEqual(mapPublicHttpError(rateLimited), { status: 429, body: rateLimited });
    assert.deepStrictEqual(mapPublicHttpError(unauthorized), { status: 401, body: unauthorized });
    assert.deepStrictEqual(mapPublicHttpError(invalidCredentials), {
      status: 400,
      body: invalidCredentials,
    });
  }).pipe(Effect.provide(layer));
});

it.effect("http adapter appends rotated session cookies to handled responses", () => {
  const { emailState, storageState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* Auth;
    const adapter = yield* AuthHttpAdapter;
    yield* emailPassword.signUp({
      email: "http-cookie@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });
    const signedIn = yield* emailPassword.signIn({
      email: "http-cookie@example.com",
      password: "correct horse battery staple",
    });
    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }

    const setCookieHeaders: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        yield* adapter.currentSession({ sessionToken: signedIn.sessionToken });
        return HttpServerResponse.jsonUnsafe(null);
      }),
      (_request, response) =>
        Effect.sync(() => {
          setCookieHeaders.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.get("https://auth.example.com")),
      ),
    );

    assert.strictEqual(setCookieHeaders.length, 1);
    assert.equal(setCookieHeaders[0]?.includes("effect_auth_session="), true);
    assert.equal(setCookieHeaders[0]?.includes("HttpOnly"), true);
    assert.equal(setCookieHeaders[0]?.includes("SameSite=Lax"), true);
    assert.equal(setCookieHeaders[0]?.includes(Redacted.value(signedIn.sessionToken)), false);
  }).pipe(Effect.provide(layer));
});

it.effect("http adapter appends sign-in and sign-out session cookie instructions", () => {
  const { emailState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* Auth;
    const adapter = yield* AuthHttpAdapter;
    yield* emailPassword.signUp({
      email: "http-sign-in-out@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });

    const signInCookies: Array<string> = [];
    let signedInToken: SessionToken | undefined;
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        const email = yield* normalizeEmail("http-sign-in-out@example.com");
        const password = yield* normalizePassword("correct horse battery staple");
        const result = yield* adapter.signInEmail({
          email,
          password,
        });
        signedInToken = result.sessionToken;
        return HttpServerResponse.jsonUnsafe(result);
      }),
      (_request, response) =>
        Effect.sync(() => {
          signInCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
      ),
    );
    if (!signedInToken) return yield* missingFixture("missing signed-in token");
    const sessionToken = signedInToken;

    const signOutCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        yield* adapter.signOut({ sessionToken });
        return HttpServerResponse.jsonUnsafe(null);
      }),
      (_request, response) =>
        Effect.sync(() => {
          signOutCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
      ),
    );

    assert.strictEqual(signInCookies.length, 1);
    assert.equal(signInCookies[0]?.includes("effect_auth_session="), true);
    assert.equal(signInCookies[0]?.includes("HttpOnly"), true);
    assert.equal(signInCookies[0]?.includes("Max-Age=0"), false);
    assert.strictEqual(signOutCookies.length, 1);
    assert.equal(signOutCookies[0]?.includes("effect_auth_session="), true);
    assert.equal(signOutCookies[0]?.includes("Max-Age=0"), true);
  }).pipe(Effect.provide(layer));
});

it.effect("http adapter uses configured session cookie options", () => {
  const { emailState, layer } = makeWorkflowLayer({
    httpConfig: {
      trustedOrigins: [new URL("https://app.example.com")],
      sessionCookieName: "__Host_effect_auth",
      sessionCookiePath: "/auth",
      secureCookies: true,
    },
  });
  return Effect.gen(function* () {
    const emailPassword = yield* Auth;
    const adapter = yield* AuthHttpAdapter;
    yield* emailPassword.signUp({
      email: "configured-cookie@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: "https://app.example.com/verify",
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });

    const signInCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        const email = yield* normalizeEmail("configured-cookie@example.com");
        const password = yield* normalizePassword("correct horse battery staple");
        yield* adapter.signInEmail({
          email,
          password,
        });
        return HttpServerResponse.jsonUnsafe(null);
      }),
      (_request, response) =>
        Effect.sync(() => {
          signInCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
      ),
    );

    assert.strictEqual(signInCookies.length, 1);
    assert.equal(signInCookies[0]?.includes("__Host_effect_auth="), true);
    assert.equal(signInCookies[0]?.includes("Path=/auth"), true);
    assert.equal(signInCookies[0]?.includes("Secure"), true);
  }).pipe(Effect.provide(layer));
});

it.effect("http adapter delegates password reset and password change behavior", () => {
  const { emailState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* Auth;
    const adapter = yield* AuthHttpAdapter;
    const sessions = yield* SessionWorkflows;

    yield* emailPassword.signUp({
      email: "http-adapter@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* adapter.verifyEmail({ token: verification.token });

    const email = yield* normalizeEmail("http-adapter@example.com");
    yield* adapter.requestPasswordReset({
      email,
      resetCallbackUrl: yield* parseCallbackUrl(new URL("https://app.example.com/reset")),
    });
    const reset = emailState.sent[1];
    if (!reset) return yield* missingFixture("missing reset email");
    assert.strictEqual(reset.kind, "PasswordReset");

    yield* adapter.completePasswordReset({
      token: reset.token,
      password: yield* normalizePassword("new correct horse battery"),
    });
    const signedIn = yield* emailPassword.signIn({
      email: "http-adapter@example.com",
      password: "new correct horse battery",
    });
    const changed = yield* adapter
      .changePassword({
        sessionToken: signedIn.sessionToken,
        currentPassword: yield* normalizePassword("new correct horse battery"),
        newPassword: yield* normalizePassword("changed correct horse battery"),
      })
      .pipe(
        Effect.provideService(
          HttpServerRequest.HttpServerRequest,
          HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
        ),
      );
    const current = yield* sessions.currentSession({
      sessionToken: changed.currentSessionToken,
    });

    assert.strictEqual(current.session.userId, signedIn.user.id);
  }).pipe(Effect.provide(layer));
});

it.effect("http handler functions exercise auth and session endpoints", () => {
  const { emailState, storageState, layer } = makeWorkflowLayer();
  const request = { headers: { origin: "https://app.example.com" } };
  const trustedLayer = Layer.mergeAll(layer, TrustedOrigins([new URL("https://app.example.com")]));
  return Effect.gen(function* () {
    yield* handleSignUpEmail({
      request,
      payload: {
        email: "http-handler@example.com",
        password: "correct horse battery staple",
        name: "Test User",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      },
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* handleVerifyEmail({
      request,
      payload: { token: Redacted.value(verification.token) },
    });

    const signInCookies: Array<string> = [];
    let sessionTokenText: string | undefined;
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        const result = yield* handleSignInEmail({
          request,
          payload: {
            email: "http-handler@example.com",
            password: "correct horse battery staple",
          },
        });
        sessionTokenText = Redacted.value(result.sessionToken);
        return HttpServerResponse.jsonUnsafe(result);
      }),
      (_request, response) =>
        Effect.sync(() => {
          signInCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
      ),
    );
    if (!sessionTokenText) return yield* missingFixture("missing handler session token");
    const sessionTokenTextValue = sessionTokenText;

    const unchangedCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        yield* handleCurrentSession({ query: { sessionToken: sessionTokenTextValue } });
        return HttpServerResponse.jsonUnsafe(null);
      }),
      (_request, response) =>
        Effect.sync(() => {
          unchangedCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.get("https://auth.example.com")),
      ),
    );

    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }
    const rotatedCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        yield* handleCurrentSession({ query: { sessionToken: sessionTokenTextValue } });
        return HttpServerResponse.jsonUnsafe(null);
      }),
      (_request, response) =>
        Effect.sync(() => {
          rotatedCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.get("https://auth.example.com")),
      ),
    );
    const rotatedTokenText = rotatedCookies[0]?.match(/^effect_auth_session=([^;]+)/u)?.[1];
    if (!rotatedTokenText) return yield* missingFixture("missing rotated handler cookie");

    const signOutCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        yield* handleSignOut({ request, payload: { sessionToken: rotatedTokenText } });
        return HttpServerResponse.jsonUnsafe(null);
      }),
      (_request, response) =>
        Effect.sync(() => {
          signOutCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
      ),
    );

    assert.strictEqual(signInCookies.length, 1);
    assert.strictEqual(unchangedCookies.length, 0);
    assert.strictEqual(rotatedCookies.length, 1);
    assert.equal(rotatedCookies[0]?.includes("effect_auth_session="), true);
    assert.equal(rotatedCookies[0]?.includes(sessionTokenTextValue), false);
    assert.strictEqual(signOutCookies.length, 1);
    assert.equal(signOutCookies[0]?.includes("Max-Age=0"), true);
  }).pipe(Effect.provide(trustedLayer));
});

it.effect("http handler functions exercise password reset and change endpoints", () => {
  const { emailState, layer } = makeWorkflowLayer();
  const request = { headers: { origin: "https://app.example.com" } };
  const trustedLayer = Layer.mergeAll(layer, TrustedOrigins([new URL("https://app.example.com")]));
  return Effect.gen(function* () {
    const emailPassword = yield* Auth;
    const sessions = yield* SessionWorkflows;
    yield* emailPassword.signUp({
      email: "http-handler-password@example.com",
      password: "correct horse battery staple",
      name: "Test User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* handleVerifyEmail({
      request,
      payload: { token: Redacted.value(verification.token) },
    });

    yield* handleRequestPasswordReset({
      request,
      payload: {
        email: "http-handler-password@example.com",
        resetCallbackUrl: new URL("https://app.example.com/reset"),
      },
    });
    const reset = emailState.sent[1];
    if (!reset) return yield* missingFixture("missing reset email");
    yield* handleCompletePasswordReset({
      request,
      payload: {
        token: Redacted.value(reset.token),
        password: "new correct horse battery",
      },
    });

    const signedIn = yield* emailPassword.signIn({
      email: "http-handler-password@example.com",
      password: "new correct horse battery",
    });
    const changeCookies: Array<string> = [];
    let changedToken: SessionToken | undefined;
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        const result = yield* handleChangePassword({
          request,
          payload: {
            sessionToken: Redacted.value(signedIn.sessionToken),
            currentPassword: "new correct horse battery",
            newPassword: "changed correct horse battery",
          },
        });
        changedToken = result.currentSessionToken;
        return HttpServerResponse.jsonUnsafe(result);
      }),
      (_request, response) =>
        Effect.sync(() => {
          changeCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
      ),
    );
    if (!changedToken) return yield* missingFixture("missing changed handler session token");
    const current = yield* sessions.currentSession({ sessionToken: changedToken });

    assert.strictEqual(current.session.userId, signedIn.user.id);
    assert.strictEqual(changeCookies.length, 1);
    assert.equal(changeCookies[0]?.includes("effect_auth_session="), true);
    assert.equal(changeCookies[0]?.includes(Redacted.value(signedIn.sessionToken)), false);
  }).pipe(Effect.provide(trustedLayer));
});

it.effect("http handler deleteUser clears cookies and deletes auth records", () => {
  const { emailState, storageState, layer } = makeWorkflowLayer();
  const request = { headers: { origin: "https://app.example.com" } };
  const trustedLayer = Layer.mergeAll(layer, TrustedOrigins([new URL("https://app.example.com")]));
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "http-handler-delete@example.com",
      password: "correct horse battery staple",
      name: "Delete User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });
    const signedIn = yield* auth.signIn({
      email: "http-handler-delete@example.com",
      password: "correct horse battery staple",
    });

    const deleteCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        const result = yield* handleDeleteUser({
          request,
          payload: {
            sessionToken: Redacted.value(signedIn.sessionToken),
            password: "correct horse battery staple",
          },
        });
        return HttpServerResponse.jsonUnsafe(result);
      }),
      (_request, response) =>
        Effect.sync(() => {
          deleteCookies.push(...Cookies.toSetCookieHeaders(response.cookies));
        }),
    ).pipe(
      Effect.provideService(
        HttpServerRequest.HttpServerRequest,
        HttpServerRequest.fromClientRequest(HttpClientRequest.post("https://auth.example.com")),
      ),
    );

    assert.strictEqual(storageState.users.has(signedIn.user.id), false);
    assert.strictEqual(storageState.accountsByEmail.has("http-handler-delete@example.com"), false);
    assert.strictEqual(deleteCookies.length, 1);
    assert.equal(deleteCookies[0]?.includes("effect_auth_session="), true);
    assert.equal(deleteCookies[0]?.includes("Max-Age=0"), true);
  }).pipe(Effect.provide(trustedLayer));
});

it.effect("trusted origin policy rejects untrusted state-changing requests", () =>
  Effect.gen(function* () {
    yield* checkTrustedOrigin(new URL("https://app.example.com"));
    yield* checkTrustedRequestOrigin({ headers: {} });
    yield* checkTrustedRequestOrigin({ headers: { origin: "https://app.example.com" } });
    const rejected = yield* Effect.exit(checkTrustedOrigin(new URL("https://evil.example.com")));
    const rejectedRequest = yield* Effect.exit(
      checkTrustedRequestOrigin({ headers: { origin: "https://evil.example.com" } }),
    );

    assert.strictEqual(rejected._tag, "Failure");
    assert.strictEqual(rejectedRequest._tag, "Failure");
  }).pipe(Effect.provide(TrustedOrigins([new URL("https://app.example.com")]))),
);

it.effect("AuthHttp.mount updates users and lists scoped secret-free accounts", () => {
  const { emailState, storageState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "mounted-identity@example.com",
      password: "correct horse battery staple",
      name: "Mounted User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });
    yield* auth.signUp({
      email: "mounted-other-identity@example.com",
      password: "correct horse battery staple",
      name: "Other User",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });

    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfig.layer({
            trustedOrigins: [new URL("https://app.example.com")],
            secureCookies: true,
          }),
        ),
      ),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const signIn = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/sign-in/email", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            origin: "https://app.example.com",
          },
          body: jsonString({
            email: "mounted-identity@example.com",
            password: "correct horse battery staple",
          }),
        }),
        Context.empty(),
      ),
    );
    const sessionCookie = signIn.headers.get("set-cookie");
    if (!sessionCookie) return yield* missingFixture("missing sign-in cookie");
    const signedInTokenText = sessionCookie.match(/^effect_auth_session=([^;]+)/u)?.[1];
    if (!signedInTokenText) return yield* missingFixture("missing sign-in cookie token");
    const untrusted = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/update-user", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: sessionCookie,
            origin: "https://evil.example.com",
          },
          body: jsonString({ name: "Evil Ada" }),
        }),
        Context.empty(),
      ),
    );
    const empty = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/update-user", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: sessionCookie,
            origin: "https://app.example.com",
          },
          body: jsonString({}),
        }),
        Context.empty(),
      ),
    );
    const emailChange = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/update-user", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: sessionCookie,
            origin: "https://app.example.com",
          },
          body: jsonString({ email: "new@example.com" }),
        }),
        Context.empty(),
      ),
    );
    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }
    const updated = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/update-user", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            cookie: sessionCookie,
            origin: "https://app.example.com",
          },
          body: jsonString({ name: "Mounted Ada", image: null }),
        }),
        Context.empty(),
      ),
    );
    const updateCookie = updated.headers.get("set-cookie");
    if (!updateCookie) return yield* missingFixture("missing update rotation cookie");
    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }
    const listed = yield* Effect.promise(() =>
      web.handler(
        new Request("https://auth.example.com/api/auth/accounts", {
          headers: { cookie: updateCookie },
        }),
        Context.empty(),
      ),
    );
    const accountsCookie = listed.headers.get("set-cookie");
    if (!accountsCookie) return yield* missingFixture("missing accounts rotation cookie");
    const updatedBody = yield* Effect.promise(() => updated.text());
    const listedBody = yield* Effect.promise(() => listed.text());
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(untrusted.status, 401);
    assert.strictEqual(empty.status, 400);
    assert.strictEqual(emailChange.status, 400);
    assert.strictEqual(updated.status, 200, updatedBody);
    assert.equal(updateCookie.includes("effect_auth_session="), true);
    assert.equal(updateCookie.includes(signedInTokenText), false);
    assert.strictEqual(listed.status, 200, listedBody);
    assert.equal(accountsCookie.includes("effect_auth_session="), true);
    assert.equal(accountsCookie.includes(signedInTokenText), false);
    assert.equal(updatedBody.includes("Mounted Ada"), true);
    assert.equal(listedBody.includes("credential"), true);
    assert.equal(listedBody.includes("usr_"), true);
    assert.equal(listedBody.includes("mounted-other-identity@example.com"), false);
    assert.equal(listedBody.includes("passwordHash"), false);
    assert.equal(listedBody.includes("accessToken"), false);
    assert.equal(listedBody.includes("refreshToken"), false);
    assert.equal(listedBody.includes("idToken"), false);
  }).pipe(Effect.provide(authLayer));
});

it.effect("auth api endpoint inventory matches the ICD paths", () =>
  Effect.sync(() => {
    assert.deepStrictEqual(AuthApiEndpoints, [
      ["POST", "/auth/sign-up/email"],
      ["POST", "/auth/verify-email"],
      ["POST", "/auth/resend-verification"],
      ["POST", "/auth/sign-in/email"],
      ["GET", "/auth/session"],
      ["POST", "/auth/sign-out"],
      ["POST", "/auth/password-reset/request"],
      ["POST", "/auth/password-reset/complete"],
      ["POST", "/auth/password/change"],
      ["POST", "/auth/delete-user"],
      ["GET", "/auth/sessions"],
      ["POST", "/auth/update-user"],
      ["GET", "/auth/accounts"],
      ["POST", "/auth/sessions/revoke"],
      ["POST", "/auth/sessions/revoke-others"],
      ["POST", "/auth/sessions/revoke-all"],
    ]);
  }),
);
