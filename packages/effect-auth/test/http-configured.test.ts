import { assert, it } from "@effect/vitest";
import { Schema } from "effect";
import * as HttpServer from "effect/unstable/http/HttpServer";
import { OpenApi } from "effect/unstable/httpapi";
import { OAuth, OAuthCallbackError, OAuthProviderId, OAuthStateHandle } from "../src/oauth/index";
import {
  Auth,
  AuthHttp,
  AuthHttpCredentialMaintenance,
  AuthHttpCredentialRenderer,
  AuthHttpCredentialResolver,
  AuthHttpUrlPolicy,
  Context,
  Effect,
  HttpRouter,
  HttpServerResponse,
  Layer,
  Redacted,
  jsonString,
  makeWorkflowLayer,
  missingFixture,
} from "./support";

const runtimeInput = {
  baseUrl: new URL("https://auth.example.com"),
  trustedOrigins: [new URL("https://app.example.com")],
  cookies: { secure: true },
};

const NoopOAuthLayer = Layer.succeed(OAuth)({
  startSignIn: () => Effect.never,
  startLink: () => Effect.never,
  completeCallback: () => Effect.never,
});

const configuredJson = (body: unknown, cookie?: string) => ({
  method: "POST",
  headers: {
    "content-type": "application/json",
    origin: "https://app.example.com",
    ...(cookie === undefined ? {} : { cookie }),
  },
  body: jsonString(body),
});

const OpenApiResponseWithContent = Schema.Struct({ content: Schema.Unknown });
const OpenApiRedirectResponseWithLocation = Schema.Struct({
  headers: Schema.Struct({ Location: Schema.Unknown }),
});
const hasContent = Schema.is(OpenApiResponseWithContent);
const hasLocationHeader = Schema.is(OpenApiRedirectResponseWithLocation);

const decodeOAuthProviderIdSync = Schema.decodeUnknownSync(OAuthProviderId);
const decodeOAuthStateHandleSync = Schema.decodeUnknownSync(OAuthStateHandle);
const decodeSignInFlowSync = Schema.decodeUnknownSync(Schema.Literal("SignIn"));

it.effect(
  "AuthHttp.configure serves cookie-first routes with stable metadata and schema errors",
  () => {
    const { emailState, layer: authLayer } = makeWorkflowLayer();
    const configured = AuthHttp.configure({ basePath: "/api/auth" });
    return Effect.gen(function* () {
      assert.strictEqual(configured.sessionCookieName, "effect_auth_session");
      assert.strictEqual(configured.tokenResponseHeader, "set-auth-token");
      assert.deepStrictEqual(Object.keys(configured.api.groups).sort(), [
        "authOptional",
        "authProtectedIdentity",
        "authProtectedSession",
        "authPublic",
      ]);

      const appLayer = configured.routes.pipe(
        Layer.provideMerge(
          configured
            .layer(runtimeInput)
            .pipe(Layer.provideMerge(authLayer), Layer.provideMerge(NoopOAuthLayer)),
        ),
        Layer.provideMerge(HttpServer.layerServices),
      );
      const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
      const call = (path: string, init?: RequestInit) =>
        Effect.promise(() =>
          web.handler(new Request(`https://auth.example.com${path}`, init), Context.empty()),
        );

      const invalid = yield* call(
        "/api/auth/sign-in/email",
        configuredJson({ email: "configured-cookie@example.com" }),
      );
      const invalidBody = yield* Effect.promise(() => invalid.text());

      const signedUp = yield* call(
        "/api/auth/sign-up/email",
        configuredJson({
          email: "configured-cookie@example.com",
          password: "correct horse battery staple",
          name: "Configured User",
          verificationCallbackUrl: "https://app.example.com/verify",
        }),
      );
      const verification = emailState.sent[0];
      if (!verification) return yield* missingFixture("missing verification email");
      const verified = yield* call(
        "/api/auth/verify-email",
        configuredJson({ token: Redacted.value(verification.token) }),
      );
      const signedIn = yield* call(
        "/api/auth/sign-in/email",
        configuredJson({
          email: "configured-cookie@example.com",
          password: "correct horse battery staple",
        }),
      );
      const cookie = signedIn.headers.get("set-cookie");
      if (!cookie) return yield* missingFixture("missing configured session cookie");
      const current = yield* call("/api/auth/session", {
        method: "GET",
        headers: { cookie },
      });
      const currentBody = yield* Effect.promise(() => current.text());
      yield* Effect.promise(() => web.dispose());

      assert.strictEqual(invalid.status, 400, invalidBody);
      assert.equal(invalidBody.includes("AuthHttpBadRequest"), true);
      assert.equal(invalidBody.includes("Invalid request"), true);
      assert.strictEqual(signedUp.status, 200);
      assert.strictEqual(verified.status, 200);
      assert.strictEqual(signedIn.status, 200);
      assert.equal(cookie.includes("effect_auth_session="), true);
      assert.equal(cookie.includes("HttpOnly"), true);
      assert.equal(cookie.includes("Secure"), true);
      assert.equal(cookie.includes("SameSite=Lax"), true);
      assert.equal(currentBody.includes("configured-cookie@example.com"), true);
      assert.equal(currentBody.includes("tokenHash"), false);
      assert.equal(currentBody.includes("sessionToken"), false);
    }).pipe(Effect.provide(authLayer));
  },
);

it.effect(
  "AuthHttp.configure exposes configured resolver, renderer, and URL policy services",
  () => {
    const { emailState, layer: authLayer } = makeWorkflowLayer();
    const configured = AuthHttp.configure({ basePath: "/service-auth", cookieAndBearer: true });
    return Effect.gen(function* () {
      const auth = yield* Auth;
      yield* auth.signUp({
        email: "configured-services@example.com",
        password: "correct horse battery staple",
        name: "Configured Services",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      });
      const verification = emailState.sent[0];
      if (!verification) return yield* missingFixture("missing services verification email");
      yield* auth.verifyEmail({ token: verification.token });
      const signedIn = yield* auth.signIn({
        email: "configured-services@example.com",
        password: "correct horse battery staple",
      });

      const resolver = yield* AuthHttpCredentialResolver;
      const resolved = yield* resolver.resolveRaw({
        source: "Bearer",
        value: Redacted.value(signedIn.sessionToken),
      });
      const renderer = yield* AuthHttpCredentialRenderer;
      const bearerResponse = renderer.apply(
        HttpServerResponse.empty(),
        AuthHttpCredentialMaintenance.IssueBearer({ token: signedIn.sessionToken }),
      );
      const policy = yield* AuthHttpUrlPolicy;
      const callbackUrl = yield* policy.resolveCallbackUrl("/after-auth");
      const untrustedCallback = yield* Effect.exit(
        policy.validateCallbackUrl("https://evil.example.com/after-auth"),
      );

      assert.strictEqual(resolved.source, "Bearer");
      assert.strictEqual(resolved.user.email, "configured-services@example.com");
      assert.strictEqual(
        bearerResponse.headers[configured.tokenResponseHeader],
        Redacted.value(signedIn.sessionToken),
      );
      assert.equal(
        bearerResponse.headers["access-control-expose-headers"]?.includes(
          configured.tokenResponseHeader,
        ),
        true,
      );
      assert.strictEqual(callbackUrl.href, "https://auth.example.com/after-auth");
      assert.strictEqual(untrustedCallback._tag, "Failure");
    }).pipe(Effect.provide(configured.layer(runtimeInput).pipe(Layer.provideMerge(authLayer))));
  },
);

it.effect("AuthHttp.configure protects configured routes with credential and origin policy", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  const configured = AuthHttp.configure({ basePath: "/protected-auth" });
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "configured-protected@example.com",
      password: "correct horse battery staple",
      name: "Configured Protected",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing protected verification email");
    yield* auth.verifyEmail({ token: verification.token });
    const appLayer = configured.routes.pipe(
      Layer.provideMerge(
        configured
          .layer(runtimeInput)
          .pipe(Layer.provideMerge(authLayer), Layer.provideMerge(NoopOAuthLayer)),
      ),
      Layer.provideMerge(HttpServer.layerServices),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const call = (path: string, init?: RequestInit) =>
      Effect.promise(() =>
        web.handler(new Request(`https://auth.example.com${path}`, init), Context.empty()),
      );

    const signedIn = yield* call(
      "/protected-auth/sign-in/email",
      configuredJson({
        email: "configured-protected@example.com",
        password: "correct horse battery staple",
      }),
    );
    const cookie = signedIn.headers.get("set-cookie");
    if (!cookie) return yield* missingFixture("missing protected sign-in cookie");
    const missing = yield* call("/protected-auth/sessions", { method: "GET" });
    const listed = yield* call("/protected-auth/sessions", { method: "GET", headers: { cookie } });
    const untrustedSignOut = yield* call("/protected-auth/sign-out", {
      method: "POST",
      headers: { cookie, origin: "https://evil.example.com" },
    });
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(missing.status, 401);
    assert.strictEqual(listed.status, 200);
    assert.strictEqual(untrustedSignOut.status, 403);
  }).pipe(Effect.provide(authLayer));
});

it.effect(
  "AuthHttp.configure keeps bearer credentials opt-in and refreshes bearer tokens by header",
  () => {
    const { emailState, storageState, layer: authLayer } = makeWorkflowLayer();
    return Effect.gen(function* () {
      const auth = yield* Auth;
      yield* auth.signUp({
        email: "configured-bearer@example.com",
        password: "correct horse battery staple",
        name: "Bearer User",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      });
      const verification = emailState.sent[0];
      if (!verification) return yield* missingFixture("missing bearer verification email");
      yield* auth.verifyEmail({ token: verification.token });
      const cookieOnly = AuthHttp.configure({ basePath: "/cookie-only" });
      const cookieOnlyLayer = cookieOnly.routes.pipe(
        Layer.provideMerge(
          cookieOnly
            .layer(runtimeInput)
            .pipe(Layer.provideMerge(authLayer), Layer.provideMerge(NoopOAuthLayer)),
        ),
        Layer.provideMerge(HttpServer.layerServices),
      );
      const cookieOnlyWeb = HttpRouter.toWebHandler(cookieOnlyLayer, { disableLogger: true });
      const cookieOnlySignIn = yield* Effect.promise(() =>
        cookieOnlyWeb.handler(
          new Request(
            "https://auth.example.com/cookie-only/sign-in/email",
            configuredJson({
              email: "configured-bearer@example.com",
              password: "correct horse battery staple",
            }),
          ),
          Context.empty(),
        ),
      );
      const cookie = cookieOnlySignIn.headers.get("set-cookie");
      if (!cookie) return yield* missingFixture("missing cookie-only sign-in cookie");
      const tokenMatch = /^effect_auth_session=([^;]+)/u.exec(cookie);
      const token = tokenMatch?.[1];
      if (token === undefined) return yield* missingFixture("missing cookie token value");
      const cookieOnlyProtected = yield* Effect.promise(() =>
        cookieOnlyWeb.handler(
          new Request("https://auth.example.com/cookie-only/sessions", {
            method: "GET",
            headers: { authorization: `Bearer ${token}` },
          }),
          Context.empty(),
        ),
      );
      yield* Effect.promise(() => cookieOnlyWeb.dispose());

      for (const [key, session] of storageState.sessionsByHash) {
        storageState.sessionsByHash.set(key, {
          ...session,
          updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
        });
      }

      const cookieAndBearer = AuthHttp.configure({
        basePath: "/cookie-and-bearer",
        cookieAndBearer: true,
      });
      const bearerLayer = cookieAndBearer.routes.pipe(
        Layer.provideMerge(
          cookieAndBearer
            .layer(runtimeInput)
            .pipe(Layer.provideMerge(authLayer), Layer.provideMerge(NoopOAuthLayer)),
        ),
        Layer.provideMerge(HttpServer.layerServices),
      );
      const bearerWeb = HttpRouter.toWebHandler(bearerLayer, { disableLogger: true });
      const bearerSessions = yield* Effect.promise(() =>
        bearerWeb.handler(
          new Request("https://auth.example.com/cookie-and-bearer/sessions", {
            method: "GET",
            headers: { authorization: `Bearer ${token}` },
          }),
          Context.empty(),
        ),
      );
      const bearerBody = yield* Effect.promise(() => bearerSessions.clone().text());
      const rotatedToken = bearerSessions.headers.get(cookieAndBearer.tokenResponseHeader);
      if (!rotatedToken)
        return yield* missingFixture(
          `missing rotated bearer header status=${bearerSessions.status} expose=${bearerSessions.headers.get("access-control-expose-headers")} body=${bearerBody}`,
        );
      const lowercaseBearerSession = yield* Effect.promise(() =>
        bearerWeb.handler(
          new Request("https://auth.example.com/cookie-and-bearer/session", {
            method: "GET",
            headers: { authorization: `bearer ${rotatedToken}` },
          }),
          Context.empty(),
        ),
      );
      const invalidBearerOnly = yield* Effect.promise(() =>
        bearerWeb.handler(
          new Request("https://auth.example.com/cookie-and-bearer/session", {
            method: "GET",
            headers: { authorization: "Bearer not-a-session-token" },
          }),
          Context.empty(),
        ),
      );
      const freshSignIn = yield* Effect.promise(() =>
        bearerWeb.handler(
          new Request(
            "https://auth.example.com/cookie-and-bearer/sign-in/email",
            configuredJson({
              email: "configured-bearer@example.com",
              password: "correct horse battery staple",
            }),
          ),
          Context.empty(),
        ),
      );
      const freshCookie = freshSignIn.headers.get("set-cookie");
      if (!freshCookie) return yield* missingFixture("missing fresh bearer fallback cookie");
      const invalidBearerWithCookie = yield* Effect.promise(() =>
        bearerWeb.handler(
          new Request("https://auth.example.com/cookie-and-bearer/session", {
            method: "GET",
            headers: { authorization: "Bearer not-a-session-token", cookie: freshCookie },
          }),
          Context.empty(),
        ),
      );
      const signedOut = yield* Effect.promise(() =>
        bearerWeb.handler(
          new Request("https://auth.example.com/cookie-and-bearer/sign-out", {
            method: "POST",
            headers: { authorization: `Bearer ${rotatedToken}` },
          }),
          Context.empty(),
        ),
      );
      yield* Effect.promise(() => bearerWeb.dispose());

      assert.strictEqual(cookieOnlyProtected.status, 401);
      assert.strictEqual(bearerSessions.status, 200);
      assert.notStrictEqual(rotatedToken, token);
      assert.equal(
        bearerSessions.headers.get("access-control-expose-headers")?.includes("set-auth-token"),
        true,
      );
      assert.strictEqual(lowercaseBearerSession.status, 200);
      assert.strictEqual(invalidBearerOnly.status, 401);
      assert.strictEqual(invalidBearerWithCookie.status, 200);
      assert.strictEqual(signedOut.status, 200);
    }).pipe(Effect.provide(authLayer));
  },
);

it.effect("AuthHttp.configure includes OAuth in the configured API only when requested", () =>
  Effect.sync(() => {
    const withoutOAuth = AuthHttp.configure({ basePath: "/auth" });
    const withOAuth = AuthHttp.configure({ basePath: "/auth", oauth: true });

    assert.deepStrictEqual(Object.keys(withoutOAuth.api.groups).sort(), [
      "authOptional",
      "authProtectedIdentity",
      "authProtectedSession",
      "authPublic",
    ]);
    assert.deepStrictEqual(Object.keys(withOAuth.api.groups).sort(), [
      "authOAuthProtected",
      "authOAuthPublic",
      "authOptional",
      "authProtectedIdentity",
      "authProtectedSession",
      "authPublic",
    ]);
    const oauthPublic = withOAuth.api.groups.authOAuthPublic;
    const oauthProtected = withOAuth.api.groups.authOAuthProtected;
    if (oauthPublic === undefined) {
      assert.fail("missing OAuth public group");
    }
    if (oauthProtected === undefined) {
      assert.fail("missing OAuth protected group");
    }
    assert.deepStrictEqual(Object.keys(oauthPublic.endpoints).sort(), [
      "oauthCallbackGet",
      "oauthCallbackPost",
      "oauthSignInStart",
    ]);
    assert.deepStrictEqual(Object.keys(oauthProtected.endpoints), ["oauthLinkStart"]);
  }),
);

it.effect("AuthHttp.configure documents OAuth callbacks as redirects", () =>
  Effect.sync(() => {
    const configured = AuthHttp.configure({ basePath: "/api/auth", oauth: true });
    const spec = OpenApi.fromApi(configured.api);
    const callbackPath = spec.paths["/api/auth/oauth2/callback/{providerId}"];
    const getCallback = callbackPath?.get;
    const postCallback = callbackPath?.post;

    if (getCallback === undefined) assert.fail("missing GET OAuth callback operation");
    if (postCallback === undefined) assert.fail("missing POST OAuth callback operation");

    const getRedirect = getCallback.responses[302];
    const postRedirect = postCallback.responses[302];

    assert.equal(getCallback.responses[200], undefined);
    assert.equal(postCallback.responses[200], undefined);
    assert.equal(hasContent(getRedirect), false);
    assert.equal(hasContent(postRedirect), false);
    assert.equal(hasLocationHeader(getRedirect), true);
    assert.equal(hasLocationHeader(postRedirect), true);
    assert.equal(
      getCallback.parameters.some(
        (parameter) => parameter.in === "query" && parameter.name === "state",
      ),
      true,
    );
    assert.equal(
      postCallback.requestBody?.content?.["application/json"]?.schema !== undefined,
      true,
    );
    assert.equal(
      postCallback.requestBody?.content?.["application/x-www-form-urlencoded"]?.schema !==
        undefined,
      true,
    );
  }),
);

it.effect("AuthHttp.configure serves OAuth start and callback redirect routes", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  const configured = AuthHttp.configure({ basePath: "/api/auth", oauth: true });
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "configured-oauth@example.com",
      password: "correct horse battery staple",
      name: "Configured OAuth",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing OAuth verification email");
    yield* auth.verifyEmail({ token: verification.token });
    const signedIn = yield* auth.signIn({
      email: "configured-oauth@example.com",
      password: "correct horse battery staple",
    });
    const starts: Array<{ readonly redirectUri: string; readonly providerId: unknown }> = [];
    const callbacks: Array<{
      readonly method: string;
      readonly state: unknown;
      readonly code: unknown;
    }> = [];
    const signInFlow = decodeSignInFlowSync("SignIn");
    const OAuthTestLayer = Layer.succeed(OAuth)({
      startSignIn: (input) =>
        Effect.sync(() => {
          const providerId = decodeOAuthProviderIdSync(input.providerId);
          starts.push({ providerId: input.providerId, redirectUri: input.redirectUri.href });
          return {
            providerId,
            authorizationUrl: new URL("https://provider.example.com/authorize"),
            state: decodeOAuthStateHandleSync("a".repeat(43)),
            scopes: input.scopes ?? [],
            flow: signInFlow,
          };
        }),
      startLink: () => Effect.never,
      completeCallback: (input) =>
        input.code === "bad"
          ? Effect.fail(new OAuthCallbackError({ reason: "InvalidState" }))
          : Effect.sync(() => {
              const providerId = decodeOAuthProviderIdSync(input.providerId);
              callbacks.push({
                method: input.callbackMethod,
                state: input.state,
                code: input.code,
              });
              return {
                flow: signInFlow,
                user: signedIn.user,
                account: {
                  id: "oauth-account",
                  providerId,
                  accountId: "provider-account",
                  userId: signedIn.user.id,
                  scopes: [],
                  providerTokens: {},
                  createdAt: signedIn.session.createdAt,
                  updatedAt: signedIn.session.updatedAt,
                },
                session: signedIn.session,
                sessionToken: signedIn.sessionToken,
                isNewUser: false,
              };
            }),
    });
    const appLayer = configured.routes.pipe(
      Layer.provideMerge(
        configured.layer({
          ...runtimeInput,
          oauth: {
            signInSuccessPath: "/dashboard",
            linkSuccessPath: "/settings/accounts",
            errorPath: "/auth/error",
          },
        }),
      ),
      Layer.provideMerge(authLayer),
      Layer.provideMerge(OAuthTestLayer),
      Layer.provideMerge(HttpServer.layerServices),
    );
    const web = HttpRouter.toWebHandler(appLayer, { disableLogger: true });
    const call = (path: string, init?: RequestInit) =>
      Effect.promise(() =>
        web.handler(new Request(`https://auth.example.com${path}`, init), Context.empty()),
      );

    const started = yield* call(
      "/api/auth/sign-in/oauth2",
      configuredJson({ providerId: "github", scopes: ["profile"] }),
    );
    const startedBody = yield* Effect.promise(() => started.text());
    const callback = yield* call("/api/auth/oauth2/callback/github?state=state-1&code=code-1");
    const failedPostCallback = yield* call("/api/auth/oauth2/callback/github", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "state=state-2&code=bad",
    });
    yield* Effect.promise(() => web.dispose());

    assert.strictEqual(started.status, 200, startedBody);
    assert.equal(startedBody.includes("https://provider.example.com/authorize"), true);
    assert.deepStrictEqual(starts, [
      {
        providerId: "github",
        redirectUri: "https://auth.example.com/api/auth/oauth2/callback/github",
      },
    ]);
    assert.strictEqual(callback.status, 302);
    assert.strictEqual(callback.headers.get("location"), "/dashboard");
    assert.equal(
      callback.headers.get("set-cookie")?.includes(`${configured.sessionCookieName}=`),
      true,
    );
    assert.deepStrictEqual(callbacks, [{ method: "GET", state: "state-1", code: "code-1" }]);
    assert.strictEqual(failedPostCallback.status, 302);
    assert.strictEqual(failedPostCallback.headers.get("location"), "/auth/error");
  }).pipe(Effect.provide(authLayer));
});
