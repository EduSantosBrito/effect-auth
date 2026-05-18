import { assert, it } from "@effect/vitest";
import * as HttpServer from "effect/unstable/http/HttpServer";
import { OAuth } from "../src/oauth/index";
import {
  Auth,
  AuthHttp,
  Context,
  Effect,
  HttpRouter,
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
