import { assert, it } from "@effect/vitest";
import { Schema } from "effect";
import {
  Auth,
  AuthApiEndpoints,
  AuthHttp,
  AuthHttpAdapter,
  AuthHttpConfig,
  AuthHttpErrorMapper,
  AuthHttpToken,
  AuthSession,
  AuthToken,
  Context,
  Cookies,
  CurrentAuthSession,
  Effect,
  EmailPasswordWorkflows,
  HttpClientRequest,
  HttpEffect,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
  Layer,
  Option,
  Redacted,
  SessionCookie,
  SessionWorkflows,
  TrustedOrigins,
  checkTrustedOrigin,
  checkTrustedRequestOrigin,
  handleChangePassword,
  handleCompletePasswordReset,
  handleCurrentSession,
  handleRequestPasswordReset,
  handleSignInEmail,
  handleSignOut,
  handleSignUpEmail,
  handleVerifyEmail,
  invalidCredentials,
  jsonString,
  jsonWithCookieInstruction,
  makeWorkflowLayer,
  mapPublicHttpError,
  missingFixture,
  rateLimited,
  unauthorized,
  type SessionToken,
} from "./support";

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

it.effect("AuthHttp.mount adds a token-free sign-in route under the configured base path", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "mounted-sign-in@example.com",
      password: "correct horse battery staple",
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

    assert.strictEqual(response.status, 200);
    assert.equal(response.headers.get("set-cookie")?.includes("effect_auth_session="), true);
    assert.equal(response.headers.get("set-cookie")?.includes("HttpOnly"), true);
    assert.equal(response.headers.get("set-cookie")?.includes("SameSite=Lax"), true);
    assert.equal(bodyText.includes("sessionToken"), false);
    assert.equal(bodyText.includes("tokenHash"), false);
  }).pipe(Effect.provide(authLayer));
});

it.effect("AuthHttp.mount rejects cookie state changes without trusted origin or referer", () => {
  const { emailState, layer: authLayer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "mounted-origin@example.com",
      password: "correct horse battery staple",
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
        verificationCallbackUrl: "https://app.example.com/verify",
      }),
    );
    assert.strictEqual(signUp.status, 200);

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
    const revokedOthers = yield* call(
      "/api/auth/sessions/revoke-others",
      json({}, rotatedCookie),
    );
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
    const emailPassword = yield* EmailPasswordWorkflows;
    const adapter = yield* AuthHttpAdapter;
    yield* emailPassword.signUp({
      email: "http-cookie@example.com",
      password: "correct horse battery staple",
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
    const emailPassword = yield* EmailPasswordWorkflows;
    const adapter = yield* AuthHttpAdapter;
    yield* emailPassword.signUp({
      email: "http-sign-in-out@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });

    const signInCookies: Array<string> = [];
    let signedInToken: SessionToken | undefined;
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        const result = yield* adapter.signInEmail({
          email: "http-sign-in-out@example.com",
          password: "correct horse battery staple",
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
    const emailPassword = yield* EmailPasswordWorkflows;
    const adapter = yield* AuthHttpAdapter;
    yield* emailPassword.signUp({
      email: "configured-cookie@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: "https://app.example.com/verify",
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });

    const signInCookies: Array<string> = [];
    yield* HttpEffect.toHandled(
      Effect.gen(function* () {
        yield* adapter.signInEmail({
          email: "configured-cookie@example.com",
          password: "correct horse battery staple",
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
    const emailPassword = yield* EmailPasswordWorkflows;
    const adapter = yield* AuthHttpAdapter;
    const sessions = yield* SessionWorkflows;

    yield* emailPassword.signUp({
      email: "http-adapter@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* adapter.verifyEmail({ token: verification.token });

    yield* adapter.requestPasswordReset({
      email: "http-adapter@example.com",
      resetCallbackUrl: new URL("https://app.example.com/reset"),
    });
    const reset = emailState.sent[1];
    if (!reset) return yield* missingFixture("missing reset email");
    assert.strictEqual(reset.kind, "PasswordReset");

    yield* adapter.completePasswordReset({
      token: reset.token,
      password: "new correct horse battery",
    });
    const signedIn = yield* emailPassword.signIn({
      email: "http-adapter@example.com",
      password: "new correct horse battery",
    });
    const changed = yield* adapter
      .changePassword({
        sessionToken: signedIn.sessionToken,
        currentPassword: "new correct horse battery",
        newPassword: "changed correct horse battery",
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
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    yield* emailPassword.signUp({
      email: "http-handler-password@example.com",
      password: "correct horse battery staple",
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
      ["GET", "/auth/sessions"],
      ["POST", "/auth/sessions/revoke"],
      ["POST", "/auth/sessions/revoke-others"],
      ["POST", "/auth/sessions/revoke-all"],
    ]);
  }),
);
