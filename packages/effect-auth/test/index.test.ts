import { assert, it } from "@effect/vitest";
import * as Context from "effect/Context";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Predicate from "effect/Predicate";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Cookies from "effect/unstable/http/Cookies";
import * as HttpEffect from "effect/unstable/http/HttpEffect";
import * as HttpClientRequest from "effect/unstable/http/HttpClientRequest";
import * as HttpRouter from "effect/unstable/http/HttpRouter";
import * as HttpServerRequest from "effect/unstable/http/HttpServerRequest";
import * as HttpServerResponse from "effect/unstable/http/HttpServerResponse";
import { Auth, AuthLive } from "../src/auth";
import {
  AuthBoundary,
  AuthBoundaryLive,
  invalidToken,
  invalidCredentials,
  rateLimited,
  unauthorized,
  normalizeEmail,
  normalizePassword,
} from "../src/domain/index";
import {
  AuthHttp,
  AuthApiEndpoints,
  AuthHttpConfigLayer,
  AuthHttpToken,
  AuthSession,
  CurrentAuthSession,
  TrustedOrigins,
} from "../src/http/index";
import {
  AuthHttpAdapter,
  checkTrustedOrigin,
  checkTrustedRequestOrigin,
  clearSessionCookie,
  handleChangePassword,
  handleCompletePasswordReset,
  handleCurrentSession,
  handleRequestPasswordReset,
  handleSignInEmail,
  handleSignOut,
  handleSignUpEmail,
  handleVerifyEmail,
  jsonWithCookieInstruction,
  makeSessionCookie,
  mapPublicHttpError,
} from "../src/http/internal";
import { createEffectAuthClient } from "../src/index";
import {
  makeNativeScryptPasswordHasher,
  NativeScryptPasswordHasher,
  PasswordHash,
  PasswordHasher,
  PasswordPolicyFailure,
  type PasswordHasherShape,
  PasswordPolicy,
  SecureDefaultPasswordPolicy,
} from "../src/password/index";
import {
  deriveRateLimitKey,
  makeBoundedDevRateLimiter,
  PermissiveDevRateLimiter,
  RateLimiter,
  RateLimitExceeded,
} from "../src/rate-limit/index";
import {
  makeDevMemoryStorage,
  makeDevMemoryStorageState,
  DevMemoryAuthStorage,
} from "../src/storage/dev-memory";
import { AuthStorageFailure } from "../src/storage/index";
import { AuthToken, AuthTokenLive, type SessionToken } from "../src/token/index";
import {
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  SessionWorkflows,
  SessionWorkflowsLive,
} from "../src/workflows/index";
import {
  AuthEmail,
  AuthEmailFailure,
  makeMockAuthEmailState,
  MockAuthEmail,
} from "../src/email/mock";

class MissingFixture extends Schema.TaggedErrorClass<MissingFixture>()("MissingFixture", {
  message: Schema.String,
}) {}

const missingFixture = (message: string) => new MissingFixture({ message });
const decodePasswordHash = Schema.decodeUnknownEffect(PasswordHash);
const jsonString = Schema.encodeUnknownSync(Schema.UnknownFromJsonString);

const makeWorkflowLayer = () => {
  const storageState = makeDevMemoryStorageState();
  const emailState = makeMockAuthEmailState();
  const coreLayer = Layer.mergeAll(
    AuthBoundaryLive,
    SecureDefaultPasswordPolicy,
    NativeScryptPasswordHasher,
    AuthTokenLive,
    DevMemoryAuthStorage(storageState),
    MockAuthEmail(emailState),
    PermissiveDevRateLimiter,
  );
  const layer = Layer.mergeAll(
    EmailPasswordWorkflowsLive,
    SessionWorkflowsLive,
    PasswordRecoveryWorkflowsLive,
  ).pipe(Layer.provideMerge(coreLayer));
  return { storageState, emailState, layer };
};

it.effect("creates effect-auth client", () =>
  Effect.sync(() => {
    const baseUrl = new URL("https://auth.example.com");

    assert.deepStrictEqual(createEffectAuthClient({ baseUrl }), { baseUrl });
  }),
);

it.effect("normalizes email and NFKC password without exposing redacted text", () =>
  Effect.gen(function* () {
    const email = yield* normalizeEmail(" USER@example.COM ");
    const password = yield* normalizePassword("e\u0301");

    assert.strictEqual(email, "user@example.com");
    assert.strictEqual(Redacted.value(password), "é");
    assert.equal(String(password).includes("é"), false);
  }),
);

it.effect("rejects invalid email at the boundary", () =>
  Effect.gen(function* () {
    const exit = yield* Effect.exit(normalizeEmail("not-an-email"));

    assert.strictEqual(exit._tag, "Failure");
    if (Predicate.isTagged(exit, "Failure")) {
      assert.equal(String(exit.cause).includes("BoundaryParseError"), true);
    }
  }),
);

it.effect("secure default password policy rejects email-derived passwords", () =>
  Effect.gen(function* () {
    const email = yield* normalizeEmail("person@example.com");
    const password = yield* normalizePassword("person@example.com");
    const exit = yield* Effect.exit(
      Effect.gen(function* () {
        const policy = yield* PasswordPolicy;
        yield* policy.validate({ email, password });
      }).pipe(Effect.provide(SecureDefaultPasswordPolicy)),
    );

    assert.strictEqual(exit._tag, "Failure");
  }),
);

it.effect("native scrypt hasher verifies correct passwords and rejects wrong passwords", () =>
  Effect.gen(function* () {
    const password = yield* normalizePassword("correct horse battery staple");
    const wrong = yield* normalizePassword("correct horse battery stapler");
    const result = yield* Effect.gen(function* () {
      const hasher = yield* PasswordHasher;
      const hash = yield* hasher.hash(password);
      const secondHash = yield* hasher.hash(password);
      const malformedHash = yield* decodePasswordHash("not-a-phc-hash");
      return {
        hash,
        secondHash,
        correct: yield* hasher.verify({ password, hash }),
        wrong: yield* hasher.verify({ password: wrong, hash }),
        malformed: yield* Effect.exit(hasher.verify({ password, hash: malformedHash })),
      };
    }).pipe(Effect.provide(NativeScryptPasswordHasher));

    assert.equal(Redacted.value(result.hash).includes("$effect-auth-scrypt$"), true);
    assert.equal(Redacted.value(result.hash).includes("N=16384,r=16,p=1,dkLen=64"), true);
    assert.notStrictEqual(Redacted.value(result.hash), Redacted.value(result.secondHash));
    assert.strictEqual(result.correct, true);
    assert.strictEqual(result.wrong, false);
    assert.strictEqual(result.malformed._tag, "Failure");
    assert.equal(String(result.hash).includes(Redacted.value(result.hash)), false);
  }),
);

it.effect("native scrypt hasher fails explicitly on unsupported runtimes", () =>
  Effect.gen(function* () {
    const password = yield* normalizePassword("correct horse battery staple");
    const hasher = makeNativeScryptPasswordHasher({});
    const placeholder = yield* decodePasswordHash(
      "$effect-auth-scrypt$N=16384,r=16,p=1,dkLen=64$c2FsdA$ZGVyaXZlZA",
    );
    const hashFailure = yield* Effect.flip(hasher.hash(password));
    const verifyFailure = yield* Effect.flip(hasher.verify({ password, hash: placeholder }));

    assert.strictEqual(hashFailure.reason, "UnsupportedRuntime");
    assert.strictEqual(verifyFailure.reason, "UnsupportedRuntime");
  }),
);

it.effect("auth token service returns redacted 32-byte base64url tokens and SHA-256 hashes", () =>
  Effect.gen(function* () {
    const tokenService = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* AuthToken;
    }).pipe(Effect.provide(AuthTokenLive));
    const verification = yield* tokenService.makeVerificationToken();
    const secondVerification = yield* tokenService.makeVerificationToken();
    const session = yield* tokenService.makeSessionToken();
    const verificationHash = yield* tokenService.hashToken(verification.token);

    assert.strictEqual(Redacted.value(verification.token).length, 43);
    assert.strictEqual(Redacted.value(session.token).length, 43);
    assert.strictEqual(Redacted.value(verification.hash).length, 64);
    assert.strictEqual(Redacted.value(verificationHash), Redacted.value(verification.hash));
    assert.notStrictEqual(
      Redacted.value(verification.token),
      Redacted.value(secondVerification.token),
    );
    assert.equal(String(verification.token).includes(Redacted.value(verification.token)), false);
    assert.equal(String(verification.hash).includes(Redacted.value(verification.hash)), false);
  }),
);

it.effect("rate limiter derives bounded retry-after failures", () =>
  Effect.gen(function* () {
    const limiter = makeBoundedDevRateLimiter({ limit: 1, windowMillis: 10_000 });
    yield* limiter.check({ bucket: "SignIn", ip: "127.0.0.1" });
    const exit = yield* Effect.exit(limiter.check({ bucket: "SignIn", ip: "127.0.0.1" }));

    assert.strictEqual(exit._tag, "Failure");
  }),
);

it.effect("rate limiter key derivation covers default and custom bucket semantics", () =>
  Effect.gen(function* () {
    const email = yield* normalizeEmail("USER@example.com");
    assert.strictEqual(
      deriveRateLimitKey({ bucket: "SignIn", email, ip: "127.0.0.1" }),
      "SignIn|email:user@example.com|ip:127.0.0.1",
    );
    assert.strictEqual(
      deriveRateLimitKey({ bucket: "SignIn", email }),
      "SignIn|email:user@example.com",
    );
    assert.strictEqual(
      deriveRateLimitKey({ bucket: "SignUp", ip: "127.0.0.1" }),
      "SignUp|ip:127.0.0.1",
    );

    const defaultLimiter = makeBoundedDevRateLimiter();
    for (let index = 0; index < 100; index++) {
      yield* defaultLimiter.check({ bucket: "SignIn", email });
    }
    const defaultLimited = yield* Effect.exit(defaultLimiter.check({ bucket: "SignIn", email }));

    const customLimiter = makeBoundedDevRateLimiter({ limit: 2, windowMillis: 60_000 });
    yield* customLimiter.check({ bucket: "SignIn", email });
    yield* customLimiter.check({ bucket: "SignIn", email });
    const customLimited = yield* Effect.exit(customLimiter.check({ bucket: "SignIn", email }));
    const otherBucket = yield* Effect.exit(customLimiter.check({ bucket: "SignUp", email }));
    const otherIp = yield* Effect.exit(
      customLimiter.check({ bucket: "SignIn", email, ip: "127.0.0.1" }),
    );

    assert.strictEqual(defaultLimited._tag, "Failure");
    assert.strictEqual(customLimited._tag, "Failure");
    assert.strictEqual(otherBucket._tag, "Success");
    assert.strictEqual(otherIp._tag, "Success");
    const customFailure = yield* Effect.flip(customLimiter.check({ bucket: "SignIn", email }));
    assert.strictEqual(customFailure.bucket, "SignIn");
    assert.equal(customFailure.retryAfterMillis > 0, true);
  }),
);

it.effect("dev memory storage enforces unique email and one-time tokens", () =>
  Effect.gen(function* () {
    const boundary = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* AuthBoundary;
    }).pipe(Effect.provide(AuthBoundaryLive));
    const tokenService = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* AuthToken;
    }).pipe(Effect.provide(AuthTokenLive));
    const hasher = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* PasswordHasher;
    }).pipe(Effect.provide(NativeScryptPasswordHasher));
    const storage = makeDevMemoryStorage();
    const email = yield* boundary.parseEmail("user@example.com");
    const password = yield* boundary.parsePassword("correct horse battery staple");
    const passwordHash = yield* hasher.hash(password);
    const user = yield* storage.createUserWithEmailPasswordCredential({
      email,
      passwordHash,
      now: 1,
    });
    const duplicate = yield* Effect.exit(
      storage.createUserWithEmailPasswordCredential({ email, passwordHash, now: 1 }),
    );
    const pair = yield* tokenService.makeVerificationToken();

    yield* storage.storeVerificationToken({
      userId: user.id,
      email,
      purpose: "EmailVerification",
      tokenHash: pair.hash,
      expiresAt: 100,
      now: 1,
    });
    const found = yield* storage.findVerificationToken({
      purpose: "EmailVerification",
      tokenHash: pair.hash,
      now: 2,
    });
    yield* storage.consumeVerificationToken({
      purpose: "EmailVerification",
      tokenHash: pair.hash,
      now: 2,
    });
    const consumedAgain = yield* Effect.exit(
      storage.consumeVerificationToken({
        purpose: "EmailVerification",
        tokenHash: pair.hash,
        now: 3,
      }),
    );

    assert.strictEqual(duplicate._tag, "Failure");
    assert.strictEqual(found.user.id, user.id);
    assert.strictEqual(consumedAgain._tag, "Failure");
  }),
);

it.effect("dev memory storage enforces session expiry and atomic rotation", () =>
  Effect.gen(function* () {
    const boundary = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* AuthBoundary;
    }).pipe(Effect.provide(AuthBoundaryLive));
    const tokenService = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* AuthToken;
    }).pipe(Effect.provide(AuthTokenLive));
    const hasher = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* PasswordHasher;
    }).pipe(Effect.provide(NativeScryptPasswordHasher));
    const storage = makeDevMemoryStorage();
    const email = yield* boundary.parseEmail("sessions@example.com");
    const password = yield* boundary.parsePassword("correct horse battery staple");
    const passwordHash = yield* hasher.hash(password);
    const user = yield* storage.createUserWithEmailPasswordCredential({
      email,
      passwordHash,
      now: 1,
    });
    const expiredPair = yield* tokenService.makeSessionToken();
    yield* storage.createSession({
      userId: user.id,
      tokenHash: expiredPair.hash,
      expiresAt: -1,
      now: 1,
    });
    const expired = yield* Effect.exit(storage.findSessionByTokenHash(expiredPair.hash));

    const currentPair = yield* tokenService.makeSessionToken();
    const nextPair = yield* tokenService.makeSessionToken();
    yield* storage.createSession({
      userId: user.id,
      tokenHash: currentPair.hash,
      expiresAt: 9_999_999_999_999,
      now: 1,
    });
    const rotated = yield* storage.rotateSessionToken({
      previousHash: currentPair.hash,
      nextHash: nextPair.hash,
      expiresAt: 9_999_999_999_999,
      now: 2,
    });
    const oldLookup = yield* Effect.exit(storage.findSessionByTokenHash(currentPair.hash));
    const newLookup = yield* storage.findSessionByTokenHash(nextPair.hash);

    assert.strictEqual(expired._tag, "Failure");
    assert.strictEqual(oldLookup._tag, "Failure");
    assert.strictEqual(newLookup.session.id, rotated.id);
  }),
);
it.effect("email password workflows verify email before issuing sessions", () => {
  const { emailState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    yield* emailPassword.signUp({
      email: " USER@example.COM ",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });

    assert.strictEqual(emailState.sent.length, 1);
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    assert.strictEqual(verification.kind, "EmailVerification");

    const unverified = yield* Effect.exit(
      emailPassword.signIn({
        email: "user@example.com",
        password: "correct horse battery staple",
      }),
    );
    assert.strictEqual(unverified._tag, "Failure");

    yield* emailPassword.verifyEmail({ token: verification.token });
    const consumedAgain = yield* Effect.exit(
      emailPassword.verifyEmail({ token: verification.token }),
    );
    assert.strictEqual(consumedAgain._tag, "Failure");

    const signedIn = yield* emailPassword.signIn({
      email: "user@example.com",
      password: "correct horse battery staple",
    });
    assert.strictEqual(signedIn.user.email, "user@example.com");
  }).pipe(Effect.provide(layer));
});

it.effect("AuthLive.default exposes flat Auth sign-in with a redacted session token", () => {
  const storageState = makeDevMemoryStorageState();
  const emailState = makeMockAuthEmailState();
  const authLayer = AuthLive.default.pipe(
    Layer.provideMerge(
      Layer.mergeAll(DevMemoryAuthStorage(storageState), MockAuthEmail(emailState)),
    ),
  );
  return Effect.gen(function* () {
    const auth = yield* Auth;
    yield* auth.signUp({
      email: "flat-auth@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* auth.verifyEmail({ token: verification.token });

    const signedIn = yield* auth.signIn({
      email: "flat-auth@example.com",
      password: "correct horse battery staple",
    });

    assert.strictEqual(signedIn.user.email, "flat-auth@example.com");
    assert.equal(
      String(signedIn.sessionToken).includes(Redacted.value(signedIn.sessionToken)),
      false,
    );
    assert.equal(
      jsonString(signedIn.sessionToken).includes(Redacted.value(signedIn.sessionToken)),
      false,
    );
  }).pipe(Effect.provide(authLayer));
});

it.effect("AuthHttp.mount adds a token-free sign-in route under the configured base path", () => {
  const storageState = makeDevMemoryStorageState();
  const emailState = makeMockAuthEmailState();
  const authLayer = AuthLive.default.pipe(
    Layer.provideMerge(
      Layer.mergeAll(DevMemoryAuthStorage(storageState), MockAuthEmail(emailState)),
    ),
  );
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
          AuthHttpConfigLayer({
            trustedOrigins: ["https://app.example.com"],
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

it.effect("AuthHttp.mount serves email, session, sign-out, and password routes", () => {
  const storageState = makeDevMemoryStorageState();
  const emailState = makeMockAuthEmailState();
  const authLayer = AuthLive.default.pipe(
    Layer.provideMerge(
      Layer.mergeAll(DevMemoryAuthStorage(storageState), MockAuthEmail(emailState)),
    ),
  );
  return Effect.gen(function* () {
    const routes = AuthHttp.mount({ basePath: "/api/auth" })(HttpRouter.layer);
    const appLayer = routes.pipe(
      Layer.provideMerge(
        Layer.mergeAll(
          authLayer,
          AuthHttpConfigLayer({
            trustedOrigins: ["https://app.example.com"],
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

it.effect(
  "AuthHttp.requireAuth provides AuthSession from cookies and explicit bearer tokens",
  () => {
    const storageState = makeDevMemoryStorageState();
    const emailState = makeMockAuthEmailState();
    const authLayer = AuthLive.default.pipe(
      Layer.provideMerge(
        Layer.mergeAll(DevMemoryAuthStorage(storageState), MockAuthEmail(emailState)),
      ),
    );
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
          AuthHttpConfigLayer({
            trustedOrigins: ["https://app.example.com"],
            secureCookies: true,
          }),
        ),
      ),
    );
  },
);

it.effect("AuthHttp.optionalAuth provides CurrentAuthSession and cleans stale cookies", () => {
  const storageState = makeDevMemoryStorageState();
  const emailState = makeMockAuthEmailState();
  const authLayer = AuthLive.default.pipe(
    Layer.provideMerge(
      Layer.mergeAll(DevMemoryAuthStorage(storageState), MockAuthEmail(emailState)),
    ),
  );
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
            HttpClientRequest.setHeader("cookie", "effect_auth_session=stale"),
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
        AuthHttpConfigLayer({
          trustedOrigins: ["https://app.example.com"],
          secureCookies: true,
        }),
      ),
    ),
  );
});

it.effect(
  "sign-up covers duplicate emails, typed delivery failure, and redacted email tokens",
  () => {
    const { emailState, layer } = makeWorkflowLayer();
    return Effect.gen(function* () {
      const emailPassword = yield* EmailPasswordWorkflows;
      yield* emailPassword.signUp({
        email: "duplicate@example.com",
        password: "correct horse battery staple",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      });
      const duplicate = yield* Effect.flip(
        emailPassword.signUp({
          email: "duplicate@example.com",
          password: "correct horse battery staple",
          verificationCallbackUrl: new URL("https://app.example.com/verify"),
        }),
      );
      const sent = emailState.sent[0];
      if (!sent) return yield* missingFixture("missing verification email");

      assert.deepStrictEqual(duplicate, new AuthStorageFailure({ reason: "Conflict" }));
      assert.equal(String(sent.token).includes(Redacted.value(sent.token)), false);
    }).pipe(Effect.provide(layer));
  },
);

it.effect("auth email port preserves typed delivery failures", () => {
  const failingEmail = Layer.succeed(AuthEmail)({
    sendEmailVerification: () =>
      Effect.fail(new AuthEmailFailure({ reason: "DeliveryUnavailable" })),
    sendPasswordReset: () => Effect.fail(new AuthEmailFailure({ reason: "InvalidRecipient" })),
  });
  const layer = Layer.mergeAll(EmailPasswordWorkflowsLive, PasswordRecoveryWorkflowsLive).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        AuthBoundaryLive,
        SecureDefaultPasswordPolicy,
        NativeScryptPasswordHasher,
        AuthTokenLive,
        DevMemoryAuthStorage(makeDevMemoryStorageState()),
        failingEmail,
        PermissiveDevRateLimiter,
      ),
    ),
  );

  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const failed = yield* Effect.flip(
      emailPassword.signUp({
        email: "delivery@example.com",
        password: "correct horse battery staple",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      }),
    );

    assert.deepStrictEqual(failed, new AuthEmailFailure({ reason: "DeliveryUnavailable" }));
    const resendFailed = yield* Effect.flip(
      emailPassword.resendVerification({
        email: "delivery@example.com",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      }),
    );
    assert.deepStrictEqual(resendFailed, new AuthEmailFailure({ reason: "DeliveryUnavailable" }));
  }).pipe(Effect.provide(layer));
});

it.effect("verify and resend cover expired tokens and already-verified no-op", () => {
  const { emailState, storageState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    yield* emailPassword.signUp({
      email: "verify-expired@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    for (const [key, token] of storageState.tokensByHash) {
      storageState.tokensByHash.set(key, { ...token, expiresAt: 0 });
    }
    const expired = yield* Effect.flip(emailPassword.verifyEmail({ token: verification.token }));
    assert.deepStrictEqual(expired, invalidToken);

    yield* emailPassword.signUp({
      email: "verified@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verifiedToken = emailState.sent[1];
    if (!verifiedToken) return yield* missingFixture("missing second verification email");
    yield* emailPassword.verifyEmail({ token: verifiedToken.token });
    yield* emailPassword.resendVerification({
      email: "verified@example.com",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    assert.strictEqual(emailState.sent.length, 2);
  }).pipe(Effect.provide(layer));
});

it.effect("workflow rate-limit failures become equivalent public RateLimited errors", () => {
  const limited = Layer.succeed(RateLimiter)({
    check: (attempt) =>
      Effect.fail(new RateLimitExceeded({ bucket: attempt.bucket, retryAfterMillis: 1_000 })),
  });
  const layer = Layer.mergeAll(EmailPasswordWorkflowsLive, PasswordRecoveryWorkflowsLive).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        AuthBoundaryLive,
        SecureDefaultPasswordPolicy,
        NativeScryptPasswordHasher,
        AuthTokenLive,
        DevMemoryAuthStorage(makeDevMemoryStorageState()),
        MockAuthEmail(makeMockAuthEmailState()),
        limited,
      ),
    ),
  );

  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;
    const signUp = yield* Effect.flip(
      emailPassword.signUp({
        email: "limited@example.com",
        password: "correct horse battery staple",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      }),
    );
    const signIn = yield* Effect.flip(
      emailPassword.signIn({
        email: "limited@example.com",
        password: "correct horse battery staple",
      }),
    );
    const resend = yield* Effect.flip(
      emailPassword.resendVerification({
        email: "limited@example.com",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      }),
    );
    const reset = yield* Effect.flip(
      recovery.requestPasswordReset({
        email: "limited@example.com",
        resetCallbackUrl: new URL("https://app.example.com/reset"),
      }),
    );

    assert.deepStrictEqual(signUp, rateLimited);
    assert.deepStrictEqual(signIn, rateLimited);
    assert.deepStrictEqual(resend, rateLimited);
    assert.deepStrictEqual(reset, rateLimited);
  }).pipe(Effect.provide(layer));
});

it.effect("sign-in uses equivalent public errors and dummy hash work for missing accounts", () => {
  const { emailState, storageState } = makeWorkflowLayer();
  let hashCalls = 0;
  let verifyCalls = 0;
  const countingHasher: PasswordHasherShape = {
    hash: (password) =>
      Effect.gen(function* () {
        hashCalls++;
        const hasher = yield* PasswordHasher;
        return yield* hasher.hash(password);
      }).pipe(Effect.provide(NativeScryptPasswordHasher)),
    verify: (input) =>
      Effect.gen(function* () {
        verifyCalls++;
        const hasher = yield* PasswordHasher;
        return yield* hasher.verify(input);
      }).pipe(Effect.provide(NativeScryptPasswordHasher)),
  };
  const layer = Layer.mergeAll(EmailPasswordWorkflowsLive).pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        AuthBoundaryLive,
        SecureDefaultPasswordPolicy,
        Layer.succeed(PasswordHasher)(countingHasher),
        AuthTokenLive,
        DevMemoryAuthStorage(storageState),
        MockAuthEmail(emailState),
        PermissiveDevRateLimiter,
      ),
    ),
  );

  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    yield* emailPassword.signUp({
      email: "enumeration@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });

    const missing = yield* Effect.flip(
      emailPassword.signIn({
        email: "missing-enumeration@example.com",
        password: "correct horse battery staple",
      }),
    );
    const wrong = yield* Effect.flip(
      emailPassword.signIn({
        email: "enumeration@example.com",
        password: "wrong correct horse battery",
      }),
    );

    assert.deepStrictEqual(missing, invalidCredentials);
    assert.deepStrictEqual(wrong, invalidCredentials);
    assert.strictEqual(hashCalls, 2);
    assert.strictEqual(verifyCalls, 1);
  }).pipe(Effect.provide(layer));
});

it.effect("session workflow rotates stale sessions and sign-out revokes them", () => {
  const { emailState, storageState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    yield* emailPassword.signUp({
      email: "session@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });
    const signedIn = yield* emailPassword.signIn({
      email: "session@example.com",
      password: "correct horse battery staple",
    });

    const unchanged = yield* sessions.currentSession({ sessionToken: signedIn.sessionToken });
    assert.strictEqual(unchanged.tokenRotation._tag, "Unchanged");

    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 2 * 24 * 60 * 60 * 1000,
      });
    }
    const rotated = yield* sessions.currentSession({ sessionToken: signedIn.sessionToken });
    assert.strictEqual(rotated.tokenRotation._tag, "Rotated");
    if (!Predicate.isTagged(rotated.tokenRotation, "Rotated")) {
      return yield* missingFixture("missing rotation");
    }

    yield* sessions.signOut({ sessionToken: rotated.tokenRotation.token });
    const signedOut = yield* Effect.exit(
      sessions.currentSession({ sessionToken: rotated.tokenRotation.token }),
    );
    assert.strictEqual(signedOut._tag, "Failure");
  }).pipe(Effect.provide(layer));
});

it.effect("password reset revokes sessions and password change rotates current session", () => {
  const { emailState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;
    const sessions = yield* SessionWorkflows;
    yield* emailPassword.signUp({
      email: "reset@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });
    const firstSession = yield* emailPassword.signIn({
      email: "reset@example.com",
      password: "correct horse battery staple",
    });

    yield* recovery.requestPasswordReset({
      email: "missing@example.com",
      resetCallbackUrl: new URL("https://app.example.com/reset"),
    });
    assert.strictEqual(emailState.sent.length, 1);

    yield* recovery.requestPasswordReset({
      email: "reset@example.com",
      resetCallbackUrl: new URL("https://app.example.com/reset"),
    });
    const resetEmail = emailState.sent[1];
    if (!resetEmail) return yield* missingFixture("missing reset email");
    const weakReset = yield* Effect.exit(
      recovery.resetPassword({
        token: resetEmail.token,
        password: "too short",
      }),
    );
    assert.strictEqual(weakReset._tag, "Failure");
    yield* recovery.resetPassword({
      token: resetEmail.token,
      password: "new correct horse battery",
    });
    const revoked = yield* Effect.exit(
      sessions.currentSession({ sessionToken: firstSession.sessionToken }),
    );
    assert.strictEqual(revoked._tag, "Failure");

    const current = yield* emailPassword.signIn({
      email: "reset@example.com",
      password: "new correct horse battery",
    });
    const other = yield* emailPassword.signIn({
      email: "reset@example.com",
      password: "new correct horse battery",
    });
    const changed = yield* recovery.changePassword({
      sessionToken: current.sessionToken,
      currentPassword: "new correct horse battery",
      newPassword: "changed correct horse battery",
    });
    const currentOld = yield* Effect.exit(
      sessions.currentSession({ sessionToken: current.sessionToken }),
    );
    const otherRevoked = yield* Effect.exit(
      sessions.currentSession({ sessionToken: other.sessionToken }),
    );
    const currentNew = yield* sessions.currentSession({
      sessionToken: changed.currentSessionToken,
    });

    assert.strictEqual(currentOld._tag, "Failure");
    assert.strictEqual(otherRevoked._tag, "Failure");
    assert.strictEqual(currentNew.session.userId, current.user.id);
  }).pipe(Effect.provide(layer));
});

it.effect("password reset rejects expired and consumed tokens", () => {
  const { emailState, storageState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;
    yield* emailPassword.signUp({
      email: "reset-token@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });

    yield* recovery.requestPasswordReset({
      email: "reset-token@example.com",
      resetCallbackUrl: new URL("https://app.example.com/reset"),
    });
    const expiredEmail = emailState.sent[1];
    if (!expiredEmail) return yield* missingFixture("missing reset email");
    for (const [key, token] of storageState.tokensByHash) {
      if (token.purpose === "PasswordReset")
        storageState.tokensByHash.set(key, { ...token, expiresAt: 0 });
    }
    const expired = yield* Effect.flip(
      recovery.resetPassword({
        token: expiredEmail.token,
        password: "new correct horse battery",
      }),
    );

    yield* recovery.requestPasswordReset({
      email: "reset-token@example.com",
      resetCallbackUrl: new URL("https://app.example.com/reset"),
    });
    const consumedEmail = emailState.sent[2];
    if (!consumedEmail) return yield* missingFixture("missing consumed reset email");
    yield* recovery.resetPassword({
      token: consumedEmail.token,
      password: "new correct horse battery",
    });
    const consumed = yield* Effect.flip(
      recovery.resetPassword({
        token: consumedEmail.token,
        password: "another correct horse battery",
      }),
    );

    assert.deepStrictEqual(expired, invalidToken);
    assert.deepStrictEqual(consumed, invalidToken);
  }).pipe(Effect.provide(layer));
});

it.effect(
  "password change rejects unauthenticated, wrong password, weak policy, and rate limits",
  () => {
    const { emailState, storageState, layer } = makeWorkflowLayer();
    return Effect.gen(function* () {
      const emailPassword = yield* EmailPasswordWorkflows;
      const recovery = yield* PasswordRecoveryWorkflows;
      const tokenService = yield* AuthToken;
      yield* emailPassword.signUp({
        email: "change-failures@example.com",
        password: "correct horse battery staple",
        verificationCallbackUrl: new URL("https://app.example.com/verify"),
      });
      const verification = emailState.sent[0];
      if (!verification) return yield* missingFixture("missing verification email");
      yield* emailPassword.verifyEmail({ token: verification.token });
      const signedIn = yield* emailPassword.signIn({
        email: "change-failures@example.com",
        password: "correct horse battery staple",
      });
      const missingToken = yield* tokenService.makeSessionToken();
      const unauthenticated = yield* Effect.flip(
        recovery.changePassword({
          sessionToken: missingToken.token,
          currentPassword: "correct horse battery staple",
          newPassword: "changed correct horse battery",
        }),
      );
      const wrongPassword = yield* Effect.flip(
        recovery.changePassword({
          sessionToken: signedIn.sessionToken,
          currentPassword: "wrong correct horse battery",
          newPassword: "changed correct horse battery",
        }),
      );
      const weakPassword = yield* Effect.flip(
        recovery.changePassword({
          sessionToken: signedIn.sessionToken,
          currentPassword: "correct horse battery staple",
          newPassword: "too short",
        }),
      );
      for (const [key, session] of storageState.sessionsByHash) {
        storageState.sessionsByHash.set(key, { ...session, expiresAt: 0 });
      }
      const expiredSession = yield* Effect.flip(
        recovery.changePassword({
          sessionToken: signedIn.sessionToken,
          currentPassword: "correct horse battery staple",
          newPassword: "changed correct horse battery",
        }),
      );

      assert.deepStrictEqual(unauthenticated, unauthorized);
      assert.deepStrictEqual(wrongPassword, invalidCredentials);
      assert.deepStrictEqual(weakPassword, new PasswordPolicyFailure({ reason: "TooShort" }));
      assert.deepStrictEqual(expiredSession, unauthorized);
    }).pipe(Effect.provide(layer));
  },
);

it.effect("password change checks rate limits before session lookup", () => {
  const limited = Layer.succeed(RateLimiter)({
    check: (attempt) =>
      Effect.fail(new RateLimitExceeded({ bucket: attempt.bucket, retryAfterMillis: 1_000 })),
  });
  const layer = PasswordRecoveryWorkflowsLive.pipe(
    Layer.provideMerge(
      Layer.mergeAll(
        AuthBoundaryLive,
        SecureDefaultPasswordPolicy,
        NativeScryptPasswordHasher,
        AuthTokenLive,
        DevMemoryAuthStorage(makeDevMemoryStorageState()),
        MockAuthEmail(makeMockAuthEmailState()),
        limited,
      ),
    ),
  );

  return Effect.gen(function* () {
    const recovery = yield* PasswordRecoveryWorkflows;
    const tokenService = yield* AuthToken;
    const token = yield* tokenService.makeSessionToken();
    const limited = yield* Effect.flip(
      recovery.changePassword({
        sessionToken: token.token,
        currentPassword: "correct horse battery staple",
        newPassword: "changed correct horse battery",
        ip: "127.0.0.1",
      }),
    );

    assert.deepStrictEqual(limited, rateLimited);
  }).pipe(Effect.provide(layer));
});

it.effect("http helpers preserve cookie defaults and public error mapping", () => {
  const { layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const tokenService = yield* AuthToken;
    const session = yield* tokenService.makeSessionToken();
    const setCookie = makeSessionCookie(session.token);
    const clearCookie = clearSessionCookie();

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
    ]);
  }),
);
