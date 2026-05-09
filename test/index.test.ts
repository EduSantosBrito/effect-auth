import { assert, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import {
  AuthBoundary,
  AuthBoundaryLive,
  normalizeEmail,
  normalizePassword,
} from "../src/domain/index";
import { createEffectAuthClient } from "../src/index";
import {
  NativeScryptPasswordHasher,
  PasswordHash,
  PasswordHasher,
  PasswordPolicy,
  SecureDefaultPasswordPolicy,
} from "../src/password/index";
import { makeBoundedDevRateLimiter, PermissiveDevRateLimiter } from "../src/rate-limit/index";
import {
  makeDevMemoryStorage,
  makeDevMemoryStorageState,
  DevMemoryAuthStorage,
} from "../src/storage/dev-memory";
import { AuthToken, AuthTokenLive } from "../src/token/index";
import {
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  SessionWorkflows,
  SessionWorkflowsLive,
} from "../src/workflows/index";
import { makeMockAuthEmailState, MockAuthEmail } from "../src/email/mock";

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
    if (exit._tag === "Failure") {
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
      const malformedHash = yield* Schema.decodeUnknownEffect(PasswordHash)("not-a-phc-hash");
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

it.effect("auth token service returns redacted 32-byte base64url tokens and SHA-256 hashes", () =>
  Effect.gen(function* () {
    const tokenService = yield* Effect.gen(function* () {
      yield* Effect.void;
      return yield* AuthToken;
    }).pipe(Effect.provide(AuthTokenLive));
    const verification = yield* tokenService.makeVerificationToken;
    const secondVerification = yield* tokenService.makeVerificationToken;
    const session = yield* tokenService.makeSessionToken;
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
    const pair = yield* tokenService.makeVerificationToken;

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
    const expiredPair = yield* tokenService.makeSessionToken;
    yield* storage.createSession({
      userId: user.id,
      tokenHash: expiredPair.hash,
      expiresAt: -1,
      now: 1,
    });
    const expired = yield* Effect.exit(storage.findSessionByTokenHash(expiredPair.hash));

    const currentPair = yield* tokenService.makeSessionToken;
    const nextPair = yield* tokenService.makeSessionToken;
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
    if (!verification) return yield* Effect.die("missing verification email");
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
    if (!verification) return yield* Effect.die("missing verification email");
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
    if (rotated.tokenRotation._tag !== "Rotated") return yield* Effect.die("missing rotation");

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
    if (!verification) return yield* Effect.die("missing verification email");
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
    if (!resetEmail) return yield* Effect.die("missing reset email");
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
