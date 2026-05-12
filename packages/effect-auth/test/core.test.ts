import { assert, it } from "@effect/vitest";
import {
  AuthBoundary,
  AuthBoundaryLive,
  AuthToken,
  AuthTokenLive,
  AuthStorageFailure,
  Effect,
  NativeScryptPasswordHasher,
  PasswordHasher,
  PasswordPolicy,
  Predicate,
  Redacted,
  SecureDefaultPasswordPolicy,
  TestPasswordHasher,
  createEffectAuthClient,
  decodePasswordHash,
  deriveRateLimitKey,
  makeBoundedDevRateLimiter,
  makeDevMemoryStorage,
  makeDevMemoryStorageState,
  makeNativeScryptPasswordHasher,
  normalizeEmail,
  normalizePassword,
  parseClientIp,
} from "./support";

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
    const ip = yield* parseClientIp("127.0.0.1");
    yield* limiter.check({ bucket: "SignIn", ip });
    const exit = yield* Effect.exit(limiter.check({ bucket: "SignIn", ip }));

    assert.strictEqual(exit._tag, "Failure");
  }),
);

it.effect("rate limiter key derivation covers default and custom bucket semantics", () =>
  Effect.gen(function* () {
    const email = yield* normalizeEmail("USER@example.com");
    const ip = yield* parseClientIp("127.0.0.1");
    assert.strictEqual(
      deriveRateLimitKey({ bucket: "SignIn", email, ip }),
      "SignIn|email:user@example.com|ip:127.0.0.1",
    );
    assert.strictEqual(
      deriveRateLimitKey({ bucket: "SignIn", email }),
      "SignIn|email:user@example.com",
    );
    assert.strictEqual(deriveRateLimitKey({ bucket: "SignUp", ip }), "SignUp|ip:127.0.0.1");

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
    const otherIp = yield* Effect.exit(customLimiter.check({ bucket: "SignIn", email, ip }));

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
    }).pipe(Effect.provide(TestPasswordHasher));
    const storageState = makeDevMemoryStorageState();
    const storage = makeDevMemoryStorage(storageState);
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
    const storageState = makeDevMemoryStorageState();
    const storage = makeDevMemoryStorage(storageState);
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

it.effect("dev memory storage lists active sessions and revokes by current user scope", () =>
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
    }).pipe(Effect.provide(TestPasswordHasher));
    const storageState = makeDevMemoryStorageState();
    const storage = makeDevMemoryStorage(storageState);
    const email = yield* boundary.parseEmail("active-sessions@example.com");
    const otherEmail = yield* boundary.parseEmail("other-sessions@example.com");
    const password = yield* boundary.parsePassword("correct horse battery staple");
    const passwordHash = yield* hasher.hash(password);
    const user = yield* storage.createUserWithEmailPasswordCredential({
      email,
      passwordHash,
      now: 1,
    });
    const other = yield* storage.createUserWithEmailPasswordCredential({
      email: otherEmail,
      passwordHash,
      now: 1,
    });
    const currentPair = yield* tokenService.makeSessionToken();
    const expiredPair = yield* tokenService.makeSessionToken();
    const revokedPair = yield* tokenService.makeSessionToken();
    const otherPair = yield* tokenService.makeSessionToken();
    const current = yield* storage.createSession({
      userId: user.id,
      tokenHash: currentPair.hash,
      expiresAt: 100,
      now: 1,
      ipAddress: "127.0.0.1",
      userAgent: "Effect Auth Test",
    });
    yield* storage.createSession({
      userId: user.id,
      tokenHash: expiredPair.hash,
      expiresAt: 1,
      now: 1,
    });
    const revoked = yield* storage.createSession({
      userId: user.id,
      tokenHash: revokedPair.hash,
      expiresAt: 100,
      now: 1,
    });
    yield* storage.revokeSession({ tokenHash: revokedPair.hash, now: 2 });
    yield* storage.createSession({
      userId: other.id,
      tokenHash: otherPair.hash,
      expiresAt: 100,
      now: 1,
    });

    const listed = yield* storage.listUserSessions({ userId: user.id, now: 3 });
    const crossUser = yield* Effect.flip(
      storage.revokeUserSession({ userId: other.id, sessionId: current.id, now: 3 }),
    );
    const revokeInactive = yield* Effect.flip(
      storage.revokeUserSession({ userId: user.id, sessionId: revoked.id, now: 3 }),
    );
    yield* storage.revokeUserSession({ userId: user.id, sessionId: current.id, now: 3 });
    const afterRevoke = yield* storage.listUserSessions({ userId: user.id, now: 4 });
    const malformedPair = yield* tokenService.makeSessionToken();
    const malformed = Object.assign({}, current, {
      id: "ses_malformed",
      tokenHash: malformedPair.hash,
      expiresAt: "not-a-number",
    });
    Reflect.apply(Map.prototype.set, storageState.sessionsByHash, [
      Redacted.value(malformedPair.hash),
      malformed,
    ]);
    const malformedLookup = yield* Effect.flip(storage.findSessionByTokenHash(malformedPair.hash));
    const malformedList = yield* Effect.flip(storage.listUserSessions({ userId: user.id, now: 4 }));
    const malformedRevoke = yield* Effect.flip(
      storage.revokeUserSession({ userId: user.id, sessionId: "ses_malformed", now: 4 }),
    );

    assert.deepStrictEqual(
      listed.map((session) => session.id),
      [current.id],
    );
    assert.strictEqual(listed[0]?.ipAddress, "127.0.0.1");
    assert.strictEqual(listed[0]?.userAgent, "Effect Auth Test");
    assert.deepStrictEqual(crossUser, new AuthStorageFailure({ reason: "NotFound" }));
    assert.deepStrictEqual(revokeInactive, new AuthStorageFailure({ reason: "NotFound" }));
    assert.deepStrictEqual(
      malformedLookup,
      new AuthStorageFailure({ reason: "BackendUnavailable" }),
    );
    assert.deepStrictEqual(malformedList, new AuthStorageFailure({ reason: "BackendUnavailable" }));
    assert.deepStrictEqual(
      malformedRevoke,
      new AuthStorageFailure({ reason: "BackendUnavailable" }),
    );
    assert.deepStrictEqual(afterRevoke, []);
  }),
);
