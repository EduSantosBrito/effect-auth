import { assert, it } from "@effect/vitest";
import {
  Auth,
  AuthBoundaryLive,
  AuthEmail,
  AuthEmailFailure,
  AuthLive,
  AuthStorageFailure,
  AuthToken,
  AuthTokenLive,
  Clock,
  DevMemoryAuthStorage,
  Effect,
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  Layer,
  MockAuthEmail,
  PasswordHasher,
  PasswordPolicyFailure,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  Predicate,
  RateLimitExceeded,
  RateLimiter,
  Redacted,
  SecureDefaultPasswordPolicy,
  SessionWorkflows,
  TestPasswordHasher,
  jsonString,
  makeDevMemoryStorageState,
  makeMockAuthEmailState,
  makeWorkflowLayer,
  missingFixture,
  invalidCredentials,
  invalidToken,
  parseClientIp,
  rateLimited,
  unauthorized,
  type PasswordHasherShape,
} from "./support";

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

it.effect("verification token TTLs are configured at the workflow seam", () => {
  const { storageState, layer } = makeWorkflowLayer({
    verificationTokenConfig: {
      emailVerificationTtl: "2 hours",
      passwordResetTtl: "3 minutes",
    },
  });
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;
    const beforeSignUp = yield* Clock.currentTimeMillis;
    yield* emailPassword.signUp({
      email: "ttl@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: "https://app.example.com/verify",
    });
    const afterSignUp = yield* Clock.currentTimeMillis;
    const verificationRecord = Array.from(storageState.tokensByHash.values()).find(
      (record) => record.purpose === "EmailVerification",
    );
    if (!verificationRecord) return yield* missingFixture("missing verification token");
    assert.equal(verificationRecord.expiresAt >= beforeSignUp + 2 * 60 * 60 * 1000, true);
    assert.equal(verificationRecord.expiresAt <= afterSignUp + 2 * 60 * 60 * 1000, true);

    const beforeReset = yield* Clock.currentTimeMillis;
    yield* recovery.requestPasswordReset({
      email: "ttl@example.com",
      resetCallbackUrl: "https://app.example.com/reset",
    });
    const afterReset = yield* Clock.currentTimeMillis;
    const resetRecord = Array.from(storageState.tokensByHash.values()).find(
      (record) => record.purpose === "PasswordReset",
    );
    if (!resetRecord) return yield* missingFixture("missing password reset token");
    assert.equal(resetRecord.expiresAt >= beforeReset + 3 * 60 * 1000, true);
    assert.equal(resetRecord.expiresAt <= afterReset + 3 * 60 * 1000, true);
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
        TestPasswordHasher,
        AuthTokenLive,
        DevMemoryAuthStorage(makeDevMemoryStorageState()),
        failingEmail,
        Layer.succeed(RateLimiter)({ check: () => Effect.void }),
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
        TestPasswordHasher,
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
      }).pipe(Effect.provide(TestPasswordHasher)),
    verify: (input) =>
      Effect.gen(function* () {
        verifyCalls++;
        const hasher = yield* PasswordHasher;
        return yield* hasher.verify(input);
      }).pipe(Effect.provide(TestPasswordHasher)),
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
        Layer.succeed(RateLimiter)({ check: () => Effect.void }),
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

it.effect("session policy drives issue and refresh durations", () => {
  const { emailState, storageState, layer } = makeWorkflowLayer({
    sessionPolicy: { sessionTtl: "2 hours", sessionUpdateAge: "30 minutes" },
  });
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    const beforeSignIn = yield* Clock.currentTimeMillis;
    yield* emailPassword.signUp({
      email: "policy@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });
    const signedIn = yield* emailPassword.signIn({
      email: "policy@example.com",
      password: "correct horse battery staple",
    });
    const afterSignIn = yield* Clock.currentTimeMillis;

    assert.equal(signedIn.session.expiresAt >= beforeSignIn + 2 * 60 * 60 * 1000, true);
    assert.equal(signedIn.session.expiresAt <= afterSignIn + 2 * 60 * 60 * 1000, true);

    for (const [key, session] of storageState.sessionsByHash) {
      storageState.sessionsByHash.set(key, {
        ...session,
        updatedAt: session.updatedAt - 31 * 60 * 1000,
      });
    }
    const beforeRefresh = yield* Clock.currentTimeMillis;
    const refreshed = yield* sessions.currentSession({ sessionToken: signedIn.sessionToken });
    const afterRefresh = yield* Clock.currentTimeMillis;

    assert.strictEqual(refreshed.tokenRotation._tag, "Rotated");
    assert.equal(refreshed.session.expiresAt >= beforeRefresh + 2 * 60 * 60 * 1000, true);
    assert.equal(refreshed.session.expiresAt <= afterRefresh + 2 * 60 * 60 * 1000, true);
  }).pipe(Effect.provide(layer));
});

it.effect("session management lists and revokes current-user sessions", () => {
  const { emailState, layer } = makeWorkflowLayer();
  return Effect.gen(function* () {
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    yield* emailPassword.signUp({
      email: "devices@example.com",
      password: "correct horse battery staple",
      verificationCallbackUrl: new URL("https://app.example.com/verify"),
    });
    const verification = emailState.sent[0];
    if (!verification) return yield* missingFixture("missing verification email");
    yield* emailPassword.verifyEmail({ token: verification.token });
    const ip = yield* parseClientIp("127.0.0.1");
    const current = yield* emailPassword.signIn({
      email: "devices@example.com",
      password: "correct horse battery staple",
      ip,
      userAgent: "Effect Auth Test",
    });
    const other = yield* emailPassword.signIn({
      email: "devices@example.com",
      password: "correct horse battery staple",
    });

    const listed = yield* sessions.listSessions({ sessionToken: current.sessionToken });
    const listedCurrent = listed.sessions.find((session) => session.id === current.session.id);
    const listedOther = listed.sessions.find((session) => session.id === other.session.id);
    if (!listedCurrent || !listedOther) return yield* missingFixture("missing listed sessions");

    assert.strictEqual(listed.sessions.length, 2);
    assert.strictEqual(listedCurrent.isCurrent, true);
    assert.strictEqual(listedCurrent.ipAddress, "127.0.0.1");
    assert.strictEqual(listedCurrent.userAgent, "Effect Auth Test");
    assert.strictEqual(listedOther.isCurrent, false);
    assert.equal(jsonString(listedCurrent).includes("tokenHash"), false);

    yield* sessions.revokeSession({
      sessionToken: current.sessionToken,
      sessionId: other.session.id,
    });
    const afterSingleRevoke = yield* sessions.listSessions({ sessionToken: current.sessionToken });
    assert.deepStrictEqual(
      afterSingleRevoke.sessions.map((session) => session.id),
      [current.session.id],
    );

    const third = yield* emailPassword.signIn({
      email: "devices@example.com",
      password: "correct horse battery staple",
    });
    yield* sessions.revokeOtherSessions({ sessionToken: current.sessionToken });
    const thirdRevoked = yield* Effect.exit(
      sessions.currentSession({ sessionToken: third.sessionToken }),
    );
    const currentStillValid = yield* sessions.currentSession({
      sessionToken: current.sessionToken,
    });
    yield* sessions.revokeSessions({ sessionToken: current.sessionToken });
    const currentRevoked = yield* Effect.exit(
      sessions.currentSession({ sessionToken: current.sessionToken }),
    );

    assert.strictEqual(thirdRevoked._tag, "Failure");
    assert.strictEqual(currentStillValid.session.id, current.session.id);
    assert.strictEqual(currentRevoked._tag, "Failure");
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
        TestPasswordHasher,
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
    const ip = yield* parseClientIp("127.0.0.1");
    const limited = yield* Effect.flip(
      recovery.changePassword({
        sessionToken: token.token,
        currentPassword: "correct horse battery staple",
        newPassword: "changed correct horse battery",
        ip,
      }),
    );

    assert.deepStrictEqual(limited, rateLimited);
  }).pipe(Effect.provide(layer));
});
