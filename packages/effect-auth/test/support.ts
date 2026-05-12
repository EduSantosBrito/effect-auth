import * as Clock from "effect/Clock";
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
import { Auth, AuthLive, type AuthShape } from "../src/auth";
import {
  AuthBoundary,
  AuthBoundaryLive,
  BoundaryParseError,
  invalidToken,
  invalidCredentials,
  rateLimited,
  unauthorized,
  normalizeEmail,
  normalizePassword,
  parseCallbackUrl,
  parseClientIp,
} from "../src/domain/index";
import { AuthEmail, AuthEmailFailure } from "../src/email/index";
import { makeMockAuthEmailState, MockAuthEmail } from "../src/email/mock";
import {
  AuthHttp,
  AuthApiEndpoints,
  AuthHttpConfig,
  AuthHttpErrorMapper,
  AuthHttpToken,
  AuthSession,
  CurrentAuthSession,
  TrustedOrigins,
} from "../src/http/index";
import {
  AuthHttpAdapter,
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
  jsonWithCookieInstruction,
  mapPublicHttpError,
  SessionCookie,
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
import { AuthToken, AuthTokenLive, SessionToken, VerificationToken } from "../src/token/index";
import {
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  SessionWorkflows,
  SessionWorkflowsLive,
  SessionPolicyLive,
  VerificationTokenConfigLive,
} from "../src/workflows/index";

class MissingFixture extends Schema.TaggedErrorClass<MissingFixture>()("MissingFixture", {
  message: Schema.String,
}) {}

const missingFixture = (message: string) => new MissingFixture({ message });
const decodePasswordHash = Schema.decodeUnknownEffect(PasswordHash);
const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);
const decodeVerificationToken = Schema.decodeUnknownEffect(VerificationToken);
const jsonString = Schema.encodeUnknownSync(Schema.UnknownFromJsonString);

const parseTestVerificationToken = (input: unknown) =>
  decodeVerificationToken(Redacted.isRedacted(input) ? Redacted.value(input) : input).pipe(
    Effect.mapError(
      () => new BoundaryParseError({ field: "token", reason: "Invalid verification token" }),
    ),
  );

const parseTestSessionToken = (input: unknown) =>
  decodeSessionToken(Redacted.isRedacted(input) ? Redacted.value(input) : input).pipe(
    Effect.mapError(
      () => new BoundaryParseError({ field: "sessionToken", reason: "Invalid session token" }),
    ),
  );

const makeTestPasswordHash = (password: string) => `effect-auth-test:${password}`;

const TestPasswordHasher = Layer.succeed(PasswordHasher)({
  hash: (password) => Effect.succeed(Redacted.make(makeTestPasswordHash(Redacted.value(password)))),
  verify: ({ password, hash }) =>
    Effect.succeed(Redacted.value(hash) === makeTestPasswordHash(Redacted.value(password))),
});

const AuthTestLive = Layer.effect(
  Auth,
  Effect.gen(function* () {
    const boundary = yield* AuthBoundary;
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;

    return {
      signUp: (input: Parameters<AuthShape["signUp"]>[0]) =>
        Effect.gen(function* () {
          const email = yield* boundary.parseEmail(input.email);
          const password = yield* boundary.parsePassword(input.password);
          const verificationCallbackUrl = yield* boundary.parseCallbackUrl(
            input.verificationCallbackUrl,
          );
          const ip = input.ip === undefined ? undefined : yield* boundary.parseClientIp(input.ip);
          return yield* emailPassword.signUp({
            email,
            password,
            verificationCallbackUrl,
            ...(ip === undefined ? {} : { ip }),
          });
        }),
      verifyEmail: emailPassword.verifyEmail,
      resendVerification: emailPassword.resendVerification,
      signIn: (input: Parameters<AuthShape["signIn"]>[0]) =>
        Effect.gen(function* () {
          const email = yield* boundary.parseEmail(input.email);
          const password = yield* boundary.parsePassword(input.password);
          const ip = input.ip === undefined ? undefined : yield* boundary.parseClientIp(input.ip);
          return yield* emailPassword.signIn({
            email,
            password,
            ...(ip === undefined ? {} : { ip }),
            ...(input.userAgent === undefined ? {} : { userAgent: input.userAgent }),
          });
        }),
      currentSession: sessions.currentSession,
      listSessions: sessions.listSessions,
      revokeSession: sessions.revokeSession,
      revokeOtherSessions: sessions.revokeOtherSessions,
      revokeSessions: sessions.revokeSessions,
      signOut: sessions.signOut,
      requestPasswordReset: (input: Parameters<AuthShape["requestPasswordReset"]>[0]) =>
        Effect.gen(function* () {
          const email = yield* boundary.parseEmail(input.email);
          const resetCallbackUrl = yield* boundary.parseCallbackUrl(input.resetCallbackUrl);
          const ip = input.ip === undefined ? undefined : yield* boundary.parseClientIp(input.ip);
          return yield* recovery.requestPasswordReset({
            email,
            resetCallbackUrl,
            ...(ip === undefined ? {} : { ip }),
          });
        }),
      resetPassword: (input: Parameters<AuthShape["resetPassword"]>[0]) =>
        Effect.gen(function* () {
          const token = yield* parseTestVerificationToken(input.token);
          const password = yield* boundary.parsePassword(input.password);
          return yield* recovery.resetPassword({ token, password });
        }),
      changePassword: (input: Parameters<AuthShape["changePassword"]>[0]) =>
        Effect.gen(function* () {
          const sessionToken = yield* parseTestSessionToken(input.sessionToken);
          const currentPassword = yield* boundary.parsePassword(input.currentPassword);
          const newPassword = yield* boundary.parsePassword(input.newPassword);
          const ip = input.ip === undefined ? undefined : yield* boundary.parseClientIp(input.ip);
          return yield* recovery.changePassword({
            sessionToken,
            currentPassword,
            newPassword,
            ...(ip === undefined ? {} : { ip }),
          });
        }),
    };
  }).pipe(Effect.annotateLogs("service", "AuthTest")),
);

const makeWorkflowLayer = (
  options: {
    readonly httpConfig?: Parameters<typeof AuthHttpConfig.layer>[0];
    readonly sessionPolicy?: Parameters<typeof SessionPolicyLive>[0];
    readonly verificationTokenConfig?: Parameters<typeof VerificationTokenConfigLive>[0];
  } = {},
) => {
  const storageState = makeDevMemoryStorageState();
  const emailState = makeMockAuthEmailState();
  const coreLayer = Layer.mergeAll(
    AuthBoundaryLive,
    SecureDefaultPasswordPolicy,
    TestPasswordHasher,
    AuthTokenLive,
    DevMemoryAuthStorage(storageState),
    MockAuthEmail(emailState),
    PermissiveDevRateLimiter,
    AuthHttpConfig.layer(
      options.httpConfig ?? { trustedOrigins: [new URL("https://app.example.com")] },
    ),
    VerificationTokenConfigLive(options.verificationTokenConfig),
    SessionPolicyLive(options.sessionPolicy),
  );
  const workflowsLayer = Layer.mergeAll(
    EmailPasswordWorkflowsLive,
    SessionWorkflowsLive,
    PasswordRecoveryWorkflowsLive,
  ).pipe(Layer.provideMerge(coreLayer));
  const layer = Layer.mergeAll(AuthTestLive.pipe(Layer.provide(workflowsLayer)), workflowsLayer);
  return { storageState, emailState, layer };
};

export {
  Auth,
  AuthApiEndpoints,
  AuthBoundary,
  AuthBoundaryLive,
  AuthEmail,
  AuthEmailFailure,
  AuthHttp,
  AuthHttpAdapter,
  AuthHttpConfig,
  AuthHttpErrorMapper,
  AuthHttpToken,
  AuthLive,
  AuthTestLive,
  AuthSession,
  AuthStorageFailure,
  AuthToken,
  AuthTokenLive,
  Clock,
  Context,
  Cookies,
  CurrentAuthSession,
  DevMemoryAuthStorage,
  Effect,
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  HttpClientRequest,
  HttpEffect,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
  Layer,
  MockAuthEmail,
  NativeScryptPasswordHasher,
  Option,
  PasswordHasher,
  PasswordPolicy,
  PasswordPolicyFailure,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  Predicate,
  RateLimitExceeded,
  RateLimiter,
  Redacted,
  SecureDefaultPasswordPolicy,
  SessionCookie,
  SessionPolicyLive,
  SessionWorkflows,
  SessionWorkflowsLive,
  TrustedOrigins,
  TestPasswordHasher,
  checkTrustedOrigin,
  checkTrustedRequestOrigin,
  createEffectAuthClient,
  decodePasswordHash,
  deriveRateLimitKey,
  handleChangePassword,
  handleCompletePasswordReset,
  handleCurrentSession,
  handleRequestPasswordReset,
  handleSignInEmail,
  handleSignOut,
  handleSignUpEmail,
  handleVerifyEmail,
  invalidCredentials,
  invalidToken,
  jsonString,
  jsonWithCookieInstruction,
  makeBoundedDevRateLimiter,
  makeDevMemoryStorage,
  makeDevMemoryStorageState,
  makeMockAuthEmailState,
  makeNativeScryptPasswordHasher,
  makeWorkflowLayer,
  mapPublicHttpError,
  missingFixture,
  normalizeEmail,
  normalizePassword,
  parseCallbackUrl,
  parseClientIp,
  rateLimited,
  unauthorized,
};
export type { PasswordHasherShape, SessionToken };
