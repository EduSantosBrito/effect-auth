import { Context, Data, Effect, Layer, Match, Option, Predicate, Redacted, Schema } from "effect";
import * as HttpEffect from "effect/unstable/http/HttpEffect";
import * as HttpRouter from "effect/unstable/http/HttpRouter";
import * as HttpServerRequest from "effect/unstable/http/HttpServerRequest";
import * as HttpServerResponse from "effect/unstable/http/HttpServerResponse";
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";
import { Auth } from "../auth.js";
import {
  invalidCredentials,
  invalidToken,
  parseClientIp,
  rateLimited,
  unauthorized,
  type ClientIp,
  type PublicAuthError,
} from "../domain/index.js";
import {
  SessionToken,
  VerificationToken,
  type SessionToken as SessionTokenValue,
} from "../token/index.js";
import type { AuthUser, StoredSession } from "../storage/index.js";
import {
  EmailPasswordWorkflows,
  PasswordRecoveryWorkflows,
  SessionWorkflows,
  type ChangePasswordInput,
  type ListedSession,
  type SignInInput,
  type TokenRotationDecision,
} from "../workflows/index.js";

export type AuthHttpError = Data.TaggedEnum<{
  Unauthorized: {};
  InvalidCredentials: {};
  EmailNotVerified: {};
  InvalidToken: {};
  MissingSessionToken: {};
  InvalidSessionToken: {};
  RateLimited: { readonly retryAfterMillis?: number };
  BadRequest: { readonly reason: string };
}>;

export const AuthHttpError = Data.taggedEnum<AuthHttpError>();

export interface AuthHttpErrorResponse {
  readonly status: number;
  readonly body: unknown;
  readonly headers?: Readonly<Record<string, string | ReadonlyArray<string>>>;
}

export interface AuthHttpErrorMapperShape {
  readonly map: (error: AuthHttpError) => Effect.Effect<AuthHttpErrorResponse>;
}

const defaultAuthHttpErrorMapper: AuthHttpErrorMapperShape = {
  map: Match.typeTags<AuthHttpError, Effect.Effect<AuthHttpErrorResponse>>()({
    RateLimited: () => Effect.succeed({ status: 429, body: rateLimited }),
    BadRequest: (error) =>
      Effect.succeed({
        status: 400,
        body: { code: "BadRequest", message: error.reason },
      }),
    InvalidCredentials: () => Effect.succeed({ status: 400, body: invalidCredentials }),
    EmailNotVerified: () =>
      Effect.succeed({
        status: 400,
        body: { code: "EmailNotVerified", message: "Email is not verified" },
      }),
    InvalidToken: () => Effect.succeed({ status: 400, body: invalidToken }),
    InvalidSessionToken: () => Effect.succeed({ status: 400, body: invalidToken }),
    MissingSessionToken: () => Effect.succeed({ status: 401, body: unauthorized }),
    Unauthorized: () => Effect.succeed({ status: 401, body: unauthorized }),
  }),
};

export const AuthHttpErrorMapper = Context.Reference<AuthHttpErrorMapperShape>(
  "effect-auth/http/AuthHttpErrorMapper",
  { defaultValue: () => defaultAuthHttpErrorMapper },
);

export interface AuthHttpConfigInput {
  readonly trustedOrigins: ReadonlyArray<URL>;
  readonly sessionCookieName?: string;
  readonly sessionCookiePath?: string;
  readonly secureCookies?: boolean;
  readonly defaultTokenExtractor?: AuthHttpTokenExtractor;
  readonly baseUrl?: URL;
}

const deriveSecureCookies = (input: AuthHttpConfigInput, nodeEnv: string): boolean => {
  if (input.secureCookies !== undefined) return input.secureCookies;
  if (input.baseUrl !== undefined) {
    if (input.baseUrl.protocol === "https:") return true;
    if (input.baseUrl.hostname === "localhost" || input.baseUrl.hostname === "127.0.0.1") {
      return false;
    }
  }
  return nodeEnv === "production";
};

const makeAuthHttpConfig = (input: AuthHttpConfigInput, nodeEnv: string): AuthHttpConfigShape => ({
  trustedOrigins: new Set(input.trustedOrigins.map((origin) => origin.origin)),
  sessionCookieName: input.sessionCookieName ?? "effect_auth_session",
  sessionCookiePath: input.sessionCookiePath ?? "/",
  secureCookies: deriveSecureCookies(input, nodeEnv),
  defaultTokenExtractor: Option.fromUndefinedOr(input.defaultTokenExtractor),
});

export class AuthHttpConfig extends Context.Service<
  AuthHttpConfig,
  {
    readonly trustedOrigins: ReadonlySet<string>;
    readonly sessionCookieName: string;
    readonly sessionCookiePath: string;
    readonly secureCookies: boolean;
    readonly defaultTokenExtractor: Option.Option<AuthHttpTokenExtractor>;
  }
>()("effect-auth/AuthHttpConfig") {
  static readonly layer = (input: AuthHttpConfigInput) =>
    Layer.succeed(AuthHttpConfig)(makeAuthHttpConfig(input, "development"));
}
export type AuthHttpConfigShape = typeof AuthHttpConfig.Service;

export class AuthSession extends Context.Service<
  AuthSession,
  {
    readonly user: AuthUser;
    readonly session: StoredSession;
  }
>()("effect-auth/AuthSession") {}
export type AuthSessionShape = typeof AuthSession.Service;

export class CurrentAuthSession extends Context.Service<
  CurrentAuthSession,
  {
    readonly current: Option.Option<{
      readonly user: AuthUser;
      readonly session: StoredSession;
    }>;
  }
>()("effect-auth/CurrentAuthSession") {}

export type SessionTokenExtractResult = Data.TaggedEnum<{
  Missing: {};
  Invalid: { readonly source: "Cookie" | "Bearer" };
  Found: {
    readonly token: SessionTokenValue;
    readonly source: "Cookie" | "Bearer";
  };
}>;

export const SessionTokenExtractResult = Data.taggedEnum<SessionTokenExtractResult>();

export interface AuthHttpTokenExtractor {
  readonly extract: Effect.Effect<
    SessionTokenExtractResult,
    never,
    HttpServerRequest.HttpServerRequest | AuthHttpConfig
  >;
}

const decodeSessionTokenValue = Schema.decodeUnknownEffect(SessionToken);

const bearerTokenValue = (authorization: string | undefined): string | undefined => {
  if (authorization === undefined) return undefined;
  const prefix = "Bearer ";
  return authorization.startsWith(prefix) ? authorization.slice(prefix.length).trim() : undefined;
};

const decodeExtractedToken = (
  value: string | undefined,
  source: "Cookie" | "Bearer",
): Effect.Effect<SessionTokenExtractResult> =>
  value === undefined || value === ""
    ? Effect.succeed(SessionTokenExtractResult.Missing())
    : decodeSessionTokenValue(value).pipe(
        Effect.map((token) => SessionTokenExtractResult.Found({ token, source })),
        Effect.catch(() => Effect.succeed(SessionTokenExtractResult.Invalid({ source }))),
      );

const cookieTokenExtractor: AuthHttpTokenExtractor = {
  extract: Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    const config = yield* AuthHttpConfig;
    return yield* decodeExtractedToken(request.cookies[config.sessionCookieName], "Cookie");
  }),
};

const bearerTokenExtractor: AuthHttpTokenExtractor = {
  extract: Effect.gen(function* () {
    const request = yield* HttpServerRequest.HttpServerRequest;
    return yield* decodeExtractedToken(bearerTokenValue(request.headers.authorization), "Bearer");
  }),
};

const cookieOrBearerTokenExtractor: AuthHttpTokenExtractor = {
  extract: Effect.gen(function* () {
    const bearer = yield* bearerTokenExtractor.extract;
    return yield* Match.valueTags(bearer, {
      Found: (found) => Effect.succeed(found),
      Invalid: (invalid) => Effect.succeed(invalid),
      Missing: () => cookieTokenExtractor.extract,
    });
  }),
};

export const AuthHttpToken = {
  cookie: cookieTokenExtractor,
  bearer: bearerTokenExtractor,
  cookieOrBearer: cookieOrBearerTokenExtractor,
};

export class TrustedOriginPolicy extends Context.Service<
  TrustedOriginPolicy,
  {
    readonly isTrusted: (origin: URL) => Effect.Effect<boolean>;
  }
>()("effect-auth/TrustedOriginPolicy") {}
export type TrustedOriginPolicyShape = typeof TrustedOriginPolicy.Service;

interface SessionCookieOptions {
  readonly name?: string;
  readonly secure?: boolean;
  readonly path?: string;
}

interface CookieInstruction {
  readonly name: string;
  readonly value: string;
  readonly httpOnly: true;
  readonly sameSite: "Lax";
  readonly path: string;
  readonly secure: boolean;
  readonly maxAge?: number;
}

const makeSessionCookie = (
  token: SessionTokenValue,
  options: SessionCookieOptions = {},
): CookieInstruction => ({
  name: options.name ?? "effect_auth_session",
  value: Redacted.value(token),
  httpOnly: true,
  sameSite: "Lax",
  path: options.path ?? "/",
  secure: options.secure ?? true,
});

const clearSessionCookie = (options: SessionCookieOptions = {}): CookieInstruction => ({
  name: options.name ?? "effect_auth_session",
  value: "",
  httpOnly: true,
  sameSite: "Lax",
  path: options.path ?? "/",
  secure: options.secure ?? true,
  maxAge: 0,
});

interface SessionCookieHttpOptions {
  readonly httpOnly: true;
  readonly sameSite: "lax";
  readonly path: string;
  readonly secure: boolean;
  readonly maxAge?: number;
}

const sessionCookieOptions = (instruction: CookieInstruction): SessionCookieHttpOptions => ({
  httpOnly: instruction.httpOnly,
  sameSite: "lax",
  path: instruction.path,
  secure: instruction.secure,
  ...(instruction.maxAge === undefined ? {} : { maxAge: instruction.maxAge }),
});

const applyCookieInstruction = (
  response: HttpServerResponse.HttpServerResponse,
  instruction: CookieInstruction,
): HttpServerResponse.HttpServerResponse =>
  HttpServerResponse.setCookieUnsafe(
    response,
    instruction.name,
    instruction.value,
    sessionCookieOptions(instruction),
  );

export const jsonWithCookieInstruction = (
  body: unknown,
  instruction: CookieInstruction,
): HttpServerResponse.HttpServerResponse =>
  applyCookieInstruction(HttpServerResponse.jsonUnsafe(body), instruction);

const appendCookieInstruction = (instruction: CookieInstruction) =>
  HttpEffect.appendPreResponseHandler((_request, response) =>
    Effect.succeed(applyCookieInstruction(response, instruction)),
  );

export const mapPublicHttpError = (
  error: PublicAuthError,
): { readonly status: number; readonly body: PublicAuthError } => {
  return Match.value(error.code).pipe(
    Match.when("RateLimited", () => ({ status: 429, body: rateLimited })),
    Match.when("Unauthorized", () => ({ status: 401, body: unauthorized })),
    Match.when("InvalidCredentials", () => ({ status: 400, body: invalidCredentials })),
    Match.when("EmailNotVerified", () => ({ status: 400, body: error })),
    Match.when("InvalidToken", () => ({ status: 400, body: error })),
    Match.exhaustive,
  );
};

const publicAuthErrorToHttpError = (code: PublicAuthError["code"]): AuthHttpError => {
  return Match.value(code).pipe(
    Match.when("InvalidCredentials", () => AuthHttpError.InvalidCredentials()),
    Match.when("EmailNotVerified", () => AuthHttpError.EmailNotVerified()),
    Match.when("InvalidToken", () => AuthHttpError.InvalidToken()),
    Match.when("RateLimited", () => AuthHttpError.RateLimited({})),
    Match.when("Unauthorized", () => AuthHttpError.Unauthorized()),
    Match.exhaustive,
  );
};

const toAuthHttpError = (error: unknown): AuthHttpError => {
  const knownAuthHttpError = Match.value(error).pipe(
    Match.when(AuthHttpError.$is("Unauthorized"), (error) => Option.some(error)),
    Match.when(AuthHttpError.$is("InvalidCredentials"), (error) => Option.some(error)),
    Match.when(AuthHttpError.$is("EmailNotVerified"), (error) => Option.some(error)),
    Match.when(AuthHttpError.$is("InvalidToken"), (error) => Option.some(error)),
    Match.when(AuthHttpError.$is("MissingSessionToken"), (error) => Option.some(error)),
    Match.when(AuthHttpError.$is("InvalidSessionToken"), (error) => Option.some(error)),
    Match.when(AuthHttpError.$is("RateLimited"), (error) => Option.some(error)),
    Match.when(AuthHttpError.$is("BadRequest"), (error) => Option.some(error)),
    Match.orElse(() => Option.none<AuthHttpError>()),
  );
  if (Option.isSome(knownAuthHttpError)) return knownAuthHttpError.value;
  if (Predicate.hasProperty(error, "name") && error.name === "SchemaError") {
    return AuthHttpError.BadRequest({ reason: "Invalid request body" });
  }
  if (
    Predicate.hasProperty(error, "code") &&
    (error.code === "InvalidCredentials" ||
      error.code === "EmailNotVerified" ||
      error.code === "InvalidToken" ||
      error.code === "RateLimited" ||
      error.code === "Unauthorized")
  ) {
    return publicAuthErrorToHttpError(error.code);
  }
  if (Predicate.isTagged(error, "BoundaryParseError")) {
    return AuthHttpError.BadRequest({ reason: "Invalid request body" });
  }
  return AuthHttpError.Unauthorized();
};

const authHttpErrorResponse = Effect.fn("authHttpErrorResponse")(function* (error: AuthHttpError) {
  const mapper = yield* AuthHttpErrorMapper;
  const mapped = yield* mapper.map(error);
  return HttpServerResponse.jsonUnsafe(mapped.body, {
    status: mapped.status,
    headers: mapped.headers,
  });
});

const sessionCookieFromConfig = (
  token: SessionTokenValue,
  config: AuthHttpConfigShape,
): CookieInstruction =>
  makeSessionCookie(token, {
    name: config.sessionCookieName,
    path: config.sessionCookiePath,
    secure: config.secureCookies,
  });

const clearSessionCookieFromConfig = (config: AuthHttpConfigShape): CookieInstruction =>
  clearSessionCookie({
    name: config.sessionCookieName,
    path: config.sessionCookiePath,
    secure: config.secureCookies,
  });

export const SessionCookie = {
  make: makeSessionCookie,
  clear: clearSessionCookie,
  fromConfig: sessionCookieFromConfig,
  clearFromConfig: clearSessionCookieFromConfig,
  append: appendCookieInstruction,
  appendFromConfig: (token: SessionTokenValue) =>
    Effect.gen(function* () {
      const config = yield* AuthHttpConfig;
      yield* appendCookieInstruction(sessionCookieFromConfig(token, config));
    }),
  appendClearFromConfig: Effect.gen(function* () {
    const config = yield* AuthHttpConfig;
    yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
  }),
};

const authHttpSession = (session: StoredSession): AuthHttpSession => {
  const { tokenHash: _tokenHash, ...publicSession } = session;
  return publicSession;
};

export const checkTrustedOrigin: (
  origin: URL,
) => Effect.Effect<void, PublicAuthError, TrustedOriginPolicy> = Effect.fn("checkTrustedOrigin")(
  function* (origin) {
    const policy = yield* TrustedOriginPolicy;
    const trusted = yield* policy.isTrusted(origin);
    if (!trusted) return yield* unauthorized;
  },
);

interface OriginRequest {
  readonly headers: {
    readonly [key: string]: string | undefined;
  };
}

export const checkTrustedRequestOrigin = (
  request: OriginRequest,
): Effect.Effect<void, PublicAuthError, TrustedOriginPolicy> =>
  request.headers.origin === undefined
    ? Effect.void
    : Effect.gen(function* () {
        const origin = yield* Effect.try({
          try: () => new URL(request.headers.origin ?? ""),
          catch: () => unauthorized,
        });
        yield* checkTrustedOrigin(origin);
      });

const validateAuthHttpConfigOrigin = (
  value: string,
  config: AuthHttpConfigShape,
): Effect.Effect<void, AuthHttpError> =>
  value === "null"
    ? Effect.fail(AuthHttpError.Unauthorized())
    : Effect.gen(function* () {
        const origin = yield* Effect.try({
          try: () => new URL(value),
          catch: () => AuthHttpError.Unauthorized(),
        });
        if (!config.trustedOrigins.has(origin.origin)) {
          return yield* Effect.fail(AuthHttpError.Unauthorized());
        }
      });

const checkAuthHttpConfigRequestOrigin: (
  request: HttpServerRequest.HttpServerRequest,
) => Effect.Effect<void, AuthHttpError, AuthHttpConfig> = Effect.fn(
  "checkAuthHttpConfigRequestOrigin",
)(function* (request) {
  const config = yield* AuthHttpConfig;
  const origin = Option.fromUndefinedOr(request.headers.origin);
  if (Option.isSome(origin)) {
    return yield* validateAuthHttpConfigOrigin(origin.value, config);
  }

  const sessionCookie = Option.fromUndefinedOr(request.cookies[config.sessionCookieName]);
  if (Option.isNone(sessionCookie)) return;

  const referer = Option.fromUndefinedOr(request.headers.referer);
  if (Option.isNone(referer)) return yield* Effect.fail(AuthHttpError.Unauthorized());
  yield* validateAuthHttpConfigOrigin(referer.value, config);
});

export const StateChangingRequest = {
  check: checkAuthHttpConfigRequestOrigin,
};

export const TrustedOrigins = (origins: ReadonlyArray<URL>) => {
  const allowed = new Set(origins.map((origin) => origin.origin));
  return Layer.succeed(TrustedOriginPolicy)({
    isTrusted: (origin) => Effect.succeed(allowed.has(origin.origin)),
  });
};

const OptionalString = Schema.optional(Schema.String);

const SignUpEmailPayload = Schema.Struct({
  email: Schema.Unknown,
  password: Schema.Unknown,
  verificationCallbackUrl: Schema.URLFromString,
  ip: OptionalString,
});

const VerifyEmailPayload = Schema.Struct({
  token: Schema.String,
});

const ResendVerificationPayload = Schema.Struct({
  email: Schema.Unknown,
  verificationCallbackUrl: Schema.URLFromString,
  ip: OptionalString,
});

const SignInEmailPayload = Schema.Struct({
  email: Schema.Unknown,
  password: Schema.Unknown,
  ip: OptionalString,
});

const MountedSignInEmailPayload = Schema.Struct({
  email: Schema.Unknown,
  password: Schema.Unknown,
});

export type AuthHttpSession = Omit<StoredSession, "tokenHash">;

export interface AuthHttpSignInResponse {
  readonly user: AuthUser;
  readonly session: AuthHttpSession;
}

export interface AuthHttpUserResponse {
  readonly user: AuthUser;
}

export interface AuthHttpSessionResponse {
  readonly user: AuthUser;
  readonly session: AuthHttpSession;
}

export interface AuthHttpListSessionsResponse {
  readonly sessions: ReadonlyArray<ListedSession>;
}

export interface AuthHttpOkResponse {
  readonly ok: true;
}

const SessionTokenPayload = Schema.Struct({
  sessionToken: Schema.String,
});

const CurrentSessionQuery = Schema.Struct({
  sessionToken: Schema.String,
});

const RequestPasswordResetPayload = Schema.Struct({
  email: Schema.Unknown,
  resetCallbackUrl: Schema.URLFromString,
  ip: OptionalString,
});

const CompletePasswordResetPayload = Schema.Struct({
  token: Schema.String,
  password: Schema.Unknown,
});

const ChangePasswordPayload = Schema.Struct({
  sessionToken: Schema.String,
  currentPassword: Schema.Unknown,
  newPassword: Schema.Unknown,
  ip: OptionalString,
});

const MountedChangePasswordPayload = Schema.Struct({
  currentPassword: Schema.Unknown,
  newPassword: Schema.Unknown,
});

const RevokeListedSessionPayload = Schema.Struct({
  sessionId: Schema.String,
});

const AuthApiGroup = HttpApiGroup.make("auth").add(
  HttpApiEndpoint.post("signUpEmail", "/auth/sign-up/email", {
    payload: SignUpEmailPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("verifyEmail", "/auth/verify-email", {
    payload: VerifyEmailPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("resendVerification", "/auth/resend-verification", {
    payload: ResendVerificationPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("signInEmail", "/auth/sign-in/email", {
    payload: SignInEmailPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.get("currentSession", "/auth/session", {
    query: CurrentSessionQuery,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("signOut", "/auth/sign-out", {
    payload: SessionTokenPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("requestPasswordReset", "/auth/password-reset/request", {
    payload: RequestPasswordResetPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("completePasswordReset", "/auth/password-reset/complete", {
    payload: CompletePasswordResetPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("changePassword", "/auth/password/change", {
    payload: ChangePasswordPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.get("listSessions", "/auth/sessions", {
    query: SessionTokenPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("revokeSession", "/auth/sessions/revoke", {
    payload: Schema.Struct({
      sessionToken: Schema.String,
      sessionId: Schema.String,
    }),
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("revokeOtherSessions", "/auth/sessions/revoke-others", {
    payload: SessionTokenPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
  HttpApiEndpoint.post("revokeSessions", "/auth/sessions/revoke-all", {
    payload: SessionTokenPayload,
    success: Schema.Unknown,
    error: Schema.Unknown,
  }),
);

export const AuthApi = HttpApi.make("auth").add(AuthApiGroup);

export const AuthApiEndpoints: ReadonlyArray<readonly [string, string]> = [
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
];

export const AuthHttpAdapter = Effect.gen(function* () {
  const emailPassword = yield* EmailPasswordWorkflows;
  const sessions = yield* SessionWorkflows;
  const recovery = yield* PasswordRecoveryWorkflows;
  return {
    signUpEmail: emailPassword.signUp,
    verifyEmail: emailPassword.verifyEmail,
    resendVerification: emailPassword.resendVerification,
    signInEmail: (input: SignInInput) =>
      Effect.gen(function* () {
        const result = yield* emailPassword.signIn(input);
        yield* SessionCookie.appendFromConfig(result.sessionToken);
        return result;
      }),
    currentSession: (input: { readonly sessionToken: SessionTokenValue }) =>
      Effect.gen(function* () {
        const result = yield* sessions.currentSession(input);
        if (Predicate.isTagged(result.tokenRotation, "Rotated")) {
          yield* SessionCookie.appendFromConfig(result.tokenRotation.token);
        }
        return result;
      }),
    signOut: (input: { readonly sessionToken: SessionTokenValue }) =>
      Effect.gen(function* () {
        yield* sessions.signOut(input);
        yield* SessionCookie.appendClearFromConfig;
        return null;
      }),
    listSessions: sessions.listSessions,
    revokeSession: sessions.revokeSession,
    revokeOtherSessions: sessions.revokeOtherSessions,
    revokeSessions: sessions.revokeSessions,
    requestPasswordReset: recovery.requestPasswordReset,
    completePasswordReset: recovery.resetPassword,
    changePassword: (input: ChangePasswordInput) =>
      Effect.gen(function* () {
        const result = yield* recovery.changePassword(input);
        yield* SessionCookie.appendFromConfig(result.currentSessionToken);
        return result;
      }),
  };
});

const decodeVerificationToken = Schema.decodeUnknownEffect(VerificationToken);

const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);

const decodeMountedSignInEmailPayload = Schema.decodeUnknownEffect(MountedSignInEmailPayload);
const decodeMountedChangePasswordPayload = Schema.decodeUnknownEffect(MountedChangePasswordPayload);

const parseOptionalClientIp = (value: string | undefined): Effect.Effect<ClientIp | undefined> =>
  value === undefined
    ? Effect.void.pipe(Effect.as(undefined))
    : parseClientIp(value).pipe(Effect.option, Effect.map(Option.getOrUndefined));

const signUpInput = Effect.fn("signUpInput")(function* (payload: typeof SignUpEmailPayload.Type) {
  const ip = yield* parseOptionalClientIp(payload.ip);
  return {
    email: payload.email,
    password: payload.password,
    verificationCallbackUrl: payload.verificationCallbackUrl,
    ...(ip === undefined ? {} : { ip }),
  };
});

const resendVerificationInput = Effect.fn("resendVerificationInput")(function* (
  payload: typeof ResendVerificationPayload.Type,
) {
  const ip = yield* parseOptionalClientIp(payload.ip);
  return {
    email: payload.email,
    verificationCallbackUrl: payload.verificationCallbackUrl,
    ...(ip === undefined ? {} : { ip }),
  };
});

const signInInput = Effect.fn("signInInput")(function* (payload: typeof SignInEmailPayload.Type) {
  const ip = yield* parseOptionalClientIp(payload.ip);
  return {
    email: payload.email,
    password: payload.password,
    ...(ip === undefined ? {} : { ip }),
  };
});

const trustedRequestIp = (
  request: HttpServerRequest.HttpServerRequest,
): Effect.Effect<ClientIp | undefined> => {
  const forwarded = request.headers["x-forwarded-for"];
  if (forwarded !== undefined && forwarded.trim() !== "") {
    return parseOptionalClientIp(forwarded.split(",")[0]?.trim());
  }
  const realIp = request.headers["x-real-ip"];
  return parseOptionalClientIp(
    realIp === undefined || realIp.trim() === "" ? undefined : realIp.trim(),
  );
};

const mountedSignInInput = Effect.fn("mountedSignInInput")(function* (
  payload: typeof MountedSignInEmailPayload.Type,
  request: HttpServerRequest.HttpServerRequest,
) {
  const ip = yield* trustedRequestIp(request);
  return {
    email: payload.email,
    password: payload.password,
    ...(ip === undefined ? {} : { ip }),
  };
});

const requestPasswordResetInput = Effect.fn("requestPasswordResetInput")(function* (
  payload: typeof RequestPasswordResetPayload.Type,
) {
  const ip = yield* parseOptionalClientIp(payload.ip);
  return {
    email: payload.email,
    resetCallbackUrl: payload.resetCallbackUrl,
    ...(ip === undefined ? {} : { ip }),
  };
});

const changePasswordInput = Effect.fn("changePasswordInput")(function* (
  payload: typeof ChangePasswordPayload.Type,
  sessionToken: SessionTokenValue,
) {
  const ip = yield* parseOptionalClientIp(payload.ip);
  return {
    sessionToken,
    currentPassword: payload.currentPassword,
    newPassword: payload.newPassword,
    ...(ip === undefined ? {} : { ip }),
  };
});

export const handleSignUpEmail = Effect.fn("handleSignUpEmail")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof SignUpEmailPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const input = yield* signUpInput(payload);
  return yield* adapter.signUpEmail(input);
});

export const handleVerifyEmail = Effect.fn("handleVerifyEmail")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof VerifyEmailPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const token = yield* decodeVerificationToken(payload.token);
  return yield* adapter.verifyEmail({ token });
});

const handleResendVerification = Effect.fn("handleResendVerification")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof ResendVerificationPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const input = yield* resendVerificationInput(payload);
  return yield* adapter.resendVerification(input);
});

export const handleSignInEmail = Effect.fn("handleSignInEmail")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof SignInEmailPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const input = yield* signInInput(payload);
  return yield* adapter.signInEmail(input);
});

const handleMountedSignInEmail = (request: HttpServerRequest.HttpServerRequest) =>
  Effect.gen(function* () {
    yield* checkAuthHttpConfigRequestOrigin(request);
    const payload = yield* request.json.pipe(Effect.flatMap(decodeMountedSignInEmailPayload));
    const auth = yield* Auth;
    const config = yield* AuthHttpConfig;
    const input = yield* mountedSignInInput(payload, request);
    const result = yield* auth.signIn(input);
    const body: AuthHttpSignInResponse = {
      user: result.user,
      session: authHttpSession(result.session),
    };
    return jsonWithCookieInstruction(body, sessionCookieFromConfig(result.sessionToken, config));
  }).pipe(Effect.catch((error) => authHttpErrorResponse(toAuthHttpError(error))));

const mountedJson = (body: unknown): HttpServerResponse.HttpServerResponse =>
  HttpServerResponse.jsonUnsafe(body);

const mountedErrorBoundary = <A, E, R>(self: Effect.Effect<A, E, R>) =>
  self.pipe(Effect.catch((error) => authHttpErrorResponse(toAuthHttpError(error))));

const extractMountedSessionToken = Effect.fn("extractMountedSessionToken")(function* () {
  const config = yield* AuthHttpConfig;
  const extractor = Option.getOrElse(config.defaultTokenExtractor, () => AuthHttpToken.cookie);
  const extracted = yield* extractor.extract;
  return yield* Match.valueTags(extracted, {
    Missing: () => Effect.fail(AuthHttpError.MissingSessionToken()),
    Invalid: () => Effect.fail(AuthHttpError.InvalidSessionToken()),
    Found: (found) => Effect.succeed(found),
  });
});

const handleMountedSignUpEmail = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const payload = yield* request.json.pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(SignUpEmailPayload)),
      );
      const auth = yield* Auth;
      const input = yield* signUpInput(payload);
      const result = yield* auth.signUp(input);
      return mountedJson({ user: result.user } satisfies AuthHttpUserResponse);
    }),
  );

const handleMountedVerifyEmail = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const payload = yield* request.json.pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(VerifyEmailPayload)),
      );
      const token = yield* decodeVerificationToken(payload.token);
      const auth = yield* Auth;
      const result = yield* auth.verifyEmail({ token });
      return mountedJson({ user: result.user } satisfies AuthHttpUserResponse);
    }),
  );

const handleMountedResendVerification = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const payload = yield* request.json.pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(ResendVerificationPayload)),
      );
      const auth = yield* Auth;
      const input = yield* resendVerificationInput(payload);
      yield* auth.resendVerification(input);
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

const handleMountedCurrentSession = (_request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      const config = yield* AuthHttpConfig;
      const extracted = yield* extractMountedSessionToken();
      const auth = yield* Auth;
      const current = yield* auth
        .currentSession({ sessionToken: extracted.token })
        .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
      if (extracted.source === "Cookie" && Predicate.isTagged(current.tokenRotation, "Rotated")) {
        yield* appendCookieInstruction(
          sessionCookieFromConfig(current.tokenRotation.token, config),
        );
      }
      return mountedJson({
        user: current.user,
        session: authHttpSession(current.session),
      } satisfies AuthHttpSessionResponse);
    }),
  );

const handleMountedListSessions = (_request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      const config = yield* AuthHttpConfig;
      const extracted = yield* extractMountedSessionToken();
      const auth = yield* Auth;
      const listed = yield* auth
        .listSessions({ sessionToken: extracted.token })
        .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
      if (extracted.source === "Cookie" && Predicate.isTagged(listed.tokenRotation, "Rotated")) {
        yield* appendCookieInstruction(sessionCookieFromConfig(listed.tokenRotation.token, config));
      }
      return mountedJson({
        sessions: listed.sessions,
      } satisfies AuthHttpListSessionsResponse);
    }),
  );

const handleMountedSignOut = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const config = yield* AuthHttpConfig;
      const extracted = yield* extractMountedSessionToken();
      const auth = yield* Auth;
      const signOut = auth
        .signOut({ sessionToken: extracted.token })
        .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
      if (extracted.source === "Cookie") {
        yield* signOut.pipe(
          Effect.catch((error) =>
            appendCookieInstruction(clearSessionCookieFromConfig(config)).pipe(
              Effect.flatMap(() => Effect.fail(error)),
            ),
          ),
        );
      } else {
        yield* signOut;
      }
      yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

const handleMountedRevokeSession = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const config = yield* AuthHttpConfig;
      const payload = yield* request.json.pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(RevokeListedSessionPayload)),
      );
      const extracted = yield* extractMountedSessionToken();
      const auth = yield* Auth;
      yield* auth
        .revokeSession({ sessionToken: extracted.token, sessionId: payload.sessionId })
        .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
      if (extracted.source === "Cookie") {
        const current = yield* Effect.option(
          auth.currentSession({ sessionToken: extracted.token }),
        );
        if (Option.isNone(current)) {
          yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
        }
      }
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

const handleMountedRevokeOtherSessions = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const extracted = yield* extractMountedSessionToken();
      const auth = yield* Auth;
      yield* auth
        .revokeOtherSessions({ sessionToken: extracted.token })
        .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

const handleMountedRevokeSessions = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const config = yield* AuthHttpConfig;
      const extracted = yield* extractMountedSessionToken();
      const auth = yield* Auth;
      yield* auth
        .revokeSessions({ sessionToken: extracted.token })
        .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
      if (extracted.source === "Cookie") {
        yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
      }
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

const handleMountedRequestPasswordReset = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const payload = yield* request.json.pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(RequestPasswordResetPayload)),
      );
      const auth = yield* Auth;
      const input = yield* requestPasswordResetInput(payload);
      yield* auth.requestPasswordReset(input);
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

const handleMountedCompletePasswordReset = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const payload = yield* request.json.pipe(
        Effect.flatMap(Schema.decodeUnknownEffect(CompletePasswordResetPayload)),
      );
      const token = yield* decodeVerificationToken(payload.token);
      const auth = yield* Auth;
      yield* auth.resetPassword({ token, password: payload.password });
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

const handleMountedChangePassword = (request: HttpServerRequest.HttpServerRequest) =>
  mountedErrorBoundary(
    Effect.gen(function* () {
      yield* checkAuthHttpConfigRequestOrigin(request);
      const config = yield* AuthHttpConfig;
      const payload = yield* request.json.pipe(Effect.flatMap(decodeMountedChangePasswordPayload));
      const extracted = yield* extractMountedSessionToken();
      const auth = yield* Auth;
      const ip = yield* trustedRequestIp(request);
      const result = yield* auth.changePassword({
        sessionToken: extracted.token,
        currentPassword: payload.currentPassword,
        newPassword: payload.newPassword,
        ...(ip === undefined ? {} : { ip }),
      });
      if (extracted.source === "Cookie") {
        yield* appendCookieInstruction(sessionCookieFromConfig(result.currentSessionToken, config));
      }
      return mountedJson({ ok: true } satisfies AuthHttpOkResponse);
    }),
  );

export interface AuthHttpRequireAuthOptions {
  readonly extractor?: AuthHttpTokenExtractor;
}

export interface AuthHttpOptionalAuthOptions {
  readonly extractor?: AuthHttpTokenExtractor;
}

const isRequireAuthOptions = (input: unknown): input is AuthHttpRequireAuthOptions =>
  !Effect.isEffect(input);

const isOptionalAuthOptions = (input: unknown): input is AuthHttpOptionalAuthOptions =>
  !Effect.isEffect(input);

const configuredTokenExtractor = (
  options: AuthHttpRequireAuthOptions | undefined,
  config: AuthHttpConfigShape,
): AuthHttpTokenExtractor =>
  options?.extractor ?? Option.getOrElse(config.defaultTokenExtractor, () => AuthHttpToken.cookie);

const resolveAuthSession = Effect.fn("resolveAuthSession")(function* (
  options?: AuthHttpRequireAuthOptions,
) {
  const config = yield* AuthHttpConfig;
  const extractor = configuredTokenExtractor(options, config);
  const extracted = yield* extractor.extract;
  return yield* Match.valueTags(extracted, {
    Missing: () => Effect.fail(AuthHttpError.MissingSessionToken()),
    Invalid: () => Effect.fail(AuthHttpError.InvalidSessionToken()),
    Found: (found) =>
      Effect.gen(function* () {
        const auth = yield* Auth;
        const current = yield* auth
          .currentSession({ sessionToken: found.token })
          .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
        if (Predicate.isTagged(current.tokenRotation, "Rotated") && found.source === "Cookie") {
          yield* appendCookieInstruction(
            sessionCookieFromConfig(current.tokenRotation.token, config),
          );
        }
        return { user: current.user, session: current.session };
      }),
  });
});

const currentSessionFromToken: (token: SessionTokenValue) => Effect.Effect<
  {
    readonly authSession: AuthSessionShape;
    readonly tokenRotation: TokenRotationDecision;
  },
  AuthHttpError,
  Auth
> = Effect.fn("currentSessionFromToken")(function* (token) {
  const auth = yield* Auth;
  const current = yield* auth
    .currentSession({ sessionToken: token })
    .pipe(Effect.mapError(() => AuthHttpError.InvalidSessionToken()));
  return {
    authSession: { user: current.user, session: current.session },
    tokenRotation: current.tokenRotation,
  };
});

const resolveOptionalAuthSession = Effect.fn("resolveOptionalAuthSession")(function* (
  options?: AuthHttpOptionalAuthOptions,
) {
  const config = yield* AuthHttpConfig;
  const extractor = configuredTokenExtractor(options, config);

  if (extractor === AuthHttpToken.cookieOrBearer) {
    const bearer = yield* AuthHttpToken.bearer.extract;
    const bearerSession = yield* Match.valueTags(bearer, {
      Found: (found) =>
        currentSessionFromToken(found.token).pipe(
          Effect.option,
          Effect.map((session) => Option.map(session, (_) => _.authSession)),
        ),
      Invalid: () => Effect.succeed(Option.none<AuthSessionShape>()),
      Missing: () => Effect.succeed(Option.none<AuthSessionShape>()),
    });
    if (Option.isSome(bearerSession)) return bearerSession;

    const cookie = yield* AuthHttpToken.cookie.extract;
    return yield* Match.valueTags(cookie, {
      Missing: () => Effect.succeed(Option.none<AuthSessionShape>()),
      Invalid: () =>
        Effect.gen(function* () {
          yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
          return Option.none<AuthSessionShape>();
        }),
      Found: (found) =>
        Effect.gen(function* () {
          const cookieSession = yield* Effect.option(currentSessionFromToken(found.token));
          if (Option.isNone(cookieSession)) {
            yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
          } else if (Predicate.isTagged(cookieSession.value.tokenRotation, "Rotated")) {
            yield* appendCookieInstruction(
              sessionCookieFromConfig(cookieSession.value.tokenRotation.token, config),
            );
          }
          return Option.map(cookieSession, (_) => _.authSession);
        }),
    });
  }

  const extracted = yield* extractor.extract;
  return yield* Match.valueTags(extracted, {
    Missing: () => Effect.succeed(Option.none<AuthSessionShape>()),
    Invalid: (invalid) =>
      Effect.gen(function* () {
        if (invalid.source === "Cookie") {
          yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
        }
        return Option.none<AuthSessionShape>();
      }),
    Found: (found) =>
      Effect.gen(function* () {
        const session = yield* Effect.option(currentSessionFromToken(found.token));
        if (Option.isNone(session) && found.source === "Cookie") {
          yield* appendCookieInstruction(clearSessionCookieFromConfig(config));
        } else if (
          Option.isSome(session) &&
          found.source === "Cookie" &&
          Predicate.isTagged(session.value.tokenRotation, "Rotated")
        ) {
          yield* appendCookieInstruction(
            sessionCookieFromConfig(session.value.tokenRotation.token, config),
          );
        }
        return Option.map(session, (_) => _.authSession);
      }),
  });
});

const requireAuthEffect = <A, E, R>(
  self: Effect.Effect<A, E, R>,
  options?: AuthHttpRequireAuthOptions,
) =>
  resolveAuthSession(options).pipe(
    Effect.flatMap((session) => Effect.provideService(self, AuthSession, session)),
  );

type RuntimeEffect<R> = Effect.Effect<unknown, unknown, R>;

type RequireAuthResult<I> =
  I extends Effect.Effect<infer A, infer E, infer R>
    ? Effect.Effect<
        A,
        E | AuthHttpError,
        Exclude<R, AuthSession> | Auth | AuthHttpConfig | HttpServerRequest.HttpServerRequest
      >
    : I extends AuthHttpRequireAuthOptions
      ? <A, E, R>(
          self: Effect.Effect<A, E, R>,
        ) => Effect.Effect<
          A,
          E | AuthHttpError,
          Exclude<R, AuthSession> | Auth | AuthHttpConfig | HttpServerRequest.HttpServerRequest
        >
      : never;

export function requireAuth<R, I extends AuthHttpRequireAuthOptions | RuntimeEffect<R>>(
  input: I,
): RequireAuthResult<I>;
export function requireAuth(input: unknown): unknown {
  if (Effect.isEffect(input)) {
    return requireAuthEffect(input);
  }
  if (isRequireAuthOptions(input)) {
    return <A, E, R>(self: Effect.Effect<A, E, R>) => requireAuthEffect(self, input);
  }
}

const optionalAuthEffect = <A, E, R>(
  self: Effect.Effect<A, E, R>,
  options?: AuthHttpOptionalAuthOptions,
) =>
  resolveOptionalAuthSession(options).pipe(
    Effect.flatMap((session) =>
      Effect.provideService(self, CurrentAuthSession, { current: session }),
    ),
  );

type OptionalAuthResult<I> =
  I extends Effect.Effect<infer A, infer E, infer R>
    ? Effect.Effect<
        A,
        E,
        Exclude<R, CurrentAuthSession> | Auth | AuthHttpConfig | HttpServerRequest.HttpServerRequest
      >
    : I extends AuthHttpOptionalAuthOptions
      ? <A, E, R>(
          self: Effect.Effect<A, E, R>,
        ) => Effect.Effect<
          A,
          E,
          | Exclude<R, CurrentAuthSession>
          | Auth
          | AuthHttpConfig
          | HttpServerRequest.HttpServerRequest
        >
      : never;

export function optionalAuth<R, I extends AuthHttpOptionalAuthOptions | RuntimeEffect<R>>(
  input: I,
): OptionalAuthResult<I>;
export function optionalAuth(input: unknown): unknown {
  if (Effect.isEffect(input)) {
    return optionalAuthEffect(input);
  }
  if (isOptionalAuthOptions(input)) {
    return <A, E, R>(self: Effect.Effect<A, E, R>) => optionalAuthEffect(self, input);
  }
}

export const handleCurrentSession = Effect.fn("handleCurrentSession")(function* ({
  query,
}: {
  readonly query: typeof CurrentSessionQuery.Type;
}) {
  const adapter = yield* AuthHttpAdapter;
  const sessionToken = yield* decodeSessionToken(query.sessionToken);
  return yield* adapter.currentSession({ sessionToken });
});

export const handleSignOut = Effect.fn("handleSignOut")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof SessionTokenPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const sessionToken = yield* decodeSessionToken(payload.sessionToken);
  return yield* adapter.signOut({ sessionToken });
});

export const handleListSessions = Effect.fn("handleListSessions")(function* ({
  query,
}: {
  readonly query: typeof SessionTokenPayload.Type;
}) {
  const adapter = yield* AuthHttpAdapter;
  const sessionToken = yield* decodeSessionToken(query.sessionToken);
  return yield* adapter.listSessions({ sessionToken });
});

export const handleRevokeSession = Effect.fn("handleRevokeSession")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof RevokeListedSessionPayload.Type & { readonly sessionToken: string };
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const sessionToken = yield* decodeSessionToken(payload.sessionToken);
  return yield* adapter.revokeSession({ sessionToken, sessionId: payload.sessionId });
});

export const handleRevokeOtherSessions = Effect.fn("handleRevokeOtherSessions")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof SessionTokenPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const sessionToken = yield* decodeSessionToken(payload.sessionToken);
  return yield* adapter.revokeOtherSessions({ sessionToken });
});

export const handleRevokeSessions = Effect.fn("handleRevokeSessions")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof SessionTokenPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const sessionToken = yield* decodeSessionToken(payload.sessionToken);
  return yield* adapter.revokeSessions({ sessionToken });
});

export const handleRequestPasswordReset = Effect.fn("handleRequestPasswordReset")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof RequestPasswordResetPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const input = yield* requestPasswordResetInput(payload);
  return yield* adapter.requestPasswordReset(input);
});

export const handleCompletePasswordReset = Effect.fn("handleCompletePasswordReset")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof CompletePasswordResetPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const token = yield* decodeVerificationToken(payload.token);
  return yield* adapter.completePasswordReset({ token, password: payload.password });
});

export const handleChangePassword = Effect.fn("handleChangePassword")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof ChangePasswordPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  const sessionToken = yield* decodeSessionToken(payload.sessionToken);
  const input = yield* changePasswordInput(payload, sessionToken);
  return yield* adapter.changePassword(input);
});

export const AuthHttpHandlersLive = HttpApiBuilder.group(AuthApi, "auth", (handlers) =>
  handlers
    .handle("signUpEmail", handleSignUpEmail)
    .handle("verifyEmail", handleVerifyEmail)
    .handle("resendVerification", handleResendVerification)
    .handle("signInEmail", handleSignInEmail)
    .handle("currentSession", handleCurrentSession)
    .handle("signOut", handleSignOut)
    .handle("requestPasswordReset", handleRequestPasswordReset)
    .handle("completePasswordReset", handleCompletePasswordReset)
    .handle("changePassword", handleChangePassword)
    .handle("listSessions", handleListSessions)
    .handle("revokeSession", handleRevokeSession)
    .handle("revokeOtherSessions", handleRevokeOtherSessions)
    .handle("revokeSessions", handleRevokeSessions),
);

export interface AuthHttpMountOptions {
  readonly basePath: `/${string}`;
}

const mountedPath = (basePath: `/${string}`, path: `/${string}`): `/${string}` =>
  `${basePath}${path}`;

export const AuthHttp = {
  requireAuth,
  optionalAuth,
  mount:
    (options: AuthHttpMountOptions) =>
    <A, E, R>(self: Layer.Layer<A, E, R>) =>
      Layer.mergeAll(
        self,
        HttpRouter.add("POST", mountedPath(options.basePath, "/sign-up/email"), (request) =>
          handleMountedSignUpEmail(request),
        ),
        HttpRouter.add("POST", mountedPath(options.basePath, "/verify-email"), (request) =>
          handleMountedVerifyEmail(request),
        ),
        HttpRouter.add("POST", mountedPath(options.basePath, "/resend-verification"), (request) =>
          handleMountedResendVerification(request),
        ),
        HttpRouter.add("POST", mountedPath(options.basePath, "/sign-in/email"), (request) =>
          handleMountedSignInEmail(request),
        ),
        HttpRouter.add("GET", mountedPath(options.basePath, "/session"), (request) =>
          handleMountedCurrentSession(request),
        ),
        HttpRouter.add("GET", mountedPath(options.basePath, "/sessions"), (request) =>
          handleMountedListSessions(request),
        ),
        HttpRouter.add("POST", mountedPath(options.basePath, "/sign-out"), (request) =>
          handleMountedSignOut(request),
        ),
        HttpRouter.add("POST", mountedPath(options.basePath, "/sessions/revoke"), (request) =>
          handleMountedRevokeSession(request),
        ),
        HttpRouter.add(
          "POST",
          mountedPath(options.basePath, "/sessions/revoke-others"),
          (request) => handleMountedRevokeOtherSessions(request),
        ),
        HttpRouter.add("POST", mountedPath(options.basePath, "/sessions/revoke-all"), (request) =>
          handleMountedRevokeSessions(request),
        ),
        HttpRouter.add(
          "POST",
          mountedPath(options.basePath, "/password-reset/request"),
          (request) => handleMountedRequestPasswordReset(request),
        ),
        HttpRouter.add(
          "POST",
          mountedPath(options.basePath, "/password-reset/complete"),
          (request) => handleMountedCompletePasswordReset(request),
        ),
        HttpRouter.add("POST", mountedPath(options.basePath, "/password/change"), (request) =>
          handleMountedChangePassword(request),
        ),
      ),
};
