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
  rateLimited,
  unauthorized,
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
  type RequestPasswordResetInput,
  type ResetPasswordInput,
  type ResendVerificationInput,
  type SignInInput,
  type SignUpInput,
  type TokenRotationDecision,
  type VerifyEmailInput,
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
  readonly trustedOrigins: ReadonlyArray<string | URL>;
  readonly sessionCookieName?: string;
  readonly sessionCookiePath?: string;
  readonly secureCookies?: boolean;
  readonly defaultTokenExtractor?: AuthHttpTokenExtractor;
  readonly baseUrl?: URL;
}

export interface AuthHttpConfigShape {
  readonly trustedOrigins: ReadonlySet<string>;
  readonly sessionCookieName: string;
  readonly sessionCookiePath: string;
  readonly secureCookies: boolean;
  readonly defaultTokenExtractor?: AuthHttpTokenExtractor;
}

const deriveSecureCookies = (input: AuthHttpConfigInput): boolean => {
  if (input.secureCookies !== undefined) return input.secureCookies;
  if (input.baseUrl !== undefined) {
    if (input.baseUrl.protocol === "https:") return true;
    if (input.baseUrl.hostname === "localhost" || input.baseUrl.hostname === "127.0.0.1") {
      return false;
    }
  }
  return process.env.NODE_ENV === "production";
};

const makeAuthHttpConfig = (input: AuthHttpConfigInput): AuthHttpConfigShape => ({
  trustedOrigins: new Set(
    input.trustedOrigins.map((origin) =>
      origin instanceof URL ? origin.origin : new URL(origin).origin,
    ),
  ),
  sessionCookieName: input.sessionCookieName ?? "effect_auth_session",
  sessionCookiePath: input.sessionCookiePath ?? "/",
  secureCookies: deriveSecureCookies(input),
  ...(input.defaultTokenExtractor === undefined
    ? {}
    : { defaultTokenExtractor: input.defaultTokenExtractor }),
});

export class AuthHttpConfig extends Context.Service<AuthHttpConfig, AuthHttpConfigShape>()(
  "effect-auth/http/AuthHttpConfig",
) {
  static readonly layer = (input: AuthHttpConfigInput): Layer.Layer<AuthHttpConfig> =>
    Layer.succeed(AuthHttpConfig)(makeAuthHttpConfig(input));
}

export interface AuthSessionShape {
  readonly user: AuthUser;
  readonly session: StoredSession;
}

export class AuthSession extends Context.Service<AuthSession, AuthSessionShape>()(
  "effect-auth/http/AuthSession",
) {}

export class CurrentAuthSession extends Context.Service<
  CurrentAuthSession,
  Option.Option<AuthSessionShape>
>()("effect-auth/http/CurrentAuthSession") {}

export type SessionTokenExtractResult = Data.TaggedEnum<{
  Missing: {};
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
        Effect.catch(() => Effect.succeed(SessionTokenExtractResult.Missing())),
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
      Missing: () => cookieTokenExtractor.extract,
    });
  }),
};

export const AuthHttpToken = {
  cookie: cookieTokenExtractor,
  bearer: bearerTokenExtractor,
  cookieOrBearer: cookieOrBearerTokenExtractor,
};

export interface TrustedOriginPolicyShape {
  readonly isTrusted: (origin: URL) => Effect.Effect<boolean>;
}

export class TrustedOriginPolicy extends Context.Service<
  TrustedOriginPolicy,
  TrustedOriginPolicyShape
>()("effect-auth/http/TrustedOriginPolicy") {}

export interface SessionCookieOptions {
  readonly name?: string;
  readonly secure?: boolean;
  readonly path?: string;
}

export interface CookieInstruction {
  readonly name: string;
  readonly value: string;
  readonly httpOnly: true;
  readonly sameSite: "Lax";
  readonly path: string;
  readonly secure: boolean;
  readonly maxAge?: number;
}

export const makeSessionCookie = (
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

export const clearSessionCookie = (options: SessionCookieOptions = {}): CookieInstruction => ({
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

export const applyCookieInstruction = (
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

export const appendCookieInstruction = (instruction: CookieInstruction) =>
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

const authHttpSession = (session: StoredSession): AuthHttpSession => {
  const { tokenHash: _tokenHash, ...publicSession } = session;
  return publicSession;
};

export interface AuthHttpAdapterShape {
  readonly signUpEmail: (input: SignUpInput) => Effect.Effect<unknown>;
  readonly verifyEmail: (input: VerifyEmailInput) => Effect.Effect<unknown>;
  readonly resendVerification: (input: ResendVerificationInput) => Effect.Effect<unknown>;
  readonly signInEmail: (input: SignInInput) => Effect.Effect<unknown>;
  readonly currentSession: (input: {
    readonly sessionToken: SessionTokenValue;
  }) => Effect.Effect<unknown>;
  readonly signOut: (input: {
    readonly sessionToken: SessionTokenValue;
  }) => Effect.Effect<{ readonly clearCookie: CookieInstruction }>;
  readonly requestPasswordReset: (input: RequestPasswordResetInput) => Effect.Effect<unknown>;
  readonly completePasswordReset: (input: ResetPasswordInput) => Effect.Effect<unknown>;
  readonly changePassword: (input: ChangePasswordInput) => Effect.Effect<unknown>;
}

export const checkTrustedOrigin = (
  origin: URL,
): Effect.Effect<void, PublicAuthError, TrustedOriginPolicy> =>
  Effect.fn("checkTrustedOrigin")(function* () {
    const policy = yield* TrustedOriginPolicy;
    const trusted = yield* policy.isTrusted(origin);
    if (!trusted) return yield* unauthorized;
  })();

export interface OriginRequest {
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

export const checkAuthHttpConfigRequestOrigin = (
  request: OriginRequest,
): Effect.Effect<void, AuthHttpError, AuthHttpConfig> =>
  request.headers.origin === undefined
    ? Effect.void
    : Effect.gen(function* () {
        const config = yield* AuthHttpConfig;
        const origin = yield* Effect.try({
          try: () => new URL(request.headers.origin ?? ""),
          catch: () => AuthHttpError.Unauthorized(),
        });
        if (!config.trustedOrigins.has(origin.origin)) {
          return yield* Effect.fail(AuthHttpError.Unauthorized());
        }
      });

export const TrustedOrigins = (origins: ReadonlyArray<string | URL>) => {
  const allowed = new Set(
    origins.map((origin) => (origin instanceof URL ? origin.origin : new URL(origin).origin)),
  );
  return Layer.succeed(TrustedOriginPolicy)({
    isTrusted: (origin) => Effect.succeed(allowed.has(origin.origin)),
  });
};

const OptionalString = Schema.optional(Schema.String);

export const SignUpEmailPayload = Schema.Struct({
  email: Schema.Unknown,
  password: Schema.Unknown,
  verificationCallbackUrl: Schema.URLFromString,
  ip: OptionalString,
});

export const VerifyEmailPayload = Schema.Struct({
  token: Schema.String,
});

export const ResendVerificationPayload = Schema.Struct({
  email: Schema.Unknown,
  verificationCallbackUrl: Schema.URLFromString,
  ip: OptionalString,
});

export const SignInEmailPayload = Schema.Struct({
  email: Schema.Unknown,
  password: Schema.Unknown,
  ip: OptionalString,
});

export const MountedSignInEmailPayload = Schema.Struct({
  email: Schema.Unknown,
  password: Schema.Unknown,
});

export type AuthHttpSession = Omit<StoredSession, "tokenHash">;

export interface AuthHttpSignInResponse {
  readonly user: AuthUser;
  readonly session: AuthHttpSession;
}

export const SessionTokenPayload = Schema.Struct({
  sessionToken: Schema.String,
});

export const CurrentSessionQuery = Schema.Struct({
  sessionToken: Schema.String,
});

export const RequestPasswordResetPayload = Schema.Struct({
  email: Schema.Unknown,
  resetCallbackUrl: Schema.URLFromString,
  ip: OptionalString,
});

export const CompletePasswordResetPayload = Schema.Struct({
  token: Schema.String,
  password: Schema.Unknown,
});

export const ChangePasswordPayload = Schema.Struct({
  sessionToken: Schema.String,
  currentPassword: Schema.Unknown,
  newPassword: Schema.Unknown,
  ip: OptionalString,
});

export const AuthApiGroup = HttpApiGroup.make("auth").add(
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
        yield* appendCookieInstruction(makeSessionCookie(result.sessionToken));
        return result;
      }),
    currentSession: (input: { readonly sessionToken: SessionTokenValue }) =>
      Effect.gen(function* () {
        const result = yield* sessions.currentSession(input);
        if (Predicate.isTagged(result.tokenRotation, "Rotated")) {
          yield* appendCookieInstruction(makeSessionCookie(result.tokenRotation.token));
        }
        return result;
      }),
    signOut: (input: { readonly sessionToken: SessionTokenValue }) =>
      Effect.gen(function* () {
        yield* sessions.signOut(input);
        yield* appendCookieInstruction(clearSessionCookie());
        return null;
      }),
    requestPasswordReset: recovery.requestPasswordReset,
    completePasswordReset: recovery.resetPassword,
    changePassword: (input: ChangePasswordInput) =>
      Effect.gen(function* () {
        const result = yield* recovery.changePassword(input);
        yield* appendCookieInstruction(makeSessionCookie(result.currentSessionToken));
        return result;
      }),
  };
});

const decodeVerificationToken = Schema.decodeUnknownEffect(VerificationToken);

const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);

const decodeMountedSignInEmailPayload = Schema.decodeUnknownEffect(MountedSignInEmailPayload);

const signUpInput = (payload: typeof SignUpEmailPayload.Type): SignUpInput => ({
  email: payload.email,
  password: payload.password,
  verificationCallbackUrl: payload.verificationCallbackUrl,
  ...(payload.ip === undefined ? {} : { ip: payload.ip }),
});

const resendVerificationInput = (
  payload: typeof ResendVerificationPayload.Type,
): ResendVerificationInput => ({
  email: payload.email,
  verificationCallbackUrl: payload.verificationCallbackUrl,
  ...(payload.ip === undefined ? {} : { ip: payload.ip }),
});

const signInInput = (payload: typeof SignInEmailPayload.Type): SignInInput => ({
  email: payload.email,
  password: payload.password,
  ...(payload.ip === undefined ? {} : { ip: payload.ip }),
});

const trustedRequestIp = (request: HttpServerRequest.HttpServerRequest): string | undefined => {
  const forwarded = request.headers["x-forwarded-for"];
  if (forwarded !== undefined && forwarded.trim() !== "") {
    return forwarded.split(",")[0]?.trim();
  }
  const realIp = request.headers["x-real-ip"];
  return realIp === undefined || realIp.trim() === "" ? undefined : realIp.trim();
};

const mountedSignInInput = (
  payload: typeof MountedSignInEmailPayload.Type,
  request: HttpServerRequest.HttpServerRequest,
): SignInInput => {
  const ip = trustedRequestIp(request);
  return {
    email: payload.email,
    password: payload.password,
    ...(ip === undefined ? {} : { ip }),
  };
};

const requestPasswordResetInput = (
  payload: typeof RequestPasswordResetPayload.Type,
): RequestPasswordResetInput => ({
  email: payload.email,
  resetCallbackUrl: payload.resetCallbackUrl,
  ...(payload.ip === undefined ? {} : { ip: payload.ip }),
});

const changePasswordInput = (
  payload: typeof ChangePasswordPayload.Type,
  sessionToken: SessionTokenValue,
): ChangePasswordInput => ({
  sessionToken,
  currentPassword: payload.currentPassword,
  newPassword: payload.newPassword,
  ...(payload.ip === undefined ? {} : { ip: payload.ip }),
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
  return yield* adapter.signUpEmail(signUpInput(payload));
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

export const handleResendVerification = Effect.fn("handleResendVerification")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof ResendVerificationPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  return yield* adapter.resendVerification(resendVerificationInput(payload));
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
  return yield* adapter.signInEmail(signInInput(payload));
});

export const handleMountedSignInEmail = (request: HttpServerRequest.HttpServerRequest) =>
  Effect.gen(function* () {
    yield* checkAuthHttpConfigRequestOrigin(request);
    const payload = yield* request.json.pipe(Effect.flatMap(decodeMountedSignInEmailPayload));
    const auth = yield* Auth;
    const config = yield* AuthHttpConfig;
    const result = yield* auth.signIn(mountedSignInInput(payload, request));
    const body: AuthHttpSignInResponse = {
      user: result.user,
      session: authHttpSession(result.session),
    };
    return jsonWithCookieInstruction(body, sessionCookieFromConfig(result.sessionToken, config));
  }).pipe(
    Effect.catch((error) => authHttpErrorResponse(toAuthHttpError(error))),
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
): AuthHttpTokenExtractor => options?.extractor ?? config.defaultTokenExtractor ?? AuthHttpToken.cookie;

const resolveAuthSession = Effect.fn("resolveAuthSession")(function* (
  options?: AuthHttpRequireAuthOptions,
) {
    const config = yield* AuthHttpConfig;
    const extractor = configuredTokenExtractor(options, config);
    const extracted = yield* extractor.extract;
    return yield* Match.valueTags(extracted, {
      Missing: () => Effect.fail(AuthHttpError.MissingSessionToken()),
      Found: (found) =>
        Effect.gen(function* () {
        const auth = yield* Auth;
        const current = yield* auth.currentSession({ sessionToken: found.token }).pipe(
          Effect.mapError(() => AuthHttpError.InvalidSessionToken()),
        );
        if (Predicate.isTagged(current.tokenRotation, "Rotated") && found.source === "Cookie") {
          yield* appendCookieInstruction(sessionCookieFromConfig(current.tokenRotation.token, config));
        }
        return { user: current.user, session: current.session };
      }),
    });
  });

const currentSessionFromToken: (
  token: SessionTokenValue,
) => Effect.Effect<
  {
    readonly authSession: AuthSessionShape;
    readonly tokenRotation: TokenRotationDecision;
  },
  AuthHttpError,
  Auth
> = Effect.fn("currentSessionFromToken")(function* (token) {
    const auth = yield* Auth;
    const current = yield* auth.currentSession({ sessionToken: token }).pipe(
      Effect.mapError(() => AuthHttpError.InvalidSessionToken()),
    );
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
        Missing: () => Effect.succeed(Option.none<AuthSessionShape>()),
      });
      if (Option.isSome(bearerSession)) return bearerSession;

      const cookie = yield* AuthHttpToken.cookie.extract;
      return yield* Match.valueTags(cookie, {
        Missing: () => Effect.succeed(Option.none<AuthSessionShape>()),
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

type RequireAuthResult<I> = I extends Effect.Effect<infer A, infer E, infer R> ? Effect.Effect<
    A,
    E | AuthHttpError,
    Exclude<R, AuthSession> | Auth | AuthHttpConfig | HttpServerRequest.HttpServerRequest
  >
  : I extends AuthHttpRequireAuthOptions ? <A, E, R>(
  self: Effect.Effect<A, E, R>,
) => Effect.Effect<
  A,
  E | AuthHttpError,
  Exclude<R, AuthSession> | Auth | AuthHttpConfig | HttpServerRequest.HttpServerRequest
>
  : never;

export function requireAuth<
  I extends AuthHttpRequireAuthOptions | Effect.Effect<unknown, unknown, unknown>,
>(
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
    Effect.flatMap((session) => Effect.provideService(self, CurrentAuthSession, session)),
  );

type OptionalAuthResult<I> = I extends Effect.Effect<infer A, infer E, infer R> ? Effect.Effect<
    A,
    E,
    Exclude<R, CurrentAuthSession> | Auth | AuthHttpConfig | HttpServerRequest.HttpServerRequest
  >
  : I extends AuthHttpOptionalAuthOptions ? <A, E, R>(
  self: Effect.Effect<A, E, R>,
) => Effect.Effect<
  A,
  E,
  Exclude<R, CurrentAuthSession> | Auth | AuthHttpConfig | HttpServerRequest.HttpServerRequest
>
  : never;

export function optionalAuth<
  I extends AuthHttpOptionalAuthOptions | Effect.Effect<unknown, unknown, unknown>,
>(
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

export const handleRequestPasswordReset = Effect.fn("handleRequestPasswordReset")(function* ({
  payload,
  request,
}: {
  readonly payload: typeof RequestPasswordResetPayload.Type;
  readonly request: OriginRequest;
}) {
  yield* checkTrustedRequestOrigin(request);
  const adapter = yield* AuthHttpAdapter;
  return yield* adapter.requestPasswordReset(requestPasswordResetInput(payload));
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
  return yield* adapter.changePassword(changePasswordInput(payload, sessionToken));
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
    .handle("changePassword", handleChangePassword),
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
        HttpRouter.add("POST", mountedPath(options.basePath, "/sign-in/email"), (request) =>
          handleMountedSignInEmail(request),
        ),
      ),
};
