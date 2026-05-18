import { Context, Data, Effect, Layer, Match, Option, Predicate, Redacted, Schema } from "effect";
import type * as FileSystem from "effect/FileSystem";
import type * as Path from "effect/Path";
import type { unhandled } from "effect/Types";
import type * as Etag from "effect/unstable/http/Etag";
import * as Headers from "effect/unstable/http/Headers";
import * as HttpEffect from "effect/unstable/http/HttpEffect";
import type * as HttpPlatform from "effect/unstable/http/HttpPlatform";
import type * as HttpRouter from "effect/unstable/http/HttpRouter";
import * as HttpServerRequest from "effect/unstable/http/HttpServerRequest";
import * as HttpServerResponse from "effect/unstable/http/HttpServerResponse";
import * as UrlParams from "effect/unstable/http/UrlParams";
import {
  HttpApi,
  HttpApiBuilder,
  HttpApiEndpoint,
  HttpApiGroup,
  HttpApiMiddleware,
  HttpApiSchema,
  HttpApiSecurity,
} from "effect/unstable/httpapi";
import { Auth } from "../auth.js";
import type { PublicAuthError } from "../domain/index.js";
import { OAuth } from "../oauth/index.js";
import { RateLimitExceeded } from "../rate-limit/index.js";
import type { AuthUser, PublicAuthAccount, StoredSession } from "../storage/index.js";
import { SessionToken, type SessionToken as SessionTokenValue } from "../token/index.js";
import type { ListedSession, TokenRotationDecision } from "../workflows/index.js";

const tokenResponseHeader = "set-auth-token";
const defaultBasePath = "/auth";
const defaultSessionCookieName = "effect_auth_session";

export class AuthHttpUser extends Schema.Class<AuthHttpUser>("AuthHttpUser")({
  id: Schema.String,
  email: Schema.String,
  name: Schema.String,
  image: Schema.NullOr(Schema.String),
  emailVerified: Schema.Boolean,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
}) {}

export class AuthHttpSession extends Schema.Class<AuthHttpSession>("AuthHttpSession")({
  id: Schema.String,
  userId: Schema.String,
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
  expiresAt: Schema.Number,
  revokedAt: Schema.optionalKey(Schema.Number),
  ipAddress: Schema.optionalKey(Schema.String),
  userAgent: Schema.optionalKey(Schema.String),
}) {}

export class AuthHttpListedSession extends AuthHttpSession.extend<AuthHttpListedSession>(
  "AuthHttpListedSession",
)({
  isCurrent: Schema.Boolean,
}) {}

export class AuthHttpAccount extends Schema.Class<AuthHttpAccount>("AuthHttpAccount")({
  id: Schema.String,
  providerId: Schema.String,
  accountId: Schema.String,
  userId: Schema.String,
  scopes: Schema.Array(Schema.String),
  createdAt: Schema.Number,
  updatedAt: Schema.Number,
}) {}

export class AuthHttpSessionResponse extends Schema.Class<AuthHttpSessionResponse>(
  "AuthHttpSessionResponse",
)({
  user: AuthHttpUser,
  session: AuthHttpSession,
}) {}

export class AuthHttpUserResponse extends Schema.Class<AuthHttpUserResponse>(
  "AuthHttpUserResponse",
)({
  user: AuthHttpUser,
}) {}

export class AuthHttpListSessionsResponse extends Schema.Class<AuthHttpListSessionsResponse>(
  "AuthHttpListSessionsResponse",
)({
  sessions: Schema.Array(AuthHttpListedSession),
}) {}

export class AuthHttpListAccountsResponse extends Schema.Class<AuthHttpListAccountsResponse>(
  "AuthHttpListAccountsResponse",
)({
  accounts: Schema.Array(AuthHttpAccount),
}) {}

export class AuthHttpOkResponse extends Schema.Class<AuthHttpOkResponse>("AuthHttpOkResponse")({
  ok: Schema.Literal(true),
}) {}

export const AuthHttpCurrentSessionResponse = Schema.NullOr(AuthHttpSessionResponse);

export class AuthHttpBadRequest extends Schema.TaggedErrorClass<AuthHttpBadRequest>()(
  "AuthHttpBadRequest",
  {
    code: Schema.String,
    message: Schema.String,
  },
) {}

export class AuthHttpUnauthorized extends Schema.TaggedErrorClass<AuthHttpUnauthorized>()(
  "AuthHttpUnauthorized",
  {
    code: Schema.String,
    message: Schema.String,
  },
) {}

export class AuthHttpForbidden extends Schema.TaggedErrorClass<AuthHttpForbidden>()(
  "AuthHttpForbidden",
  {
    code: Schema.String,
    message: Schema.String,
  },
) {}

export class AuthHttpRateLimited extends Schema.TaggedErrorClass<AuthHttpRateLimited>()(
  "AuthHttpRateLimited",
  {
    code: Schema.String,
    message: Schema.String,
    retryAfterMillis: Schema.optionalKey(Schema.Number),
  },
) {}

export const AuthHttpBadRequestSchema = AuthHttpBadRequest.pipe(HttpApiSchema.status("BadRequest"));
export const AuthHttpUnauthorizedSchema = AuthHttpUnauthorized.pipe(
  HttpApiSchema.status("Unauthorized"),
);
export const AuthHttpForbiddenSchema = AuthHttpForbidden.pipe(HttpApiSchema.status("Forbidden"));
export const AuthHttpRateLimitedSchema = AuthHttpRateLimited.pipe(
  HttpApiSchema.status("TooManyRequests"),
);
export const AuthHttpErrors = [
  AuthHttpBadRequestSchema,
  AuthHttpUnauthorizedSchema,
  AuthHttpForbiddenSchema,
  AuthHttpRateLimitedSchema,
];

export class AuthHttpConfigError extends Schema.TaggedErrorClass<AuthHttpConfigError>()(
  "AuthHttpConfigError",
  {
    field: Schema.String,
    reason: Schema.String,
  },
) {}

export class AuthHttpSignUpEmailPayload extends Schema.Class<AuthHttpSignUpEmailPayload>(
  "AuthHttpSignUpEmailPayload",
)({
  email: Schema.String,
  password: Schema.String,
  name: Schema.String,
  verificationCallbackUrl: Schema.String,
  ip: Schema.optionalKey(Schema.String),
}) {}

export class AuthHttpVerifyEmailPayload extends Schema.Class<AuthHttpVerifyEmailPayload>(
  "AuthHttpVerifyEmailPayload",
)({
  token: Schema.String,
}) {}

export class AuthHttpResendVerificationPayload extends Schema.Class<AuthHttpResendVerificationPayload>(
  "AuthHttpResendVerificationPayload",
)({
  email: Schema.String,
  verificationCallbackUrl: Schema.String,
  ip: Schema.optionalKey(Schema.String),
}) {}

export class AuthHttpSignInEmailPayload extends Schema.Class<AuthHttpSignInEmailPayload>(
  "AuthHttpSignInEmailPayload",
)({
  email: Schema.String,
  password: Schema.String,
  ip: Schema.optionalKey(Schema.String),
}) {}

export class AuthHttpRequestPasswordResetPayload extends Schema.Class<AuthHttpRequestPasswordResetPayload>(
  "AuthHttpRequestPasswordResetPayload",
)({
  email: Schema.String,
  resetCallbackUrl: Schema.String,
  ip: Schema.optionalKey(Schema.String),
}) {}

export class AuthHttpCompletePasswordResetPayload extends Schema.Class<AuthHttpCompletePasswordResetPayload>(
  "AuthHttpCompletePasswordResetPayload",
)({
  token: Schema.String,
  password: Schema.String,
}) {}

export class AuthHttpChangePasswordPayload extends Schema.Class<AuthHttpChangePasswordPayload>(
  "AuthHttpChangePasswordPayload",
)({
  currentPassword: Schema.String,
  newPassword: Schema.String,
  ip: Schema.optionalKey(Schema.String),
}) {}

export class AuthHttpDeleteUserPayload extends Schema.Class<AuthHttpDeleteUserPayload>(
  "AuthHttpDeleteUserPayload",
)({
  password: Schema.String,
  ip: Schema.optionalKey(Schema.String),
}) {}

export class AuthHttpUpdateUserPayload extends Schema.Class<AuthHttpUpdateUserPayload>(
  "AuthHttpUpdateUserPayload",
)({
  name: Schema.optionalKey(Schema.String),
  image: Schema.optionalKey(Schema.NullOr(Schema.String)),
}) {}

export class AuthHttpRevokeSessionPayload extends Schema.Class<AuthHttpRevokeSessionPayload>(
  "AuthHttpRevokeSessionPayload",
)({
  sessionId: Schema.String,
}) {}

export class AuthHttpOAuthStartSignInPayload extends Schema.Class<AuthHttpOAuthStartSignInPayload>(
  "AuthHttpOAuthStartSignInPayload",
)({
  providerId: Schema.String,
  scopes: Schema.optionalKey(Schema.Array(Schema.String)),
  allowSignUp: Schema.optionalKey(Schema.Boolean),
}) {}

export class AuthHttpOAuthStartLinkPayload extends Schema.Class<AuthHttpOAuthStartLinkPayload>(
  "AuthHttpOAuthStartLinkPayload",
)({
  providerId: Schema.String,
  scopes: Schema.optionalKey(Schema.Array(Schema.String)),
}) {}

export class AuthHttpOAuthAuthorizationUrlResponse extends Schema.Class<AuthHttpOAuthAuthorizationUrlResponse>(
  "AuthHttpOAuthAuthorizationUrlResponse",
)({
  authorizationUrl: Schema.String,
}) {}

const OAuthCallbackParams = Schema.Struct({ providerId: Schema.String });

export interface AuthHttpConfigureInput {
  readonly basePath?: string;
  readonly sessionCookieName?: string;
  readonly cookieAndBearer?: boolean;
  readonly oauth?: boolean;
}

export interface AuthHttpRuntimeInput {
  readonly baseUrl: URL;
  readonly trustedOrigins?: ReadonlyArray<URL>;
  readonly cookies?: {
    readonly secure?: boolean;
    readonly path?: string;
    readonly domain?: string;
    readonly sameSite?: "lax" | "strict" | "none";
    readonly partitioned?: boolean;
  };
  readonly oauth?: {
    readonly signInSuccessPath?: string;
    readonly linkSuccessPath?: string;
    readonly errorPath?: string;
  };
}

interface AuthHttpContractConfig {
  readonly basePath: `/${string}`;
  readonly sessionCookieName: string;
  readonly cookieAndBearer: boolean;
  readonly oauth: boolean;
}

export class AuthHttpRuntimeConfig extends Context.Service<
  AuthHttpRuntimeConfig,
  {
    readonly contract: AuthHttpContractConfig;
    readonly baseUrl: URL;
    readonly trustedOrigins: ReadonlySet<string>;
    readonly cookies: {
      readonly secure: boolean;
      readonly path: string;
      readonly domain?: string;
      readonly sameSite: "lax" | "strict" | "none";
      readonly partitioned?: boolean;
    };
    readonly oauth: {
      readonly signInSuccessPath: string;
      readonly linkSuccessPath: string;
      readonly errorPath: string;
    };
  }
>()("effect-auth/http/AuthHttpRuntimeConfig") {}

type AuthHttpRuntimeConfigShape = typeof AuthHttpRuntimeConfig.Service;

export type AuthHttpCredentialSource = "Cookie" | "Bearer";

export type AuthHttpTokenRotation = Data.TaggedEnum<{
  Unchanged: {};
  Rotated: { readonly token: SessionTokenValue };
}>;
export const AuthHttpTokenRotation = Data.taggedEnum<AuthHttpTokenRotation>();

export type AuthHttpCredentialResolution = Data.TaggedEnum<{
  Missing: {};
  Invalid: { readonly attempted: ReadonlyArray<AuthHttpCredentialSource> };
  Authenticated: {
    readonly source: AuthHttpCredentialSource;
    readonly user: AuthHttpUser;
    readonly session: AuthHttpSession;
    readonly rotation: AuthHttpTokenRotation;
  };
}>;
export const AuthHttpCredentialResolution = Data.taggedEnum<AuthHttpCredentialResolution>();

interface AuthenticatedCredential {
  readonly source: AuthHttpCredentialSource;
  readonly sessionToken: SessionTokenValue;
  readonly user: AuthHttpUser;
  readonly session: AuthHttpSession;
  readonly rotation: AuthHttpTokenRotation;
}

type AuthHttpCredentialContextResolution = Data.TaggedEnum<{
  Missing: {};
  Invalid: { readonly attempted: ReadonlyArray<AuthHttpCredentialSource> };
  Authenticated: AuthenticatedCredential;
}>;
const AuthHttpCredentialContextResolution = Data.taggedEnum<AuthHttpCredentialContextResolution>();

export class AuthHttpSessionContext extends Context.Service<
  AuthHttpSessionContext,
  {
    readonly user: AuthHttpUser;
    readonly session: AuthHttpSession;
  }
>()("effect-auth/http/AuthHttpSessionContext") {}

export class AuthHttpOptionalSessionContext extends Context.Service<
  AuthHttpOptionalSessionContext,
  {
    readonly session: Option.Option<{
      readonly user: AuthHttpUser;
      readonly session: AuthHttpSession;
    }>;
  }
>()("effect-auth/http/AuthHttpOptionalSessionContext") {}

class AuthHttpSelectedCredentialContext extends Context.Service<
  AuthHttpSelectedCredentialContext,
  {
    readonly source: AuthHttpCredentialSource;
    readonly sessionToken: SessionTokenValue;
    readonly user: AuthHttpUser;
    readonly session: AuthHttpSession;
    readonly rotation: AuthHttpTokenRotation;
  }
>()("effect-auth/http/internal/AuthHttpSelectedCredentialContext") {}

export type AuthHttpSelectedCredential = Data.TaggedEnum<{
  Anonymous: {};
  Cookie: {};
  Bearer: {};
}>;
export const AuthHttpSelectedCredential = Data.taggedEnum<AuthHttpSelectedCredential>();

export class AuthHttpCredentialResolver extends Context.Service<
  AuthHttpCredentialResolver,
  {
    readonly resolveRequired: Effect.Effect<
      AuthHttpCredentialResolution,
      AuthHttpUnauthorized,
      HttpServerRequest.HttpServerRequest
    >;
    readonly resolveOptional: Effect.Effect<
      AuthHttpCredentialResolution,
      never,
      HttpServerRequest.HttpServerRequest
    >;
    readonly resolveRequiredContext: Effect.Effect<
      AuthenticatedCredential,
      AuthHttpUnauthorized,
      HttpServerRequest.HttpServerRequest
    >;
    readonly resolveOptionalContext: Effect.Effect<
      AuthHttpCredentialContextResolution,
      never,
      HttpServerRequest.HttpServerRequest
    >;
    readonly resolveRaw: (input: {
      readonly source: AuthHttpCredentialSource;
      readonly value: string;
    }) => Effect.Effect<AuthenticatedCredential, AuthHttpUnauthorized>;
  }
>()("effect-auth/http/AuthHttpCredentialResolver") {}

export type AuthHttpCredentialMaintenance = Data.TaggedEnum<{
  None: {};
  IssueCookie: { readonly token: SessionTokenValue };
  ClearCookie: {};
  IssueBearer: { readonly token: SessionTokenValue };
}>;
export const AuthHttpCredentialMaintenance = Data.taggedEnum<AuthHttpCredentialMaintenance>();

export class AuthHttpCredentialRenderer extends Context.Service<
  AuthHttpCredentialRenderer,
  {
    readonly tokenResponseHeader: typeof tokenResponseHeader;
    readonly render: (
      instruction: AuthHttpCredentialMaintenance,
    ) => Effect.Effect<void, never, HttpServerRequest.HttpServerRequest>;
    readonly apply: (
      response: HttpServerResponse.HttpServerResponse,
      instruction: AuthHttpCredentialMaintenance,
    ) => HttpServerResponse.HttpServerResponse;
  }
>()("effect-auth/http/AuthHttpCredentialRenderer") {}

export class AuthHttpUrlPolicy extends Context.Service<
  AuthHttpUrlPolicy,
  {
    readonly isTrustedOrigin: (origin: URL) => Effect.Effect<boolean>;
    readonly validatePublicStateChange: (
      request: HttpServerRequest.HttpServerRequest,
    ) => Effect.Effect<void, AuthHttpForbidden>;
    readonly validateProtectedStateChange: (input: {
      readonly request: HttpServerRequest.HttpServerRequest;
      readonly credential: AuthHttpSelectedCredential;
    }) => Effect.Effect<void, AuthHttpForbidden>;
    readonly validateCallbackUrl: (
      value: string,
    ) => Effect.Effect<string, AuthHttpForbidden | AuthHttpBadRequest>;
    readonly resolveCallbackUrl: (
      value: string,
    ) => Effect.Effect<URL, AuthHttpForbidden | AuthHttpBadRequest>;
    readonly validateOAuthRedirectPath: (
      value: string,
    ) => Effect.Effect<string, AuthHttpConfigError>;
  }
>()("effect-auth/http/AuthHttpUrlPolicy") {}

class AuthHttpSchemaErrorMiddleware extends HttpApiMiddleware.Service<AuthHttpSchemaErrorMiddleware>()(
  "effect-auth/http/AuthHttpSchemaErrorMiddleware",
  { error: AuthHttpErrors },
) {}

const AuthHttpSchemaErrorLayer = HttpApiMiddleware.layerSchemaErrorTransform(
  AuthHttpSchemaErrorMiddleware,
  () => Effect.fail(new AuthHttpBadRequest({ code: "BadRequest", message: "Invalid request" })),
);

const toAuthHttpUser = (user: AuthUser): AuthHttpUser =>
  new AuthHttpUser({
    id: user.id,
    email: String(user.email),
    name: user.name,
    image: user.image,
    emailVerified: user.emailVerified,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  });

const toAuthHttpSession = (session: StoredSession): AuthHttpSession =>
  new AuthHttpSession({
    id: session.id,
    userId: session.userId,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    expiresAt: session.expiresAt,
    ...(session.revokedAt === undefined ? {} : { revokedAt: session.revokedAt }),
    ...(session.ipAddress === undefined ? {} : { ipAddress: session.ipAddress }),
    ...(session.userAgent === undefined ? {} : { userAgent: session.userAgent }),
  });

const toAuthHttpListedSession = (session: ListedSession): AuthHttpListedSession =>
  new AuthHttpListedSession({
    id: session.id,
    userId: session.userId,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    expiresAt: session.expiresAt,
    isCurrent: session.isCurrent,
    ...(session.ipAddress === undefined ? {} : { ipAddress: session.ipAddress }),
    ...(session.userAgent === undefined ? {} : { userAgent: session.userAgent }),
  });

const toAuthHttpAccount = (account: PublicAuthAccount): AuthHttpAccount =>
  new AuthHttpAccount({
    id: account.id,
    providerId: String(account.providerId),
    accountId: account.accountId,
    userId: account.userId,
    scopes: [...account.scopes],
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  });

const toSessionResponse = (input: {
  readonly user: AuthUser;
  readonly session: StoredSession;
}): AuthHttpSessionResponse =>
  new AuthHttpSessionResponse({
    user: toAuthHttpUser(input.user),
    session: toAuthHttpSession(input.session),
  });

const okResponse = new AuthHttpOkResponse({ ok: true });

const badRequest = (code: string, message: string) => new AuthHttpBadRequest({ code, message });
const unauthorizedError = (code = "Unauthorized", message = "Unauthorized") =>
  new AuthHttpUnauthorized({ code, message });
const forbidden = (code: string, message: string) => new AuthHttpForbidden({ code, message });

const isAuthHttpBadRequest = Schema.is(AuthHttpBadRequest);
const isAuthHttpUnauthorized = Schema.is(AuthHttpUnauthorized);
const isAuthHttpForbidden = Schema.is(AuthHttpForbidden);
const isAuthHttpRateLimited = Schema.is(AuthHttpRateLimited);
const isRateLimitExceeded = Schema.is(RateLimitExceeded);

const publicAuthErrorCode = (error: unknown): PublicAuthError["code"] | undefined =>
  Predicate.hasProperty(error, "code") && typeof error.code === "string"
    ? error.code === "InvalidCredentials" ||
      error.code === "EmailNotVerified" ||
      error.code === "InvalidToken" ||
      error.code === "RateLimited" ||
      error.code === "Unauthorized"
      ? error.code
      : undefined
    : undefined;

const authHttpError = (
  error: unknown,
): AuthHttpBadRequest | AuthHttpUnauthorized | AuthHttpForbidden | AuthHttpRateLimited => {
  if (isAuthHttpBadRequest(error)) return error;
  if (isAuthHttpUnauthorized(error)) return error;
  if (isAuthHttpForbidden(error)) return error;
  if (isAuthHttpRateLimited(error)) return error;
  if (isRateLimitExceeded(error)) {
    return new AuthHttpRateLimited({
      code: "RateLimited",
      message: "Too many attempts",
      retryAfterMillis: error.retryAfterMillis,
    });
  }
  const code = publicAuthErrorCode(error);
  if (code === "RateLimited") {
    return new AuthHttpRateLimited({ code: "RateLimited", message: "Too many attempts" });
  }
  if (code === "Unauthorized") return unauthorizedError();
  if (code === "EmailNotVerified") return badRequest("EmailNotVerified", "Email is not verified");
  if (code === "InvalidToken") return badRequest("InvalidToken", "Invalid token");
  if (code === "InvalidCredentials") return badRequest("InvalidCredentials", "Invalid credentials");
  if (Predicate.isTagged(error, "BoundaryParseError")) {
    const reason =
      Predicate.hasProperty(error, "reason") && typeof error.reason === "string"
        ? error.reason
        : "Invalid request body";
    return badRequest("BadRequest", reason);
  }
  if (
    Predicate.isTagged(error, "OAuthStartError") ||
    Predicate.isTagged(error, "OAuthProviderNotFound")
  ) {
    return badRequest("InvalidOAuthStart", "Invalid OAuth start request");
  }
  if (Predicate.isTagged(error, "AuthStorageFailure")) {
    return badRequest("AuthStorageFailure", "Authentication storage operation failed");
  }
  return badRequest("BadRequest", "Authentication request failed");
};

const withAuthHttpErrors = <A, E, R>(self: Effect.Effect<A, E, R>) =>
  self.pipe(Effect.mapError(authHttpError));

const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);

const isBasePath = (value: string): value is `/${string}` =>
  value.startsWith("/") && !value.startsWith("//");

const failConfigure = (field: string, reason: string): never =>
  Effect.runSync(Effect.fail(new AuthHttpConfigError({ field, reason })));

const normalizeBasePath = (value: string | undefined): `/${string}` => {
  const path = value ?? defaultBasePath;
  const normalized = path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
  if (isBasePath(normalized)) return normalized;
  return failConfigure("basePath", "AuthHttp.configure: basePath must start with a single slash");
};

const cookieNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const cookiePathPattern = /^\/[\u0020-\u003a\u003c-\u007e]*$/u;
const oauthRedirectPathPattern = /^\/(?!\/)[!-~]*$/u;

const parseSessionCookieName = (value: string | undefined): string => {
  const name = value ?? defaultSessionCookieName;
  if (name.length > 0 && cookieNamePattern.test(name)) return name;
  return failConfigure("sessionCookieName", "AuthHttp.configure: invalid sessionCookieName");
};

const parseCookiePath = (value: string | undefined): Effect.Effect<string, AuthHttpConfigError> =>
  value === undefined
    ? Effect.succeed("/")
    : cookiePathPattern.test(value)
      ? Effect.succeed(value)
      : Effect.fail(
          new AuthHttpConfigError({ field: "cookies.path", reason: "Invalid cookie path" }),
        );

const validateOAuthRedirectPath = (value: string): Effect.Effect<string, AuthHttpConfigError> =>
  oauthRedirectPathPattern.test(value)
    ? Effect.succeed(value)
    : Effect.fail(
        new AuthHttpConfigError({ field: "oauth.redirectPath", reason: "Expected relative path" }),
      );

const makeRuntimeConfig: (
  contract: AuthHttpContractConfig,
  input: AuthHttpRuntimeInput,
) => Effect.Effect<AuthHttpRuntimeConfigShape, AuthHttpConfigError> = Effect.fn(
  "AuthHttp.makeRuntimeConfig",
)(function* (contract, input) {
  const baseUrl = input.baseUrl;
  if (!(baseUrl instanceof URL)) {
    return yield* new AuthHttpConfigError({ field: "baseUrl", reason: "Expected URL" });
  }
  const path = yield* parseCookiePath(input.cookies?.path);
  const trustedOrigins = new Set<string>([baseUrl.origin]);
  for (const origin of input.trustedOrigins ?? []) {
    if (!(origin instanceof URL)) {
      return yield* new AuthHttpConfigError({
        field: "trustedOrigins",
        reason: "Expected URL",
      });
    }
    trustedOrigins.add(origin.origin);
  }
  return {
    contract,
    baseUrl,
    trustedOrigins,
    cookies: {
      secure: input.cookies?.secure ?? baseUrl.protocol === "https:",
      path,
      ...(input.cookies?.domain === undefined ? {} : { domain: input.cookies.domain }),
      sameSite: input.cookies?.sameSite ?? "lax",
      ...(input.cookies?.partitioned === undefined
        ? {}
        : { partitioned: input.cookies.partitioned }),
    },
    oauth: {
      signInSuccessPath: yield* validateOAuthRedirectPath(input.oauth?.signInSuccessPath ?? "/"),
      linkSuccessPath: yield* validateOAuthRedirectPath(
        input.oauth?.linkSuccessPath ?? "/settings/accounts",
      ),
      errorPath: yield* validateOAuthRedirectPath(input.oauth?.errorPath ?? "/auth/error"),
    },
  };
});

const makeCookieOptions = (
  config: AuthHttpRuntimeConfigShape,
  clear: boolean,
): {
  readonly httpOnly: true;
  readonly secure: boolean;
  readonly path: string;
  readonly sameSite: "lax" | "strict" | "none";
  readonly domain?: string;
  readonly partitioned?: boolean;
  readonly maxAge?: number;
} => ({
  httpOnly: true,
  secure: config.cookies.secure,
  path: config.cookies.path,
  sameSite: config.cookies.sameSite,
  ...(config.cookies.domain === undefined ? {} : { domain: config.cookies.domain }),
  ...(config.cookies.partitioned === undefined ? {} : { partitioned: config.cookies.partitioned }),
  ...(clear ? { maxAge: 0 } : {}),
});

const applyCookie = (
  response: HttpServerResponse.HttpServerResponse,
  config: AuthHttpRuntimeConfigShape,
  token: SessionTokenValue,
): HttpServerResponse.HttpServerResponse =>
  HttpServerResponse.setCookieUnsafe(
    response,
    config.contract.sessionCookieName,
    Redacted.value(token),
    makeCookieOptions(config, false),
  );

const applyClearCookie = (
  response: HttpServerResponse.HttpServerResponse,
  config: AuthHttpRuntimeConfigShape,
): HttpServerResponse.HttpServerResponse =>
  HttpServerResponse.setCookieUnsafe(
    response,
    config.contract.sessionCookieName,
    "",
    makeCookieOptions(config, true),
  );

const appendExposeHeader = (response: HttpServerResponse.HttpServerResponse) => {
  const current = Option.getOrUndefined(
    Headers.get(response.headers, "access-control-expose-headers"),
  );
  const values = (current ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
  const hasTokenHeader = values.some((value) => value.toLowerCase() === tokenResponseHeader);
  const next = hasTokenHeader ? values : [...values, tokenResponseHeader];
  return HttpServerResponse.setHeader(response, "access-control-expose-headers", next.join(", "));
};

const applyMaintenance = (
  response: HttpServerResponse.HttpServerResponse,
  config: AuthHttpRuntimeConfigShape,
  instruction: AuthHttpCredentialMaintenance,
): HttpServerResponse.HttpServerResponse =>
  Match.valueTags(instruction, {
    None: () => response,
    IssueCookie: (instruction) => applyCookie(response, config, instruction.token),
    ClearCookie: () => applyClearCookie(response, config),
    IssueBearer: (instruction) =>
      appendExposeHeader(
        HttpServerResponse.setHeader(
          response,
          tokenResponseHeader,
          Redacted.value(instruction.token),
        ),
      ),
  });

const makeCredentialRendererLayer = Layer.effect(
  AuthHttpCredentialRenderer,
  Effect.gen(function* () {
    const config = yield* AuthHttpRuntimeConfig;
    const service: typeof AuthHttpCredentialRenderer.Service = {
      tokenResponseHeader,
      render: (instruction: AuthHttpCredentialMaintenance) =>
        HttpEffect.appendPreResponseHandler((_request, response) =>
          Effect.succeed(applyMaintenance(response, config, instruction)),
        ),
      apply: (
        response: HttpServerResponse.HttpServerResponse,
        instruction: AuthHttpCredentialMaintenance,
      ) => applyMaintenance(response, config, instruction),
    };
    return service;
  }).pipe(Effect.annotateLogs({ service: "AuthHttpCredentialRenderer" })),
);

const tokenRotation = (rotation: TokenRotationDecision): AuthHttpTokenRotation =>
  Predicate.isTagged(rotation, "Rotated")
    ? AuthHttpTokenRotation.Rotated({ token: rotation.token })
    : AuthHttpTokenRotation.Unchanged();

const maintenanceForRotation = (
  source: AuthHttpCredentialSource,
  rotation: AuthHttpTokenRotation,
): AuthHttpCredentialMaintenance =>
  Match.valueTags(rotation, {
    Unchanged: () => AuthHttpCredentialMaintenance.None(),
    Rotated: ({ token }) =>
      source === "Cookie"
        ? AuthHttpCredentialMaintenance.IssueCookie({ token })
        : AuthHttpCredentialMaintenance.IssueBearer({ token }),
  });

const rotationFromContextOrResult = (
  context: AuthenticatedCredential,
  rotation: TokenRotationDecision,
): AuthHttpTokenRotation => {
  const resultRotation = tokenRotation(rotation);
  return Predicate.isTagged(resultRotation, "Rotated") ? resultRotation : context.rotation;
};

const bearerTokenValue = (authorization: string | undefined): string | undefined => {
  if (authorization === undefined) return undefined;
  const prefix = "Bearer ";
  return authorization.startsWith(prefix) ? authorization.slice(prefix.length).trim() : undefined;
};

type ParsedCredential = Data.TaggedEnum<{
  Missing: {};
  Invalid: {};
  Found: { readonly token: SessionTokenValue };
}>;
const ParsedCredential = Data.taggedEnum<ParsedCredential>();

const missingCredential = (): ParsedCredential => ParsedCredential.Missing();
const invalidCredential = (): ParsedCredential => ParsedCredential.Invalid();
const foundCredential = (token: SessionTokenValue): ParsedCredential =>
  ParsedCredential.Found({ token });

const parseCredential = (value: string | undefined): Effect.Effect<ParsedCredential> =>
  value === undefined || value === ""
    ? Effect.succeed(missingCredential())
    : decodeSessionToken(value).pipe(
        Effect.match({
          onFailure: invalidCredential,
          onSuccess: foundCredential,
        }),
      );

const toPublicResolution = (credential: AuthenticatedCredential): AuthHttpCredentialResolution =>
  AuthHttpCredentialResolution.Authenticated({
    source: credential.source,
    user: credential.user,
    session: credential.session,
    rotation: credential.rotation,
  });

const makeCredentialResolverLayer = (contract: AuthHttpContractConfig) =>
  Layer.effect(
    AuthHttpCredentialResolver,
    Effect.gen(function* () {
      const auth = yield* Auth;
      const resolveRaw = ({
        source,
        value,
      }: {
        readonly source: AuthHttpCredentialSource;
        readonly value: string;
      }): Effect.Effect<AuthenticatedCredential, AuthHttpUnauthorized> =>
        parseCredential(value).pipe(
          Effect.flatMap((parsed) =>
            Predicate.isTagged(parsed, "Found")
              ? auth.currentSession({ sessionToken: parsed.token }).pipe(
                  Effect.mapError(() => unauthorizedError()),
                  Effect.map((current) => {
                    const rotation = tokenRotation(current.tokenRotation);
                    return {
                      source,
                      sessionToken: Predicate.isTagged(rotation, "Rotated")
                        ? rotation.token
                        : parsed.token,
                      user: toAuthHttpUser(current.user),
                      session: toAuthHttpSession(current.session),
                      rotation,
                    };
                  }),
                )
              : Effect.fail(unauthorizedError()),
          ),
        );
      const resolveOptionalContext = Effect.gen(function* () {
        const request = yield* HttpServerRequest.HttpServerRequest;
        const attempted: Array<AuthHttpCredentialSource> = [];

        const tryParsed = function* (
          source: AuthHttpCredentialSource,
          raw: string | undefined,
        ): Generator<Effect.Effect<ParsedCredential>, ParsedCredential> {
          const parsed = yield* parseCredential(raw);
          if (Predicate.isTagged(parsed, "Missing")) return parsed;
          attempted.push(source);
          return parsed;
        };

        if (contract.cookieAndBearer) {
          const bearer = yield* tryParsed(
            "Bearer",
            bearerTokenValue(request.headers.authorization),
          );
          if (Predicate.isTagged(bearer, "Found")) {
            const bearerSession = yield* Effect.option(
              resolveRaw({ source: "Bearer", value: Redacted.value(bearer.token) }),
            );
            if (Option.isSome(bearerSession)) {
              return AuthHttpCredentialContextResolution.Authenticated(bearerSession.value);
            }
          }
        }

        const cookie = yield* tryParsed("Cookie", request.cookies[contract.sessionCookieName]);
        if (Predicate.isTagged(cookie, "Found")) {
          const cookieSession = yield* Effect.option(
            resolveRaw({ source: "Cookie", value: Redacted.value(cookie.token) }),
          );
          if (Option.isSome(cookieSession)) {
            return AuthHttpCredentialContextResolution.Authenticated(cookieSession.value);
          }
        }

        return attempted.length === 0
          ? AuthHttpCredentialContextResolution.Missing()
          : AuthHttpCredentialContextResolution.Invalid({ attempted });
      });
      const resolveRequiredContext = Effect.gen(function* () {
        const resolved = yield* resolveOptionalContext;
        if (Predicate.isTagged(resolved, "Authenticated")) return resolved;
        return yield* unauthorizedError();
      });
      return {
        resolveRaw,
        resolveOptionalContext,
        resolveRequiredContext,
        resolveRequired: resolveRequiredContext.pipe(Effect.map(toPublicResolution)),
        resolveOptional: resolveOptionalContext.pipe(
          Effect.map(
            (resolved): AuthHttpCredentialResolution =>
              Predicate.isTagged(resolved, "Authenticated")
                ? toPublicResolution(resolved)
                : resolved,
          ),
        ),
      };
    }).pipe(Effect.annotateLogs({ service: "AuthHttpCredentialResolver" })),
  );

const originFromHeader = (field: string, value: string): Effect.Effect<URL, AuthHttpForbidden> =>
  value === "null"
    ? Effect.fail(forbidden("InvalidOrigin", "Invalid origin"))
    : Effect.try({
        try: () => new URL(value),
        catch: () => forbidden("InvalidOrigin", `Invalid ${field}`),
      });

const makeUrlPolicyLayer = Layer.effect(
  AuthHttpUrlPolicy,
  Effect.gen(function* () {
    const config = yield* AuthHttpRuntimeConfig;
    const isTrustedOrigin = (origin: URL) =>
      Effect.succeed(config.trustedOrigins.has(origin.origin));
    const checkTrusted = (origin: URL) =>
      isTrustedOrigin(origin).pipe(
        Effect.flatMap((trusted) =>
          trusted ? Effect.void : Effect.fail(forbidden("UntrustedOrigin", "Untrusted origin")),
        ),
      );
    const validateRequestOrigin = (
      request: HttpServerRequest.HttpServerRequest,
      requireHeader: boolean,
    ) => {
      const origin = request.headers.origin;
      if (origin !== undefined)
        return originFromHeader("origin", origin).pipe(Effect.flatMap(checkTrusted));
      const referer = request.headers.referer;
      if (referer !== undefined)
        return originFromHeader("referer", referer).pipe(Effect.flatMap(checkTrusted));
      return requireHeader
        ? Effect.fail(forbidden("MissingOrigin", "Missing trusted origin"))
        : Effect.void;
    };
    const resolveCallbackUrl = (value: string) => {
      if (value.startsWith("//")) {
        return Effect.fail(forbidden("InvalidCallbackUrl", "Invalid callback URL"));
      }
      if (value.startsWith("/")) return Effect.succeed(new URL(value, config.baseUrl));
      return Effect.try({
        try: () => new URL(value),
        catch: () => badRequest("InvalidCallbackUrl", "Invalid callback URL"),
      }).pipe(
        Effect.flatMap((url) =>
          config.trustedOrigins.has(url.origin)
            ? Effect.succeed(url)
            : Effect.fail(forbidden("InvalidCallbackUrl", "Untrusted callback URL")),
        ),
      );
    };
    const service: typeof AuthHttpUrlPolicy.Service = {
      isTrustedOrigin,
      validatePublicStateChange: (request: HttpServerRequest.HttpServerRequest) =>
        validateRequestOrigin(request, false),
      validateProtectedStateChange: ({ request, credential }) =>
        Predicate.isTagged(credential, "Cookie")
          ? validateRequestOrigin(request, true)
          : Effect.void,
      validateCallbackUrl: (value: string) =>
        resolveCallbackUrl(value).pipe(Effect.map((url) => url.href)),
      resolveCallbackUrl,
      validateOAuthRedirectPath,
    };
    return service;
  }).pipe(Effect.annotateLogs({ service: "AuthHttpUrlPolicy" })),
);

const credentialSelection = (credential: AuthenticatedCredential): AuthHttpSelectedCredential =>
  credential.source === "Cookie"
    ? AuthHttpSelectedCredential.Cookie()
    : AuthHttpSelectedCredential.Bearer();

const trustedRequestIp = (request: HttpServerRequest.HttpServerRequest): string | undefined => {
  const forwarded = request.headers["x-forwarded-for"];
  if (forwarded !== undefined && forwarded.trim() !== "") return forwarded.split(",")[0]?.trim();
  const realIp = request.headers["x-real-ip"];
  return realIp === undefined || realIp.trim() === "" ? undefined : realIp.trim();
};

const oauthCallbackPath = (basePath: `/${string}`, providerId: string): `/${string}` =>
  `${basePath}/oauth2/callback/${providerId}`;

const oauthRedirectUri = (config: AuthHttpRuntimeConfigShape, providerId: string): URL =>
  new URL(oauthCallbackPath(config.contract.basePath, providerId), config.baseUrl);

const publicGroup = HttpApiGroup.make("authPublic")
  .add(
    HttpApiEndpoint.post("signUpEmail", "/sign-up/email", {
      payload: AuthHttpSignUpEmailPayload,
      success: AuthHttpUserResponse,
      error: AuthHttpErrors,
    }),
    HttpApiEndpoint.post("verifyEmail", "/verify-email", {
      payload: AuthHttpVerifyEmailPayload,
      success: AuthHttpUserResponse,
      error: AuthHttpErrors,
    }),
    HttpApiEndpoint.post("resendVerification", "/resend-verification", {
      payload: AuthHttpResendVerificationPayload,
      success: AuthHttpOkResponse,
      error: AuthHttpErrors,
    }),
    HttpApiEndpoint.post("signInEmail", "/sign-in/email", {
      payload: AuthHttpSignInEmailPayload,
      success: AuthHttpSessionResponse,
      error: AuthHttpErrors,
    }),
    HttpApiEndpoint.post("requestPasswordReset", "/password-reset/request", {
      payload: AuthHttpRequestPasswordResetPayload,
      success: AuthHttpOkResponse,
      error: AuthHttpErrors,
    }),
    HttpApiEndpoint.post("completePasswordReset", "/password-reset/complete", {
      payload: AuthHttpCompletePasswordResetPayload,
      success: AuthHttpOkResponse,
      error: AuthHttpErrors,
    }),
  )
  .middleware(AuthHttpSchemaErrorMiddleware);

const optionalGroup = HttpApiGroup.make("authOptional")
  .add(
    HttpApiEndpoint.get("currentSession", "/session", {
      success: AuthHttpCurrentSessionResponse,
      error: AuthHttpErrors,
    }),
  )
  .middleware(AuthHttpSchemaErrorMiddleware);

const protectedSessionGroup = HttpApiGroup.make("authProtectedSession").add(
  HttpApiEndpoint.post("signOut", "/sign-out", {
    success: AuthHttpOkResponse,
    error: AuthHttpErrors,
  }),
  HttpApiEndpoint.get("listSessions", "/sessions", {
    success: AuthHttpListSessionsResponse,
    error: AuthHttpErrors,
  }),
  HttpApiEndpoint.post("revokeSession", "/sessions/revoke", {
    payload: AuthHttpRevokeSessionPayload,
    success: AuthHttpOkResponse,
    error: AuthHttpErrors,
  }),
  HttpApiEndpoint.post("revokeOtherSessions", "/sessions/revoke-others", {
    success: AuthHttpOkResponse,
    error: AuthHttpErrors,
  }),
  HttpApiEndpoint.post("revokeSessions", "/sessions/revoke-all", {
    success: AuthHttpOkResponse,
    error: AuthHttpErrors,
  }),
);

const protectedIdentityGroup = HttpApiGroup.make("authProtectedIdentity").add(
  HttpApiEndpoint.post("changePassword", "/password/change", {
    payload: AuthHttpChangePasswordPayload,
    success: AuthHttpOkResponse,
    error: AuthHttpErrors,
  }),
  HttpApiEndpoint.post("deleteUser", "/delete-user", {
    payload: AuthHttpDeleteUserPayload,
    success: AuthHttpOkResponse,
    error: AuthHttpErrors,
  }),
  HttpApiEndpoint.post("updateUser", "/update-user", {
    payload: AuthHttpUpdateUserPayload,
    success: AuthHttpUserResponse,
    error: AuthHttpErrors,
  }),
  HttpApiEndpoint.get("listAccounts", "/accounts", {
    success: AuthHttpListAccountsResponse,
    error: AuthHttpErrors,
  }),
);

const oauthPublicGroup = HttpApiGroup.make("authOAuthPublic")
  .add(
    HttpApiEndpoint.post("oauthSignInStart", "/sign-in/oauth2", {
      payload: AuthHttpOAuthStartSignInPayload,
      success: AuthHttpOAuthAuthorizationUrlResponse,
      error: AuthHttpErrors,
    }),
    HttpApiEndpoint.get("oauthCallbackGet", "/oauth2/callback/:providerId", {
      params: OAuthCallbackParams,
      success: AuthHttpOkResponse,
      error: AuthHttpErrors,
    }),
    HttpApiEndpoint.post("oauthCallbackPost", "/oauth2/callback/:providerId", {
      params: OAuthCallbackParams,
      success: AuthHttpOkResponse,
      error: AuthHttpErrors,
    }),
  )
  .middleware(AuthHttpSchemaErrorMiddleware);

const oauthProtectedGroup = HttpApiGroup.make("authOAuthProtected").add(
  HttpApiEndpoint.post("oauthLinkStart", "/oauth2/link", {
    payload: AuthHttpOAuthStartLinkPayload,
    success: AuthHttpOAuthAuthorizationUrlResponse,
    error: AuthHttpErrors,
  }),
);

const makeApi = <I extends HttpApiMiddleware.AnyId>(input: {
  readonly contract: AuthHttpContractConfig;
  readonly middleware: Context.Key<I, unknown>;
}) => {
  const protectedSession = protectedSessionGroup
    .middleware(input.middleware)
    .middleware(AuthHttpSchemaErrorMiddleware);
  const protectedIdentity = protectedIdentityGroup
    .middleware(input.middleware)
    .middleware(AuthHttpSchemaErrorMiddleware);
  const base = HttpApi.make("effectAuth").add(
    publicGroup,
    optionalGroup,
    protectedSession,
    protectedIdentity,
  );
  const withOAuth = input.contract.oauth
    ? base.add(
        oauthPublicGroup,
        oauthProtectedGroup.middleware(input.middleware).middleware(AuthHttpSchemaErrorMiddleware),
      )
    : base;
  return withOAuth.prefix(input.contract.basePath);
};

const publicHandlers = <I extends HttpApiMiddleware.AnyId>(api: ReturnType<typeof makeApi<I>>) =>
  HttpApiBuilder.group(api, "authPublic", (handlers) =>
    handlers
      .handle("signUpEmail", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const policy = yield* AuthHttpUrlPolicy;
            yield* policy.validatePublicStateChange(request);
            const callbackUrl = yield* policy.resolveCallbackUrl(payload.verificationCallbackUrl);
            const result = yield* auth.signUp({
              email: payload.email,
              password: payload.password,
              name: payload.name,
              verificationCallbackUrl: callbackUrl,
              ...(payload.ip === undefined ? {} : { ip: payload.ip }),
            });
            return new AuthHttpUserResponse({ user: toAuthHttpUser(result.user) });
          }),
        ),
      )
      .handle("verifyEmail", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const policy = yield* AuthHttpUrlPolicy;
            yield* policy.validatePublicStateChange(request);
            const result = yield* auth.verifyEmail({ token: payload.token });
            return new AuthHttpUserResponse({ user: toAuthHttpUser(result.user) });
          }),
        ),
      )
      .handle("resendVerification", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const policy = yield* AuthHttpUrlPolicy;
            yield* policy.validatePublicStateChange(request);
            const callbackUrl = yield* policy.resolveCallbackUrl(payload.verificationCallbackUrl);
            yield* auth.resendVerification({
              email: payload.email,
              verificationCallbackUrl: callbackUrl,
            });
            return okResponse;
          }),
        ),
      )
      .handle("signInEmail", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const policy = yield* AuthHttpUrlPolicy;
            const renderer = yield* AuthHttpCredentialRenderer;
            yield* policy.validatePublicStateChange(request);
            const result = yield* auth.signIn({
              email: payload.email,
              password: payload.password,
              ...(payload.ip === undefined ? {} : { ip: payload.ip }),
              ...(request.headers["user-agent"] === undefined
                ? {}
                : { userAgent: request.headers["user-agent"] }),
            });
            yield* renderer.render(
              AuthHttpCredentialMaintenance.IssueCookie({ token: result.sessionToken }),
            );
            return toSessionResponse(result);
          }),
        ),
      )
      .handle("requestPasswordReset", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const policy = yield* AuthHttpUrlPolicy;
            yield* policy.validatePublicStateChange(request);
            const callbackUrl = yield* policy.resolveCallbackUrl(payload.resetCallbackUrl);
            yield* auth.requestPasswordReset({
              email: payload.email,
              resetCallbackUrl: callbackUrl,
              ...(payload.ip === undefined ? {} : { ip: payload.ip }),
            });
            return okResponse;
          }),
        ),
      )
      .handle("completePasswordReset", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const policy = yield* AuthHttpUrlPolicy;
            yield* policy.validatePublicStateChange(request);
            yield* auth.resetPassword({ token: payload.token, password: payload.password });
            return okResponse;
          }),
        ),
      ),
  );

const optionalHandlers = <I extends HttpApiMiddleware.AnyId>(api: ReturnType<typeof makeApi<I>>) =>
  HttpApiBuilder.group(api, "authOptional", (handlers) =>
    handlers.handle("currentSession", () =>
      withAuthHttpErrors(
        Effect.gen(function* () {
          const resolver = yield* AuthHttpCredentialResolver;
          const renderer = yield* AuthHttpCredentialRenderer;
          const resolved = yield* resolver.resolveOptionalContext;
          if (Predicate.isTagged(resolved, "Authenticated")) {
            yield* renderer.render(maintenanceForRotation(resolved.source, resolved.rotation));
            return new AuthHttpSessionResponse({ user: resolved.user, session: resolved.session });
          }
          if (Predicate.isTagged(resolved, "Invalid") && resolved.attempted.includes("Cookie")) {
            yield* renderer.render(AuthHttpCredentialMaintenance.ClearCookie());
          }
          return null;
        }),
      ),
    ),
  );

const renderSelectedRotation = Effect.fn("AuthHttp.renderSelectedRotation")(function* (
  context: AuthenticatedCredential,
) {
  const renderer = yield* AuthHttpCredentialRenderer;
  yield* renderer.render(maintenanceForRotation(context.source, context.rotation));
});

const validateProtectedStateChange = Effect.fn("AuthHttp.validateProtectedStateChange")(function* (
  request: HttpServerRequest.HttpServerRequest,
  context: AuthenticatedCredential,
) {
  const policy = yield* AuthHttpUrlPolicy;
  yield* policy.validateProtectedStateChange({ request, credential: credentialSelection(context) });
});

const protectedSessionHandlers = <I extends HttpApiMiddleware.AnyId>(
  api: ReturnType<typeof makeApi<I>>,
) =>
  HttpApiBuilder.group(api, "authProtectedSession", (handlers) =>
    handlers
      .handle("signOut", ({ request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            yield* validateProtectedStateChange(request, context);
            yield* auth.signOut({ sessionToken: context.sessionToken });
            if (context.source === "Cookie")
              yield* renderer.render(AuthHttpCredentialMaintenance.ClearCookie());
            return okResponse;
          }),
        ),
      )
      .handle("listSessions", () =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            const result = yield* auth.listSessions({ sessionToken: context.sessionToken });
            yield* renderer.render(
              maintenanceForRotation(
                context.source,
                rotationFromContextOrResult(context, result.tokenRotation),
              ),
            );
            return new AuthHttpListSessionsResponse({
              sessions: result.sessions.map(toAuthHttpListedSession),
            });
          }),
        ),
      )
      .handle("revokeSession", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            yield* validateProtectedStateChange(request, context);
            yield* auth.revokeSession({
              sessionToken: context.sessionToken,
              sessionId: payload.sessionId,
            });
            if (context.source === "Cookie" && payload.sessionId === context.session.id) {
              yield* renderer.render(AuthHttpCredentialMaintenance.ClearCookie());
            } else {
              yield* renderer.render(maintenanceForRotation(context.source, context.rotation));
            }
            return okResponse;
          }),
        ),
      )
      .handle("revokeOtherSessions", ({ request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const context = yield* AuthHttpSelectedCredentialContext;
            yield* validateProtectedStateChange(request, context);
            yield* auth.revokeOtherSessions({ sessionToken: context.sessionToken });
            yield* renderSelectedRotation(context);
            return okResponse;
          }),
        ),
      )
      .handle("revokeSessions", ({ request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            yield* validateProtectedStateChange(request, context);
            yield* auth.revokeSessions({ sessionToken: context.sessionToken });
            if (context.source === "Cookie")
              yield* renderer.render(AuthHttpCredentialMaintenance.ClearCookie());
            return okResponse;
          }),
        ),
      ),
  );

const protectedIdentityHandlers = <I extends HttpApiMiddleware.AnyId>(
  api: ReturnType<typeof makeApi<I>>,
) =>
  HttpApiBuilder.group(api, "authProtectedIdentity", (handlers) =>
    handlers
      .handle("changePassword", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            yield* validateProtectedStateChange(request, context);
            const result = yield* auth.changePassword({
              sessionToken: context.sessionToken,
              currentPassword: payload.currentPassword,
              newPassword: payload.newPassword,
              ...(payload.ip === undefined ? {} : { ip: payload.ip }),
            });
            yield* renderer.render(
              context.source === "Cookie"
                ? AuthHttpCredentialMaintenance.IssueCookie({ token: result.currentSessionToken })
                : AuthHttpCredentialMaintenance.IssueBearer({ token: result.currentSessionToken }),
            );
            return okResponse;
          }),
        ),
      )
      .handle("deleteUser", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            yield* validateProtectedStateChange(request, context);
            yield* auth.deleteUser({
              sessionToken: context.sessionToken,
              password: payload.password,
              ...(payload.ip === undefined ? {} : { ip: payload.ip }),
            });
            if (context.source === "Cookie")
              yield* renderer.render(AuthHttpCredentialMaintenance.ClearCookie());
            return okResponse;
          }),
        ),
      )
      .handle("updateUser", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            yield* validateProtectedStateChange(request, context);
            const result = yield* auth.updateUser({
              sessionToken: context.sessionToken,
              ...(payload.name === undefined ? {} : { name: payload.name }),
              ...(payload.image === undefined ? {} : { image: payload.image }),
            });
            yield* renderer.render(
              maintenanceForRotation(
                context.source,
                rotationFromContextOrResult(context, result.tokenRotation),
              ),
            );
            return new AuthHttpUserResponse({ user: toAuthHttpUser(result.user) });
          }),
        ),
      )
      .handle("listAccounts", () =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const auth = yield* Auth;
            const renderer = yield* AuthHttpCredentialRenderer;
            const context = yield* AuthHttpSelectedCredentialContext;
            const result = yield* auth.listAccounts({ sessionToken: context.sessionToken });
            yield* renderer.render(
              maintenanceForRotation(
                context.source,
                rotationFromContextOrResult(context, result.tokenRotation),
              ),
            );
            return new AuthHttpListAccountsResponse({
              accounts: result.accounts.map(toAuthHttpAccount),
            });
          }),
        ),
      ),
  );

const oauthCallbackPayload = (input: {
  readonly state: string | undefined;
  readonly code: string | undefined;
  readonly error: string | undefined;
  readonly errorDescription: string | undefined;
}) => ({
  ...(input.state === undefined ? {} : { state: input.state }),
  ...(input.code === undefined ? {} : { code: input.code }),
  ...(input.error === undefined ? {} : { error: input.error }),
  ...(input.errorDescription === undefined ? {} : { errorDescription: input.errorDescription }),
});

const isReadonlyRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const optionalStringField = (
  record: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined => {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
};

const oauthCallbackPayloadFromRecord = (record: Readonly<Record<string, unknown>>) =>
  oauthCallbackPayload({
    state: optionalStringField(record, "state"),
    code: optionalStringField(record, "code"),
    error: optionalStringField(record, "error"),
    errorDescription:
      optionalStringField(record, "error_description") ??
      optionalStringField(record, "errorDescription"),
  });

const oauthCallbackPayloadFromSearch = (request: HttpServerRequest.HttpServerRequest) => {
  const search = new URL(request.originalUrl, "http://effect-auth.local").searchParams;
  return oauthCallbackPayload({
    state: search.get("state") ?? undefined,
    code: search.get("code") ?? undefined,
    error: search.get("error") ?? undefined,
    errorDescription: search.get("error_description") ?? undefined,
  });
};

const oauthCallbackPayloadFromUrlParams = (params: UrlParams.UrlParams) =>
  oauthCallbackPayload({
    state: Option.getOrUndefined(UrlParams.getFirst(params, "state")),
    code: Option.getOrUndefined(UrlParams.getFirst(params, "code")),
    error: Option.getOrUndefined(UrlParams.getFirst(params, "error")),
    errorDescription: Option.getOrUndefined(UrlParams.getFirst(params, "error_description")),
  });

const oauthPostCallbackPayload = (request: HttpServerRequest.HttpServerRequest) => {
  const contentType = request.headers["content-type"]?.toLowerCase() ?? "";
  return contentType.includes("application/json")
    ? request.json.pipe(
        Effect.map((body) => (isReadonlyRecord(body) ? oauthCallbackPayloadFromRecord(body) : {})),
      )
    : request.urlParamsBody.pipe(Effect.map(oauthCallbackPayloadFromUrlParams));
};

const oauthHandlers = <I extends HttpApiMiddleware.AnyId>(api: ReturnType<typeof makeApi<I>>) => {
  const publicLayer = HttpApiBuilder.group(api, "authOAuthPublic", (handlers) =>
    handlers
      .handle("oauthSignInStart", ({ payload, request }) =>
        withAuthHttpErrors(
          Effect.gen(function* () {
            const config = yield* AuthHttpRuntimeConfig;
            const oauth = yield* OAuth;
            const policy = yield* AuthHttpUrlPolicy;
            yield* policy.validatePublicStateChange(request);
            const result = yield* oauth.startSignIn({
              providerId: payload.providerId,
              redirectUri: oauthRedirectUri(config, payload.providerId),
              ...(payload.scopes === undefined ? {} : { scopes: payload.scopes }),
              ...(payload.allowSignUp === undefined ? {} : { allowSignUp: payload.allowSignUp }),
              ...(trustedRequestIp(request) === undefined ? {} : { ip: trustedRequestIp(request) }),
            });
            return new AuthHttpOAuthAuthorizationUrlResponse({
              authorizationUrl: result.authorizationUrl.href,
            });
          }),
        ),
      )
      .handleRaw("oauthCallbackGet", ({ request, params }) =>
        Effect.gen(function* () {
          const config = yield* AuthHttpRuntimeConfig;
          const renderer = yield* AuthHttpCredentialRenderer;
          const oauth = yield* OAuth;
          const payload = oauthCallbackPayloadFromSearch(request);
          const ip = Option.getOrUndefined(request.remoteAddress);
          const result = yield* oauth.completeCallback({
            providerId: params.providerId,
            state: payload.state,
            ...(payload.code === undefined ? {} : { code: payload.code }),
            ...(payload.error === undefined ? {} : { error: payload.error }),
            ...(payload.errorDescription === undefined
              ? {}
              : { errorDescription: payload.errorDescription }),
            callbackMethod: "GET",
            ...(ip === undefined ? {} : { ip }),
            ...(request.headers["user-agent"] === undefined
              ? {}
              : { userAgent: request.headers["user-agent"] }),
          });
          if (result.flow === "SignIn") {
            return renderer.apply(
              HttpServerResponse.redirect(config.oauth.signInSuccessPath),
              AuthHttpCredentialMaintenance.IssueCookie({ token: result.sessionToken }),
            );
          }
          return HttpServerResponse.redirect(config.oauth.linkSuccessPath);
        }).pipe(
          Effect.catch(() =>
            Effect.gen(function* () {
              const config = yield* AuthHttpRuntimeConfig;
              return HttpServerResponse.redirect(config.oauth.errorPath);
            }),
          ),
        ),
      )
      .handleRaw("oauthCallbackPost", ({ request, params }) =>
        Effect.gen(function* () {
          const config = yield* AuthHttpRuntimeConfig;
          const renderer = yield* AuthHttpCredentialRenderer;
          const oauth = yield* OAuth;
          const payload = yield* oauthPostCallbackPayload(request);
          const ip = Option.getOrUndefined(request.remoteAddress);
          const result = yield* oauth.completeCallback({
            providerId: params.providerId,
            state: payload.state,
            ...(payload.code === undefined ? {} : { code: payload.code }),
            ...(payload.error === undefined ? {} : { error: payload.error }),
            ...(payload.errorDescription === undefined
              ? {}
              : { errorDescription: payload.errorDescription }),
            callbackMethod: "POST",
            ...(ip === undefined ? {} : { ip }),
            ...(request.headers["user-agent"] === undefined
              ? {}
              : { userAgent: request.headers["user-agent"] }),
          });
          if (result.flow === "SignIn") {
            return renderer.apply(
              HttpServerResponse.redirect(config.oauth.signInSuccessPath),
              AuthHttpCredentialMaintenance.IssueCookie({ token: result.sessionToken }),
            );
          }
          return HttpServerResponse.redirect(config.oauth.linkSuccessPath);
        }).pipe(
          Effect.catch(() =>
            Effect.gen(function* () {
              const config = yield* AuthHttpRuntimeConfig;
              return HttpServerResponse.redirect(config.oauth.errorPath);
            }),
          ),
        ),
      ),
  );

  const protectedLayer = HttpApiBuilder.group(api, "authOAuthProtected", (handlers) =>
    handlers.handle("oauthLinkStart", ({ payload, request }) =>
      withAuthHttpErrors(
        Effect.gen(function* () {
          const config = yield* AuthHttpRuntimeConfig;
          const oauth = yield* OAuth;
          const policy = yield* AuthHttpUrlPolicy;
          const context = yield* AuthHttpSelectedCredentialContext;
          yield* policy.validateProtectedStateChange({
            request,
            credential: credentialSelection(context),
          });
          const result = yield* oauth.startLink({
            providerId: payload.providerId,
            redirectUri: oauthRedirectUri(config, payload.providerId),
            sessionToken: context.sessionToken,
            ...(payload.scopes === undefined ? {} : { scopes: payload.scopes }),
            ...(trustedRequestIp(request) === undefined ? {} : { ip: trustedRequestIp(request) }),
          });
          return new AuthHttpOAuthAuthorizationUrlResponse({
            authorizationUrl: result.authorizationUrl.href,
          });
        }),
      ),
    ),
  );

  return Layer.mergeAll(publicLayer, protectedLayer);
};

const requireAuthEffect = Effect.fn("AuthHttp.requireAuthEffect")(function* <A, E, R>(
  self: Effect.Effect<A, E, R>,
) {
  const resolver = yield* AuthHttpCredentialResolver;
  const credential = yield* resolver.resolveRequiredContext;
  return yield* self.pipe(
    Effect.provideService(AuthHttpSessionContext, {
      user: credential.user,
      session: credential.session,
    }),
    Effect.provideService(AuthHttpSelectedCredentialContext, credential),
  );
});

const optionalAuthEffect = Effect.fn("AuthHttp.optionalAuthEffect")(function* <A, E, R>(
  self: Effect.Effect<A, E, R>,
) {
  const resolver = yield* AuthHttpCredentialResolver;
  const resolved = yield* resolver.resolveOptionalContext;
  const session = Predicate.isTagged(resolved, "Authenticated")
    ? Option.some({ user: resolved.user, session: resolved.session })
    : Option.none<typeof AuthHttpSessionContext.Service>();
  return yield* Effect.provideService(self, AuthHttpOptionalSessionContext, { session });
});

export interface ConfiguredAuthHttpApi {
  readonly identifier: string;
  readonly groups: Readonly<
    Record<
      string,
      {
        readonly identifier: string;
        readonly endpoints: Readonly<Record<string, unknown>>;
      }
    >
  >;
}

type ConfiguredAuthHttpRouteRequirements =
  | AuthHttpCredentialResolver
  | FileSystem.FileSystem
  | Etag.Generator
  | HttpPlatform.HttpPlatform
  | HttpRouter.HttpRouter
  | Path.Path
  | HttpRouter.Request<"Requires", Auth>
  | HttpRouter.Request<"Requires", AuthHttpCredentialRenderer>
  | HttpRouter.Request<"Requires", AuthHttpCredentialResolver>
  | HttpRouter.Request<"Requires", AuthHttpRuntimeConfig>
  | HttpRouter.Request<"Requires", AuthHttpUrlPolicy>
  | HttpRouter.Request<"Requires", OAuth>;

export interface ConfiguredAuthHttp {
  readonly api: ConfiguredAuthHttpApi;
  readonly routes: Layer.Layer<never, unknown, ConfiguredAuthHttpRouteRequirements>;
  readonly middleware: {
    readonly layer: Layer.Layer<never, unknown, AuthHttpCredentialResolver>;
  };
  readonly requireAuth: <A, E, R>(
    self: Effect.Effect<A, E, R>,
  ) => Effect.Effect<
    A,
    E | AuthHttpUnauthorized,
    R | AuthHttpCredentialResolver | HttpServerRequest.HttpServerRequest
  >;
  readonly optionalAuth: <A, E, R>(
    self: Effect.Effect<A, E, R>,
  ) => Effect.Effect<A, E, R | AuthHttpCredentialResolver | HttpServerRequest.HttpServerRequest>;
  readonly layer: (
    runtimeInput: AuthHttpRuntimeInput,
  ) => Layer.Layer<
    | AuthHttpCredentialResolver
    | AuthHttpCredentialRenderer
    | AuthHttpRuntimeConfig
    | AuthHttpUrlPolicy,
    AuthHttpConfigError,
    Auth
  >;
  readonly sessionCookieName: string;
  readonly tokenResponseHeader: typeof tokenResponseHeader;
}

const configureAuthHttp = (input: AuthHttpConfigureInput = {}): ConfiguredAuthHttp => {
  const contract: AuthHttpContractConfig = {
    basePath: normalizeBasePath(input.basePath),
    sessionCookieName: parseSessionCookieName(input.sessionCookieName),
    cookieAndBearer: input.cookieAndBearer ?? false,
    oauth: input.oauth ?? false,
  };

  /** @effect-expect-leaking HttpServerRequest | ParsedSearchParams | RouteContext */
  class ConfiguredAuthMiddleware extends HttpApiMiddleware.Service<
    ConfiguredAuthMiddleware,
    {
      provides: AuthHttpSessionContext | AuthHttpSelectedCredentialContext;
    }
  >()("effect-auth/http/ConfiguredAuthMiddleware", {
    error: AuthHttpErrors,
    security: contract.cookieAndBearer
      ? {
          bearer: HttpApiSecurity.bearer,
          cookie: HttpApiSecurity.apiKey({ in: "cookie", key: contract.sessionCookieName }),
        }
      : {
          cookie: HttpApiSecurity.apiKey({ in: "cookie", key: contract.sessionCookieName }),
        },
  }) {}

  const middlewareLayer = Layer.effect(
    ConfiguredAuthMiddleware,
    Effect.gen(function* () {
      const resolver = yield* AuthHttpCredentialResolver;
      const provideCredential = (
        source: AuthHttpCredentialSource,
        value: string,
        effect: Effect.Effect<
          HttpServerResponse.HttpServerResponse,
          unhandled,
          AuthHttpSessionContext | AuthHttpSelectedCredentialContext
        >,
      ) =>
        resolver.resolveRaw({ source, value }).pipe(
          Effect.flatMap((credential) =>
            effect.pipe(
              Effect.provideService(AuthHttpSessionContext, {
                user: credential.user,
                session: credential.session,
              }),
              Effect.provideService(AuthHttpSelectedCredentialContext, credential),
            ),
          ),
        );
      return {
        bearer: (
          httpEffect: Effect.Effect<
            HttpServerResponse.HttpServerResponse,
            unhandled,
            AuthHttpSessionContext | AuthHttpSelectedCredentialContext
          >,
          { credential }: { readonly credential: Redacted.Redacted<string> },
        ) => provideCredential("Bearer", Redacted.value(credential), httpEffect),
        cookie: (
          httpEffect: Effect.Effect<
            HttpServerResponse.HttpServerResponse,
            unhandled,
            AuthHttpSessionContext | AuthHttpSelectedCredentialContext
          >,
          { credential }: { readonly credential: Redacted.Redacted<string> },
        ) => provideCredential("Cookie", Redacted.value(credential), httpEffect),
      };
    }).pipe(Effect.annotateLogs({ service: "ConfiguredAuthMiddleware" })),
  );
  const middleware = Object.assign(ConfiguredAuthMiddleware, { layer: middlewareLayer });
  const api = makeApi({ contract, middleware: ConfiguredAuthMiddleware });
  const handlers = Layer.mergeAll(
    publicHandlers(api),
    optionalHandlers(api),
    protectedSessionHandlers(api),
    protectedIdentityHandlers(api),
    ...(contract.oauth ? [oauthHandlers(api)] : []),
  ).pipe(Layer.provide(AuthHttpSchemaErrorLayer));
  const routes = HttpApiBuilder.layer(api).pipe(
    Layer.provide(handlers),
    Layer.provide(middlewareLayer),
  );
  const runtimeLayer = (runtimeInput: AuthHttpRuntimeInput) => {
    const configLayer = Layer.effect(AuthHttpRuntimeConfig)(
      makeRuntimeConfig(contract, runtimeInput),
    );
    const servicesLayer = Layer.mergeAll(
      makeCredentialResolverLayer(contract),
      makeCredentialRendererLayer,
      makeUrlPolicyLayer,
    ).pipe(Layer.provideMerge(configLayer));
    return middlewareLayer.pipe(Layer.provideMerge(servicesLayer));
  };

  return {
    api,
    routes,
    middleware,
    requireAuth: requireAuthEffect,
    optionalAuth: optionalAuthEffect,
    layer: runtimeLayer,
    sessionCookieName: contract.sessionCookieName,
    tokenResponseHeader,
  };
};

export const AuthHttp: {
  readonly configure: (input?: AuthHttpConfigureInput) => ConfiguredAuthHttp;
} = {
  configure: configureAuthHttp,
};
