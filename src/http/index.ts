import { Context, Effect, Layer, Redacted, Schema } from "effect";
import * as HttpEffect from "effect/unstable/http/HttpEffect";
import * as HttpServerResponse from "effect/unstable/http/HttpServerResponse";
import { HttpApi, HttpApiBuilder, HttpApiEndpoint, HttpApiGroup } from "effect/unstable/httpapi";
import {
  invalidCredentials,
  rateLimited,
  unauthorized,
  type PublicAuthError,
} from "../domain/index.js";
import {
  SessionToken,
  VerificationToken,
  type SessionToken as SessionTokenValue,
} from "../token/index.js";
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
  type VerifyEmailInput,
} from "../workflows/index.js";

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
  switch (error.code) {
    case "RateLimited":
      return { status: 429, body: rateLimited };
    case "Unauthorized":
      return { status: 401, body: unauthorized };
    case "InvalidCredentials":
    case "EmailNotVerified":
    case "InvalidToken":
      return {
        status: 400,
        body: error.code === "InvalidCredentials" ? invalidCredentials : error,
      };
  }
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
  Effect.gen(function* () {
    const policy = yield* TrustedOriginPolicy;
    const trusted = yield* policy.isTrusted(origin);
    if (!trusted) return yield* unauthorized;
  });

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
        if (result.tokenRotation._tag === "Rotated") {
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

const decodeVerificationToken = (token: string) =>
  Schema.decodeUnknownEffect(VerificationToken)(token);

const decodeSessionToken = (token: string) => Schema.decodeUnknownEffect(SessionToken)(token);

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

export const handleSignUpEmail = ({
  payload,
  request,
}: {
  readonly payload: typeof SignUpEmailPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
    yield* checkTrustedRequestOrigin(request);
    const adapter = yield* AuthHttpAdapter;
    return yield* adapter.signUpEmail(signUpInput(payload));
  });

export const handleVerifyEmail = ({
  payload,
  request,
}: {
  readonly payload: typeof VerifyEmailPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
    yield* checkTrustedRequestOrigin(request);
    const adapter = yield* AuthHttpAdapter;
    const token = yield* decodeVerificationToken(payload.token);
    return yield* adapter.verifyEmail({ token });
  });

export const handleResendVerification = ({
  payload,
  request,
}: {
  readonly payload: typeof ResendVerificationPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
    yield* checkTrustedRequestOrigin(request);
    const adapter = yield* AuthHttpAdapter;
    return yield* adapter.resendVerification(resendVerificationInput(payload));
  });

export const handleSignInEmail = ({
  payload,
  request,
}: {
  readonly payload: typeof SignInEmailPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
    yield* checkTrustedRequestOrigin(request);
    const adapter = yield* AuthHttpAdapter;
    return yield* adapter.signInEmail(signInInput(payload));
  });

export const handleCurrentSession = ({
  query,
}: {
  readonly query: typeof CurrentSessionQuery.Type;
}) =>
  Effect.gen(function* () {
    const adapter = yield* AuthHttpAdapter;
    const sessionToken = yield* decodeSessionToken(query.sessionToken);
    return yield* adapter.currentSession({ sessionToken });
  });

export const handleSignOut = ({
  payload,
  request,
}: {
  readonly payload: typeof SessionTokenPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
    yield* checkTrustedRequestOrigin(request);
    const adapter = yield* AuthHttpAdapter;
    const sessionToken = yield* decodeSessionToken(payload.sessionToken);
    return yield* adapter.signOut({ sessionToken });
  });

export const handleRequestPasswordReset = ({
  payload,
  request,
}: {
  readonly payload: typeof RequestPasswordResetPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
    yield* checkTrustedRequestOrigin(request);
    const adapter = yield* AuthHttpAdapter;
    return yield* adapter.requestPasswordReset(requestPasswordResetInput(payload));
  });

export const handleCompletePasswordReset = ({
  payload,
  request,
}: {
  readonly payload: typeof CompletePasswordResetPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
    yield* checkTrustedRequestOrigin(request);
    const adapter = yield* AuthHttpAdapter;
    const token = yield* decodeVerificationToken(payload.token);
    return yield* adapter.completePasswordReset({ token, password: payload.password });
  });

export const handleChangePassword = ({
  payload,
  request,
}: {
  readonly payload: typeof ChangePasswordPayload.Type;
  readonly request: OriginRequest;
}) =>
  Effect.gen(function* () {
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
