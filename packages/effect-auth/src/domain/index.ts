import { isIP } from "node:net";
import { Context, Effect, Layer, Schema } from "effect";

export const NormalizedEmail = Schema.String.pipe(Schema.brand("NormalizedEmail"));
export type NormalizedEmail = typeof NormalizedEmail.Type;

export const PasswordText = Schema.RedactedFromValue(Schema.String, { label: "PasswordText" });
export type PasswordText = typeof PasswordText.Type;

export const CallbackUrl = Schema.instanceOf(URL).pipe(Schema.brand("CallbackUrl"));
export type CallbackUrl = typeof CallbackUrl.Type;

export const OriginUrl = Schema.instanceOf(URL).pipe(Schema.brand("OriginUrl"));
export type OriginUrl = typeof OriginUrl.Type;

export const ClientIp = Schema.String.pipe(Schema.brand("ClientIp"));
export type ClientIp = typeof ClientIp.Type;

export class BoundaryParseError extends Schema.TaggedErrorClass<BoundaryParseError>()(
  "BoundaryParseError",
  {
    field: Schema.String,
    reason: Schema.String,
  },
) {}

export class PublicAuthError extends Schema.TaggedErrorClass<PublicAuthError>()("PublicAuthError", {
  code: Schema.Literals([
    "InvalidCredentials",
    "EmailNotVerified",
    "InvalidToken",
    "RateLimited",
    "Unauthorized",
  ]),
  message: Schema.String,
}) {}

export const invalidCredentials = new PublicAuthError({
  code: "InvalidCredentials",
  message: "Invalid credentials",
});

export const emailNotVerified = new PublicAuthError({
  code: "EmailNotVerified",
  message: "Email is not verified",
});

export const invalidToken = new PublicAuthError({
  code: "InvalidToken",
  message: "Invalid token",
});

export const unauthorized = new PublicAuthError({
  code: "Unauthorized",
  message: "Unauthorized",
});

export const rateLimited = new PublicAuthError({
  code: "RateLimited",
  message: "Too many attempts",
});

export class AuthBoundary extends Context.Service<
  AuthBoundary,
  {
    readonly parseEmail: (input: unknown) => Effect.Effect<NormalizedEmail, BoundaryParseError>;
    readonly parsePassword: (input: unknown) => Effect.Effect<PasswordText, BoundaryParseError>;
    readonly parseCallbackUrl: (input: unknown) => Effect.Effect<CallbackUrl, BoundaryParseError>;
    readonly parseOrigin: (input: unknown) => Effect.Effect<OriginUrl, BoundaryParseError>;
    readonly parseClientIp: (input: unknown) => Effect.Effect<ClientIp, BoundaryParseError>;
  }
>()("effect-auth/AuthBoundary") {}
export type AuthBoundaryShape = typeof AuthBoundary.Service;

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;
const decodeNormalizedEmail = Schema.decodeUnknownEffect(NormalizedEmail);
const decodePasswordText = Schema.decodeUnknownEffect(PasswordText);
const decodeCallbackUrl = Schema.decodeUnknownEffect(CallbackUrl);
const decodeOriginUrl = Schema.decodeUnknownEffect(OriginUrl);
const decodeClientIp = Schema.decodeUnknownEffect(ClientIp);

export const normalizeEmail = (
  input: unknown,
): Effect.Effect<NormalizedEmail, BoundaryParseError> =>
  typeof input !== "string"
    ? Effect.fail(new BoundaryParseError({ field: "email", reason: "Expected string" }))
    : Effect.suspend(() => {
        const normalized = input.trim().toLowerCase();
        return normalized.length > 0 && emailPattern.test(normalized)
          ? decodeNormalizedEmail(normalized).pipe(
              Effect.mapError(
                () => new BoundaryParseError({ field: "email", reason: "Invalid email" }),
              ),
            )
          : Effect.fail(new BoundaryParseError({ field: "email", reason: "Invalid email" }));
      });

export const normalizePassword = (
  input: unknown,
): Effect.Effect<PasswordText, BoundaryParseError> =>
  typeof input !== "string"
    ? Effect.fail(new BoundaryParseError({ field: "password", reason: "Expected string" }))
    : decodePasswordText(input.normalize("NFKC")).pipe(
        Effect.mapError(
          () => new BoundaryParseError({ field: "password", reason: "Invalid password" }),
        ),
      );

export const parseCallbackUrl = (input: unknown): Effect.Effect<CallbackUrl, BoundaryParseError> =>
  Effect.try({
    try: () => (input instanceof URL ? input : new URL(String(input))),
    catch: () => new BoundaryParseError({ field: "callbackUrl", reason: "Invalid URL" }),
  }).pipe(
    Effect.flatMap(decodeCallbackUrl),
    Effect.mapError(() => new BoundaryParseError({ field: "callbackUrl", reason: "Invalid URL" })),
  );

export const parseOrigin = (input: unknown): Effect.Effect<OriginUrl, BoundaryParseError> =>
  Effect.try({
    try: () => (input instanceof URL ? input : new URL(String(input))),
    catch: () => new BoundaryParseError({ field: "origin", reason: "Invalid URL" }),
  }).pipe(
    Effect.flatMap(decodeOriginUrl),
    Effect.mapError(() => new BoundaryParseError({ field: "origin", reason: "Invalid URL" })),
  );

const canonicalIp = (input: string): string | undefined => {
  const value = input.trim();
  if (value === "") return undefined;
  if (isIP(value) === 4) return new URL(`http://${value}/`).hostname;
  if (isIP(value) === 6) return new URL(`http://[${value}]/`).hostname.slice(1, -1);
  return undefined;
};

export const parseClientIp = (input: unknown): Effect.Effect<ClientIp, BoundaryParseError> =>
  typeof input !== "string"
    ? Effect.fail(new BoundaryParseError({ field: "ip", reason: "Expected string" }))
    : Effect.suspend(() => {
        const normalized = canonicalIp(input);
        return normalized === undefined
          ? Effect.fail(new BoundaryParseError({ field: "ip", reason: "Invalid IP address" }))
          : decodeClientIp(normalized).pipe(
              Effect.mapError(
                () => new BoundaryParseError({ field: "ip", reason: "Invalid IP address" }),
              ),
            );
      });

export const AuthBoundaryLive = Layer.succeed(AuthBoundary)({
  parseEmail: normalizeEmail,
  parsePassword: normalizePassword,
  parseCallbackUrl,
  parseOrigin,
  parseClientIp,
});
