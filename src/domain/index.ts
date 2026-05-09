import { Context, Effect, Layer, Schema } from "effect";

export const NormalizedEmail = Schema.String.pipe(Schema.brand("NormalizedEmail"));
export type NormalizedEmail = typeof NormalizedEmail.Type;

export const PasswordText = Schema.RedactedFromValue(Schema.String, { label: "PasswordText" });
export type PasswordText = typeof PasswordText.Type;

export const CallbackUrl = Schema.instanceOf(URL).pipe(Schema.brand("CallbackUrl"));
export type CallbackUrl = typeof CallbackUrl.Type;

export const OriginUrl = Schema.instanceOf(URL).pipe(Schema.brand("OriginUrl"));
export type OriginUrl = typeof OriginUrl.Type;

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

export interface AuthBoundaryShape {
  readonly parseEmail: (input: unknown) => Effect.Effect<NormalizedEmail, BoundaryParseError>;
  readonly parsePassword: (input: unknown) => Effect.Effect<PasswordText, BoundaryParseError>;
  readonly parseCallbackUrl: (input: unknown) => Effect.Effect<CallbackUrl, BoundaryParseError>;
  readonly parseOrigin: (input: unknown) => Effect.Effect<OriginUrl, BoundaryParseError>;
}

export class AuthBoundary extends Context.Service<AuthBoundary, AuthBoundaryShape>()(
  "effect-auth/domain/AuthBoundary",
) {}

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

export const normalizeEmail = (
  input: unknown,
): Effect.Effect<NormalizedEmail, BoundaryParseError> =>
  typeof input !== "string"
    ? Effect.fail(new BoundaryParseError({ field: "email", reason: "Expected string" }))
    : Effect.suspend(() => {
        const normalized = input.trim().toLowerCase();
        return normalized.length > 0 && emailPattern.test(normalized)
          ? Schema.decodeUnknownEffect(NormalizedEmail)(normalized).pipe(
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
    : Schema.decodeUnknownEffect(PasswordText)(input.normalize("NFKC")).pipe(
        Effect.mapError(
          () => new BoundaryParseError({ field: "password", reason: "Invalid password" }),
        ),
      );

export const parseCallbackUrl = (input: unknown): Effect.Effect<CallbackUrl, BoundaryParseError> =>
  Effect.try({
    try: () => (input instanceof URL ? input : new URL(String(input))),
    catch: () => new BoundaryParseError({ field: "callbackUrl", reason: "Invalid URL" }),
  }).pipe(
    Effect.flatMap((url) => Schema.decodeUnknownEffect(CallbackUrl)(url)),
    Effect.mapError(() => new BoundaryParseError({ field: "callbackUrl", reason: "Invalid URL" })),
  );

export const parseOrigin = (input: unknown): Effect.Effect<OriginUrl, BoundaryParseError> =>
  Effect.try({
    try: () => (input instanceof URL ? input : new URL(String(input))),
    catch: () => new BoundaryParseError({ field: "origin", reason: "Invalid URL" }),
  }).pipe(
    Effect.flatMap((url) => Schema.decodeUnknownEffect(OriginUrl)(url)),
    Effect.mapError(() => new BoundaryParseError({ field: "origin", reason: "Invalid URL" })),
  );

export const AuthBoundaryLive = Layer.succeed(AuthBoundary)({
  parseEmail: normalizeEmail,
  parsePassword: normalizePassword,
  parseCallbackUrl,
  parseOrigin,
});
