import { createHash, randomBytes } from "node:crypto";
import { Context, Effect, Layer, Redacted, Schema } from "effect";

const tokenFormat = Schema.String.pipe(
  Schema.check(
    Schema.makeFilter((value) =>
      /^[A-Za-z0-9_-]{43}$/u.test(value) ? undefined : "Expected generated token format",
    ),
  ),
);

export const VerificationToken = Schema.RedactedFromValue(tokenFormat, {
  label: "VerificationToken",
});
export type VerificationToken = typeof VerificationToken.Type;

export const SessionToken = Schema.RedactedFromValue(tokenFormat, { label: "SessionToken" });
export type SessionToken = typeof SessionToken.Type;

export const TokenHash = Schema.RedactedFromValue(Schema.String, { label: "TokenHash" });
export type TokenHash = typeof TokenHash.Type;

export class TokenGenerationFailure extends Schema.TaggedErrorClass<TokenGenerationFailure>()(
  "TokenGenerationFailure",
  {
    reason: Schema.Literals(["UnavailableEntropy", "HashingFailed"]),
  },
) {}

export class AuthToken extends Context.Service<
  AuthToken,
  {
    readonly makeVerificationToken: () => Effect.Effect<
      { readonly token: VerificationToken; readonly hash: TokenHash },
      TokenGenerationFailure
    >;
    readonly makeSessionToken: () => Effect.Effect<
      { readonly token: SessionToken; readonly hash: TokenHash },
      TokenGenerationFailure
    >;
    readonly hashToken: (
      token: VerificationToken | SessionToken,
    ) => Effect.Effect<TokenHash, TokenGenerationFailure>;
  }
>()("effect-auth/AuthToken") {}
export type AuthTokenShape = typeof AuthToken.Service;

const sha256 = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const decodeTokenHash = Schema.decodeUnknownEffect(TokenHash);
const decodeVerificationToken = Schema.decodeUnknownEffect(VerificationToken);
const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);

export const hashTokenValue = (
  token: VerificationToken | SessionToken,
): Effect.Effect<TokenHash, TokenGenerationFailure> =>
  decodeTokenHash(sha256(Redacted.value(token))).pipe(
    Effect.mapError(() => new TokenGenerationFailure({ reason: "HashingFailed" })),
  );

const makeVerificationTokenPair = Effect.fn("AuthToken.makeVerificationToken")(function* () {
  const token = yield* Effect.try({
    try: () => randomBytes(32).toString("base64url"),
    catch: () => new TokenGenerationFailure({ reason: "UnavailableEntropy" }),
  }).pipe(
    Effect.flatMap(decodeVerificationToken),
    Effect.mapError(() => new TokenGenerationFailure({ reason: "UnavailableEntropy" })),
  );
  const hash = yield* hashTokenValue(token);
  return { token, hash };
});

const makeSessionTokenPair = Effect.fn("AuthToken.makeSessionToken")(function* () {
  const token = yield* Effect.try({
    try: () => randomBytes(32).toString("base64url"),
    catch: () => new TokenGenerationFailure({ reason: "UnavailableEntropy" }),
  }).pipe(
    Effect.flatMap(decodeSessionToken),
    Effect.mapError(() => new TokenGenerationFailure({ reason: "UnavailableEntropy" })),
  );
  const hash = yield* hashTokenValue(token);
  return { token, hash };
});

export const AuthTokenLive = Layer.succeed(AuthToken)({
  makeVerificationToken: makeVerificationTokenPair,
  makeSessionToken: makeSessionTokenPair,
  hashToken: hashTokenValue,
});
