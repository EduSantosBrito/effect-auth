import { Context, Effect, Schema } from "effect";
import type { NormalizedEmail } from "../domain/index.js";
import type { VerificationToken } from "../token/index.js";

export class AuthEmailFailure extends Schema.TaggedErrorClass<AuthEmailFailure>()(
  "AuthEmailFailure",
  {
    reason: Schema.Literals(["DeliveryUnavailable", "InvalidRecipient"]),
  },
) {}

export interface SentAuthEmail {
  readonly kind: "EmailVerification" | "PasswordReset";
  readonly to: NormalizedEmail;
  readonly token: VerificationToken;
  readonly callbackUrl: URL;
}

export class AuthEmail extends Context.Service<
  AuthEmail,
  {
    readonly sendEmailVerification: (input: {
      readonly to: NormalizedEmail;
      readonly token: VerificationToken;
      readonly callbackUrl: URL;
    }) => Effect.Effect<void, AuthEmailFailure>;
    readonly sendPasswordReset: (input: {
      readonly to: NormalizedEmail;
      readonly token: VerificationToken;
      readonly callbackUrl: URL;
    }) => Effect.Effect<void, AuthEmailFailure>;
  }
>()("effect-auth/AuthEmail") {}
export type AuthEmailShape = typeof AuthEmail.Service;
