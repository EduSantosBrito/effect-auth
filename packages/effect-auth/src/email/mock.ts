import { Context, Effect, Layer, Schema } from "effect";
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

export interface MockAuthEmailState {
  readonly sent: Array<SentAuthEmail>;
}

export const makeMockAuthEmailState = (): MockAuthEmailState => ({ sent: [] });

export const makeMockAuthEmail = (
  state = makeMockAuthEmailState(),
): AuthEmailShape & { readonly state: MockAuthEmailState } => ({
  state,
  sendEmailVerification: (input) =>
    Effect.sync(() => state.sent.push({ kind: "EmailVerification", ...input })).pipe(Effect.asVoid),
  sendPasswordReset: (input) =>
    Effect.sync(() => state.sent.push({ kind: "PasswordReset", ...input })).pipe(Effect.asVoid),
});

export const MockAuthEmail = (state?: MockAuthEmailState) =>
  Layer.succeed(AuthEmail)(makeMockAuthEmail(state));
