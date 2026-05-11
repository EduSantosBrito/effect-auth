import { Effect, Layer } from "effect";
import { AuthEmail, type AuthEmailShape, type SentAuthEmail } from "./index.js";

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
