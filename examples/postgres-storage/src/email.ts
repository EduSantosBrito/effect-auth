import { Effect, Layer, Redacted } from "effect";
import { Email, EmailMessage } from "effect-email";
import { AuthEmail, AuthEmailFailure, type SentAuthEmail } from "effect-auth/email";

const callbackWithToken = ({ callbackUrl, token }: SentAuthEmail) => {
  const url = new URL(callbackUrl);
  url.searchParams.set("token", Redacted.value(token));
  return url.toString();
};

const mapSendFailure = () => new AuthEmailFailure({ reason: "DeliveryUnavailable" });

const makeAuthEmailMessage = (input: SentAuthEmail) => {
  const url = callbackWithToken(input);
  return EmailMessage.make({
    from: "Effect Auth <auth@example.com>",
    to: String(input.to),
    subject: input.kind === "EmailVerification" ? "Verify your email" : "Reset your password",
    text:
      input.kind === "EmailVerification"
        ? `Verify your email: ${url}`
        : `Reset your password: ${url}`,
  }).pipe(Effect.mapError(mapSendFailure));
};

export const EffectEmailAuthEmail: Layer.Layer<AuthEmail, never, Email> = Layer.effect(
  AuthEmail,
  Effect.gen(function* () {
    const email = yield* Email;
    return AuthEmail.of({
      sendEmailVerification: (input) =>
        makeAuthEmailMessage({ kind: "EmailVerification", ...input }).pipe(
          Effect.flatMap(email.send),
          Effect.mapError(mapSendFailure),
          Effect.asVoid,
        ),
      sendPasswordReset: (input) =>
        makeAuthEmailMessage({ kind: "PasswordReset", ...input }).pipe(
          Effect.flatMap(email.send),
          Effect.mapError(mapSendFailure),
          Effect.asVoid,
        ),
    });
  }).pipe(Effect.annotateLogs("service", "AuthEmail")),
);
