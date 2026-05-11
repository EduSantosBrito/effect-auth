import { Clock, Console, Effect, Layer, Redacted, Schema } from "effect";
import { type EmailMessage, MessageBody } from "effect-email";
import * as TestEmail from "effect-email/test";
import { Auth, AuthLive } from "effect-auth";
import { VerificationToken } from "effect-auth/token";
import {
  EffectEmailAuthEmail,
  ExampleAuthStorage,
  makeExampleStorageState,
} from "./dev-adapters.js";

class ExampleFailure extends Schema.TaggedErrorClass<ExampleFailure>()("ExampleFailure", {
  reason: Schema.String,
}) {}

interface StepEvent {
  readonly event: "effect_auth_minimal_step";
  readonly service: "effect-auth-example";
  readonly flow: "minimal";
  readonly run_id: string;
  readonly step: "sign_up" | "email_sent" | "verify_email" | "sign_in" | "current_session";
  readonly outcome: "success";
  readonly duration_ms: number;
  readonly user?: {
    readonly id?: string;
    readonly email: string;
  };
  readonly auth?: {
    readonly verification_email_count?: number;
    readonly verification_token_preview?: string;
    readonly session_id?: string;
    readonly session_token_preview?: string;
    readonly token_rotation?: string;
  };
  readonly email?: {
    readonly adapter: "effect-email/test";
    readonly from: string;
    readonly to: ReadonlyArray<string>;
    readonly subject: string;
    readonly body_preview: string;
  };
}

const storageState = makeExampleStorageState();

const appLayer = AuthLive.dev.pipe(
  Layer.provideMerge(Layer.mergeAll(ExampleAuthStorage(storageState), EffectEmailAuthEmail)),
  Layer.provideMerge(TestEmail.defaultLayer),
);

const preview = (value: string): string => `${value.slice(0, 8)}...`;

const previewRedacted = (value: Redacted.Redacted<string>): string =>
  preview(Redacted.value(value));

const messageText = MessageBody.$match({
  TextOnly: ({ text }) => text,
  HtmlOnly: ({ html }) => html,
  TextAndHtml: ({ text }) => text,
});

const mailboxLabel = (mailbox: EmailMessage["from"]): string =>
  mailbox.displayName === undefined
    ? mailbox.address
    : `${mailbox.displayName} <${mailbox.address}>`;

const firstSentEmail = (sent: ReadonlyArray<EmailMessage>) =>
  Effect.suspend(() => {
    const message = sent[0];
    return message === undefined
      ? Effect.fail(new ExampleFailure({ reason: "Expected verification email to be sent" }))
      : Effect.succeed(message);
  });

const decodeVerificationToken = Schema.decodeUnknownEffect(VerificationToken);

const extractVerificationToken = (message: EmailMessage) => {
  const urlText = messageText(message.body).match(/https?:\/\/\S+/u)?.[0];
  if (urlText === undefined)
    return Effect.fail(new ExampleFailure({ reason: "Expected verification email URL" }));
  return Effect.try({
    try: () => new URL(urlText).searchParams.get("token"),
    catch: () => new ExampleFailure({ reason: "Expected valid verification email URL" }),
  }).pipe(
    Effect.flatMap((token) =>
      token === null
        ? Effect.fail(new ExampleFailure({ reason: "Expected verification email token" }))
        : decodeVerificationToken(token).pipe(
            Effect.mapError(
              () => new ExampleFailure({ reason: "Expected valid verification token" }),
            ),
          ),
    ),
  );
};

const logStep = (event: StepEvent) => Console.log(JSON.stringify(event, null, 2));

const timedStep = Effect.fn("timedStep")(function* <A, E>(
  event: Omit<StepEvent, "duration_ms" | "outcome">,
  effect: Effect.Effect<A, E>,
) {
  const start = yield* Clock.currentTimeMillis;
  const value = yield* effect;
  const end = yield* Clock.currentTimeMillis;
  yield* logStep({ ...event, outcome: "success", duration_ms: end - start });
  return value;
});

const demoProgram = Effect.gen(function* () {
  const startedAt = yield* Clock.currentTimeMillis;
  const runId = `auth_demo_${startedAt}`;
  const auth = yield* Auth;
  const emailInspection = yield* TestEmail.TestEmailInspection;
  const email = "demo@example.com";
  const password = "correct horse battery staple";

  const signUp = yield* timedStep(
    {
      event: "effect_auth_minimal_step",
      service: "effect-auth-example",
      flow: "minimal",
      run_id: runId,
      step: "sign_up",
      user: { email },
    },
    auth.signUp({
      email,
      password,
      verificationCallbackUrl: "http://localhost:3000/auth/verify",
    }),
  );

  const sentEmails = yield* emailInspection.sent;
  const sentEmail = yield* firstSentEmail(sentEmails);
  const verificationToken = yield* extractVerificationToken(sentEmail);
  const verificationTokenPreview = previewRedacted(verificationToken);
  const emailBodyPreview = messageText(sentEmail.body)
    .replace(Redacted.value(verificationToken), verificationTokenPreview)
    .slice(0, 96);

  yield* logStep({
    event: "effect_auth_minimal_step",
    service: "effect-auth-example",
    flow: "minimal",
    run_id: runId,
    step: "email_sent",
    outcome: "success",
    duration_ms: 0,
    user: { id: signUp.user.id, email },
    auth: {
      verification_email_count: sentEmails.length,
      verification_token_preview: verificationTokenPreview,
    },
    email: {
      adapter: "effect-email/test",
      from: mailboxLabel(sentEmail.from),
      to: sentEmail.to.map(mailboxLabel),
      subject: sentEmail.subject,
      body_preview: emailBodyPreview,
    },
  });

  const verified = yield* timedStep(
    {
      event: "effect_auth_minimal_step",
      service: "effect-auth-example",
      flow: "minimal",
      run_id: runId,
      step: "verify_email",
      user: { id: signUp.user.id, email },
      auth: {
        verification_email_count: sentEmails.length,
        verification_token_preview: verificationTokenPreview,
      },
    },
    auth.verifyEmail({ token: verificationToken }),
  );

  const signedIn = yield* timedStep(
    {
      event: "effect_auth_minimal_step",
      service: "effect-auth-example",
      flow: "minimal",
      run_id: runId,
      step: "sign_in",
      user: { id: verified.user.id, email: String(verified.user.email) },
    },
    auth.signIn({ email, password }),
  );

  const currentSessionStartedAt = yield* Clock.currentTimeMillis;
  const current = yield* auth.currentSession({ sessionToken: signedIn.sessionToken });
  const currentSessionEndedAt = yield* Clock.currentTimeMillis;

  yield* logStep({
    event: "effect_auth_minimal_step",
    service: "effect-auth-example",
    flow: "minimal",
    run_id: runId,
    step: "current_session",
    outcome: "success",
    duration_ms: currentSessionEndedAt - currentSessionStartedAt,
    user: { id: signedIn.user.id, email: String(signedIn.user.email) },
    auth: {
      session_id: current.session.id,
      session_token_preview: preview(Redacted.value(signedIn.sessionToken)),
      token_rotation: current.tokenRotation._tag,
    },
  });
}).pipe(Effect.provide(appLayer));

Effect.runPromise(demoProgram);
