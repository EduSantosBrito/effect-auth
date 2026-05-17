import { Clock, Console, Effect, Layer, Redacted, Schema } from "effect";
import { type EmailMessage, MessageBody } from "effect-email";
import * as TestEmail from "effect-email/test";
import { Auth, AuthLive } from "effect-auth";
import { VerificationToken } from "effect-auth/token";
import { makePostgresLive } from "./database.js";
import { EffectEmailAuthEmail } from "./email.js";

class ExampleFailure extends Schema.TaggedErrorClass<ExampleFailure>()("ExampleFailure", {
  reason: Schema.String,
}) {}

interface ListedSessionLog {
  readonly id: string;
  readonly is_current: boolean;
  readonly user_agent?: string;
}

interface StepEvent {
  readonly event: "effect_auth_postgres_storage_step";
  readonly service: "effect-auth-example";
  readonly flow: "postgres-storage";
  readonly run_id: string;
  readonly step:
    | "storage_configured"
    | "sign_up"
    | "email_sent"
    | "verify_email"
    | "sign_in_primary"
    | "sign_in_secondary"
    | "list_sessions"
    | "change_password"
    | "current_session"
    | "delete_user";
  readonly outcome: "success";
  readonly duration_ms: number;
  readonly database?: {
    readonly url: string;
    readonly schema: "effect-auth generate --prefix auth_";
  };
  readonly user?: {
    readonly id?: string;
    readonly email: string;
  };
  readonly auth?: {
    readonly verification_email_count?: number;
    readonly verification_token_preview?: string;
    readonly session_id?: string;
    readonly session_token_preview?: string;
    readonly rotated_session_token_preview?: string;
    readonly token_rotation?: string;
    readonly active_session_count?: number;
    readonly listed_sessions?: ReadonlyArray<ListedSessionLog>;
  };
  readonly email?: {
    readonly adapter: "effect-email/test";
    readonly from: string;
    readonly to: ReadonlyArray<string>;
    readonly subject: string;
    readonly body_preview: string;
  };
}

const defaultDatabaseUrl = "postgres://effect_auth:effect_auth@localhost:5432/effect_auth_example";
const databaseUrl = process.env.DATABASE_URL ?? defaultDatabaseUrl;

const makeAppLayer = (url: string) => {
  const postgresLive = makePostgresLive(url);
  return AuthLive.dev.pipe(
    Layer.provideMerge(Layer.mergeAll(postgresLive, EffectEmailAuthEmail)),
    Layer.provideMerge(TestEmail.defaultLayer),
  );
};

const redactDatabaseUrl = (url: string): string => url.replace(/:([^:@/]+)@/u, ":***@");

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

const sentEmailAt = (sent: ReadonlyArray<EmailMessage>, index: number, description: string) =>
  Effect.suspend(() => {
    const message = sent[index];
    return message === undefined
      ? Effect.fail(new ExampleFailure({ reason: `Expected ${description} email to be sent` }))
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

const listedSessionLog = (session: {
  readonly id: string;
  readonly isCurrent: boolean;
  readonly userAgent?: string;
}): ListedSessionLog =>
  session.userAgent === undefined
    ? { id: session.id, is_current: session.isCurrent }
    : { id: session.id, is_current: session.isCurrent, user_agent: session.userAgent };

const logStep = (event: StepEvent) => Console.log(JSON.stringify(event, null, 2));

const timed = Effect.fn("timed")(function* <A, E>(effect: Effect.Effect<A, E>) {
  const start = yield* Clock.currentTimeMillis;
  const value = yield* effect;
  const end = yield* Clock.currentTimeMillis;
  return { value, durationMs: end - start };
});

const timedStep = Effect.fn("timedStep")(function* <A, E>(
  event: Omit<StepEvent, "duration_ms" | "outcome">,
  effect: Effect.Effect<A, E>,
) {
  const result = yield* timed(effect);
  yield* logStep({ ...event, outcome: "success", duration_ms: result.durationMs });
  return result.value;
});

const demoProgram = Effect.gen(function* () {
  const startedAt = yield* Clock.currentTimeMillis;
  const runId = `auth_postgres_demo_${startedAt}`;
  const email = `postgres-demo-${startedAt}@example.com`;
  const password = "correct horse battery staple";
  const newPassword = "correct horse battery staple with postgres";
  const auth = yield* Auth;
  const emailInspection = yield* TestEmail.TestEmailInspection;

  yield* logStep({
    event: "effect_auth_postgres_storage_step",
    service: "effect-auth-example",
    flow: "postgres-storage",
    run_id: runId,
    step: "storage_configured",
    outcome: "success",
    duration_ms: 0,
    database: {
      url: redactDatabaseUrl(databaseUrl),
      schema: "effect-auth generate --prefix auth_",
    },
  });

  const signUp = yield* timedStep(
    {
      event: "effect_auth_postgres_storage_step",
      service: "effect-auth-example",
      flow: "postgres-storage",
      run_id: runId,
      step: "sign_up",
      user: { email },
    },
    auth.signUp({
      email,
      password,
      name: "Effect Auth Postgres User",
      verificationCallbackUrl: "http://localhost:3000/auth/verify",
    }),
  );

  const sentEmails = yield* emailInspection.sent;
  const verificationEmail = yield* sentEmailAt(sentEmails, 0, "verification");
  const verificationToken = yield* extractVerificationToken(verificationEmail);
  const verificationTokenPreview = previewRedacted(verificationToken);
  const emailBodyPreview = messageText(verificationEmail.body)
    .replace(Redacted.value(verificationToken), verificationTokenPreview)
    .slice(0, 96);

  yield* logStep({
    event: "effect_auth_postgres_storage_step",
    service: "effect-auth-example",
    flow: "postgres-storage",
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
      from: mailboxLabel(verificationEmail.from),
      to: verificationEmail.to.map(mailboxLabel),
      subject: verificationEmail.subject,
      body_preview: emailBodyPreview,
    },
  });

  const verified = yield* timedStep(
    {
      event: "effect_auth_postgres_storage_step",
      service: "effect-auth-example",
      flow: "postgres-storage",
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

  const primarySignIn = yield* timedStep(
    {
      event: "effect_auth_postgres_storage_step",
      service: "effect-auth-example",
      flow: "postgres-storage",
      run_id: runId,
      step: "sign_in_primary",
      user: { id: verified.user.id, email: String(verified.user.email) },
    },
    auth.signIn({
      email,
      password,
      userAgent: "Effect Auth Postgres Example / primary browser",
    }),
  );

  const secondarySignIn = yield* timedStep(
    {
      event: "effect_auth_postgres_storage_step",
      service: "effect-auth-example",
      flow: "postgres-storage",
      run_id: runId,
      step: "sign_in_secondary",
      user: { id: primarySignIn.user.id, email: String(primarySignIn.user.email) },
    },
    auth.signIn({
      email,
      password,
      userAgent: "Effect Auth Postgres Example / secondary browser",
    }),
  );

  const listed = yield* timed(auth.listSessions({ sessionToken: primarySignIn.sessionToken }));
  yield* logStep({
    event: "effect_auth_postgres_storage_step",
    service: "effect-auth-example",
    flow: "postgres-storage",
    run_id: runId,
    step: "list_sessions",
    outcome: "success",
    duration_ms: listed.durationMs,
    user: { id: listed.value.user.id, email: String(listed.value.user.email) },
    auth: {
      active_session_count: listed.value.sessions.length,
      token_rotation: listed.value.tokenRotation._tag,
      listed_sessions: listed.value.sessions.map(listedSessionLog),
    },
  });

  const changed = yield* timed(
    auth.changePassword({
      sessionToken: primarySignIn.sessionToken,
      currentPassword: password,
      newPassword,
    }),
  );
  yield* logStep({
    event: "effect_auth_postgres_storage_step",
    service: "effect-auth-example",
    flow: "postgres-storage",
    run_id: runId,
    step: "change_password",
    outcome: "success",
    duration_ms: changed.durationMs,
    user: { id: primarySignIn.user.id, email: String(primarySignIn.user.email) },
    auth: {
      rotated_session_token_preview: previewRedacted(changed.value.currentSessionToken),
    },
  });

  const current = yield* timed(
    auth.currentSession({ sessionToken: changed.value.currentSessionToken }),
  );
  yield* logStep({
    event: "effect_auth_postgres_storage_step",
    service: "effect-auth-example",
    flow: "postgres-storage",
    run_id: runId,
    step: "current_session",
    outcome: "success",
    duration_ms: current.durationMs,
    user: { id: current.value.user.id, email: String(current.value.user.email) },
    auth: {
      session_id: current.value.session.id,
      session_token_preview: previewRedacted(changed.value.currentSessionToken),
      token_rotation: current.value.tokenRotation._tag,
    },
  });

  yield* timedStep(
    {
      event: "effect_auth_postgres_storage_step",
      service: "effect-auth-example",
      flow: "postgres-storage",
      run_id: runId,
      step: "delete_user",
      user: { id: current.value.user.id, email: String(current.value.user.email) },
    },
    auth.deleteUser({ sessionToken: changed.value.currentSessionToken, password: newPassword }),
  );
}).pipe(Effect.provide(makeAppLayer(databaseUrl)));

Effect.runPromise(demoProgram);
