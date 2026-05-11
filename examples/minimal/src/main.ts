import { BunServices } from "@effect/platform-bun";
import { Clock, Console, Effect, Layer, Redacted, Schema } from "effect";
import { Command, Prompt } from "effect/unstable/cli";
import { Auth, AuthLive } from "effect-auth";
import { makeMockAuthEmailState, MockAuthEmail, type SentAuthEmail } from "effect-auth/email/mock";
import { DevMemoryAuthStorage, makeDevMemoryStorageState } from "effect-auth/storage/dev-memory";

class ExampleFailure extends Schema.TaggedErrorClass<ExampleFailure>()("ExampleFailure", {
  reason: Schema.String,
}) {}

interface StepEvent {
  readonly event: "effect_auth_cli_step";
  readonly service: "effect-auth-example";
  readonly command: "demo";
  readonly run_id: string;
  readonly step: "sign_up" | "verify_email" | "sign_in" | "current_session";
  readonly outcome: "success" | "skipped";
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
  readonly next_action?: string;
}

const storageState = makeDevMemoryStorageState();
const emailState = makeMockAuthEmailState();

const appLayer = AuthLive.dev.pipe(
  Layer.provideMerge(Layer.mergeAll(DevMemoryAuthStorage(storageState), MockAuthEmail(emailState))),
);

const preview = (value: string): string => `${value.slice(0, 8)}...`;

const firstEmail = (sent: ReadonlyArray<SentAuthEmail>) =>
  Effect.suspend(() => {
    const email = sent[0];
    return email === undefined
      ? Effect.fail(new ExampleFailure({ reason: "Expected verification email to be sent" }))
      : Effect.succeed(email);
  });

const confirmStep = (message: string) =>
  Prompt.confirm({
    message,
    initial: true,
    label: { confirm: "run", deny: "skip" },
  });

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

const skippedStep = (event: Omit<StepEvent, "duration_ms" | "outcome">) =>
  logStep({ ...event, outcome: "skipped", duration_ms: 0 });

const demoProgram = Effect.gen(function* () {
  const startedAt = yield* Clock.currentTimeMillis;
  const runId = `auth_demo_${startedAt}`;
  const auth = yield* Auth;
  const email = "demo@example.com";
  const password = "correct horse battery staple";

  const runSignUp = yield* confirmStep("Step 1: create an email/password user?");
  if (!runSignUp) {
    return yield* skippedStep({
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "sign_up",
      next_action: "Run sign-up to create a verification token.",
    });
  }

  const signUp = yield* timedStep(
    {
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "sign_up",
      user: { email },
      next_action: "Verify the email using the mock email token.",
    },
    auth.signUp({
      email,
      password,
      verificationCallbackUrl: "http://localhost:3000/auth/verify",
    }),
  );

  const verificationEmail = yield* firstEmail(emailState.sent);
  const runVerify = yield* confirmStep("Step 2: verify the mock email token?");
  if (!runVerify) {
    return yield* skippedStep({
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "verify_email",
      user: { id: signUp.user.id, email },
      auth: {
        verification_email_count: emailState.sent.length,
        verification_token_preview: preview(Redacted.value(verificationEmail.token)),
      },
      next_action: "Run verification before signing in.",
    });
  }

  const verified = yield* timedStep(
    {
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "verify_email",
      user: { id: signUp.user.id, email },
      auth: {
        verification_email_count: emailState.sent.length,
        verification_token_preview: preview(Redacted.value(verificationEmail.token)),
      },
      next_action: "Sign in to create a session.",
    },
    auth.verifyEmail({ token: verificationEmail.token }),
  );

  const runSignIn = yield* confirmStep("Step 3: sign in and create a session?");
  if (!runSignIn) {
    return yield* skippedStep({
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "sign_in",
      user: { id: verified.user.id, email: String(verified.user.email) },
      next_action: "Run sign-in before reading the current session.",
    });
  }

  const signedIn = yield* timedStep(
    {
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "sign_in",
      user: { id: verified.user.id, email: String(verified.user.email) },
      next_action: "Read the current session using the issued session token.",
    },
    auth.signIn({ email, password }),
  );

  const runCurrentSession = yield* confirmStep("Step 4: read the current session?");
  if (!runCurrentSession) {
    return yield* skippedStep({
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "current_session",
      user: { id: signedIn.user.id, email: String(signedIn.user.email) },
      auth: {
        session_id: signedIn.session.id,
        session_token_preview: preview(Redacted.value(signedIn.sessionToken)),
      },
      next_action: "Run current-session lookup to complete the flow.",
    });
  }

  const current = yield* timedStep(
    {
      event: "effect_auth_cli_step",
      service: "effect-auth-example",
      command: "demo",
      run_id: runId,
      step: "current_session",
      user: { id: signedIn.user.id, email: String(signedIn.user.email) },
      auth: {
        session_id: signedIn.session.id,
        session_token_preview: preview(Redacted.value(signedIn.sessionToken)),
      },
    },
    auth.currentSession({ sessionToken: signedIn.sessionToken }),
  );

  yield* logStep({
    event: "effect_auth_cli_step",
    service: "effect-auth-example",
    command: "demo",
    run_id: runId,
    step: "current_session",
    outcome: "success",
    duration_ms: 0,
    user: { id: signedIn.user.id, email: String(signedIn.user.email) },
    auth: {
      session_id: current.session.id,
      session_token_preview: preview(Redacted.value(signedIn.sessionToken)),
      token_rotation: current.tokenRotation._tag,
    },
  });
}).pipe(Effect.provide(appLayer));

const demo = Command.make("demo", {}, () => demoProgram).pipe(
  Command.withDescription("Walk through sign-up, verification, sign-in, and session lookup."),
);

const cli = Command.make("effect-auth-example", {}, () =>
  Console.log("Run `bun run demo` to manually step through the auth flow."),
).pipe(
  Command.withDescription("Minimal effect-auth CLI example."),
  Command.withSubcommands([demo]),
);

const main = Command.run(cli, { version: "0.1.0" }).pipe(Effect.provide(BunServices.layer));

Effect.runPromise(main);
