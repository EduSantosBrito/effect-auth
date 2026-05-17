import { Console, Effect, Layer, Redacted } from "effect";
import { Auth, AuthLive } from "effect-auth";
import { MockAuthEmail, makeMockAuthEmailState } from "effect-auth/email/mock";
import { DevMemoryAuthStorage } from "effect-auth/storage/dev-memory";

const emailState = makeMockAuthEmailState();

const AppLive = AuthLive.dev.pipe(
  Layer.provideMerge(DevMemoryAuthStorage()),
  Layer.provideMerge(MockAuthEmail(emailState)),
);

const email = "demo@example.com";
const password = "correct horse battery staple";

const firstVerificationEmail = Effect.sync(() => {
  const message = emailState.sent.find((email) => email.kind === "EmailVerification");
  if (message === undefined) throw new Error("Expected a verification email to be sent");
  return message;
});

const tokenPreview = (token: Redacted.Redacted<string>) =>
  `${Redacted.value(token).slice(0, 8)}...`;

const demo = Effect.gen(function* () {
  const auth = yield* Auth;

  const signUp = yield* auth.signUp({
    email,
    password,
    name: "Effect Auth Example User",
    verificationCallbackUrl: "http://localhost:3000/auth/verify",
  });
  yield* Console.log(`Signed up ${signUp.user.email}`);

  const verificationEmail = yield* firstVerificationEmail;
  yield* Console.log(
    `Queued ${verificationEmail.kind} email for ${verificationEmail.to} with token ${tokenPreview(
      verificationEmail.token,
    )}`,
  );

  const verified = yield* auth.verifyEmail({ token: verificationEmail.token });
  yield* Console.log(`Verified ${verified.user.email}`);

  const signedIn = yield* auth.signIn({ email, password });
  yield* Console.log(`Signed in ${signedIn.user.email}`);

  const current = yield* auth.currentSession({ sessionToken: signedIn.sessionToken });
  yield* Console.log(
    `Current session ${current.session.id} for ${current.user.email} (${current.tokenRotation._tag})`,
  );
}).pipe(Effect.provide(AppLive));

Effect.runPromise(demo);
