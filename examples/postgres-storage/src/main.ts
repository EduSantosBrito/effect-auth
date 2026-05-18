import { Console, Effect, Layer, Redacted } from "effect";
import { Auth, AuthLive } from "effect-auth";
import { MockAuthEmail, makeMockAuthEmailState } from "effect-auth/email/mock";
import { BoundedDevRateLimiter } from "effect-auth/rate-limit";
import { makePostgresLive } from "./database.js";

const defaultDatabaseUrl = "postgres://effect_auth:effect_auth@localhost:5432/effect_auth_example";
const databaseUrl = process.env.DATABASE_URL ?? defaultDatabaseUrl;
const emailState = makeMockAuthEmailState();

const AppLive = AuthLive().pipe(
  Layer.provide(
    Layer.mergeAll(
      makePostgresLive(databaseUrl),
      MockAuthEmail(emailState),
      BoundedDevRateLimiter(),
    ),
  ),
);

const email = `postgres-demo-${Date.now()}@example.com`;
const password = "correct horse battery staple";

const redactDatabaseUrl = (url: string) => url.replace(/:([^:@/]+)@/u, ":***@");

const tokenPreview = (token: Redacted.Redacted<string>) =>
  `${Redacted.value(token).slice(0, 8)}...`;

const firstVerificationEmail = Effect.gen(function* () {
  const message = emailState.sent.find((email) => email.kind === "EmailVerification");
  return yield* Effect.fromNullishOr(message);
});

const demo = Effect.gen(function* () {
  const auth = yield* Auth;

  yield* Console.log(`Using ${redactDatabaseUrl(databaseUrl)}`);
  yield* Console.log("Schema source: effect-auth generate --prefix auth_");

  const signUp = yield* auth.signUp({
    email,
    password,
    name: "Effect Auth Postgres User",
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
