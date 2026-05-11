# effect-auth

Server-side authentication for Effect applications.

`effect-auth` owns authentication workflows, session issuance, token handling, and storage boundaries while keeping persistence and email delivery explicit in your app. The first supported authentication method is email/password.

## Why effect-auth

Authentication code tends to mix transport, storage, crypto, validation, and application policy in one place. That makes it hard to test and easy to leak security decisions into route handlers.

`effect-auth` keeps those concerns separate:

- Auth Workflows are transport-neutral Effect services.
- Auth Storage is an application-provided Effect service.
- Auth Email is an application-provided Effect service.
- Auth HTTP Adapter maps browser/API requests to workflows and owns web defaults.
- Secret values use Effect `Redacted` types instead of plain strings.

## Features

- Email/password sign-up and sign-in.
- Email Verification with one-time hashed Verification Tokens.
- Password Reset and authenticated Password Change.
- Server-side Sessions with revocation and token rotation.
- HttpOnly SameSite=Lax Session Cookie support for browser flows.
- Bearer Session Token extraction for server-owned API flows.
- Trusted Origin checks for state-changing browser requests.
- Boundary Parse for external email, password, token, and URL inputs.
- Secure Default Password Policy and native Scrypt password hashing.
- Rate Limiter service boundary with development presets.
- Dev Memory Storage and Mock Auth Email for tests/examples.

## Install

```sh
bun add effect-auth effect
```

## Backend Usage

```ts
import { Effect, Layer } from "effect";
import { Auth, AuthLive } from "effect-auth";
import { MockAuthEmail } from "effect-auth/email/mock";
import { DevMemoryAuthStorage } from "effect-auth/storage/dev-memory";

const AuthTestLayer = AuthLive.dev.pipe(
  Layer.provide(DevMemoryAuthStorage()),
  Layer.provide(MockAuthEmail()),
);

const program = Effect.gen(function* () {
  const auth = yield* Auth;

  const signUp = yield* auth.signUp({
    email: "user@example.com",
    password: "correct horse battery staple",
    verificationCallbackUrl: "https://app.example.com/verify",
  });

  return signUp.user;
}).pipe(Effect.provide(AuthTestLayer));
```

`AuthLive.dev` wires Boundary Parse, Secure Default Password Policy, native Scrypt hashing, token generation, workflow composition, and a permissive development Rate Limiter. `AuthLive.default` is currently an alias for `AuthLive.dev`. Production apps should use `AuthLive.production` and provide a real Rate Limiter.

Token TTLs are configured at the workflow seam:

```ts
import { VerificationTokenConfigLive } from "effect-auth";

const TokenPolicyLive = VerificationTokenConfigLive({
  emailVerificationTtl: "24 hours",
  passwordResetTtl: "15 minutes",
});
```

## HTTP Usage

```ts
import { Effect, Layer, Option } from "effect";
import { AuthLive, VerificationTokenConfigLive } from "effect-auth";
import { AuthHttp, AuthHttpConfig, AuthSession, CurrentAuthSession } from "effect-auth/http";
import * as HttpRouter from "effect/unstable/http/HttpRouter";

const appLayer = Layer.mergeAll(
  AuthLive.production,
  AuthHttpConfig.layer({
    trustedOrigins: ["https://app.example.com"],
    sessionCookieName: "__Host_effect_auth_session",
    secureCookies: true,
  }),
  VerificationTokenConfigLive({
    emailVerificationTtl: "24 hours",
    passwordResetTtl: "15 minutes",
  }),
).pipe(
  Layer.provide(PostgresAuthStorage),
  Layer.provide(ResendAuthEmail),
  Layer.provide(RedisRateLimiter),
);

const app = HttpRouter.layer.pipe(AuthHttp.mount({ basePath: "/api/auth" }));

const protectedProgram = Effect.gen(function* () {
  const authSession = yield* AuthSession;
  return authSession.user;
}).pipe(AuthHttp.requireAuth);

const navbarProgram = Effect.gen(function* () {
  const session = yield* CurrentAuthSession;
  return Option.match(session.current, {
    onNone: () => ({ signedIn: false }),
    onSome: ({ user }) => ({ signedIn: true, user }),
  });
}).pipe(AuthHttp.optionalAuth);
```

Mounted browser sign-in sets the configured HttpOnly SameSite=Lax Session Cookie and does not return Session Tokens in JSON. Programmatic `Auth.signIn` returns a redacted Session Token for server-owned bearer/API flows.

## HTTP Endpoints

Mounted with `AuthHttp.mount({ basePath: "/api/auth" })`:

| Method | Path                                |
| ------ | ----------------------------------- |
| `POST` | `/api/auth/sign-up/email`           |
| `POST` | `/api/auth/verify-email`            |
| `POST` | `/api/auth/resend-verification`     |
| `POST` | `/api/auth/sign-in/email`           |
| `GET`  | `/api/auth/session`                 |
| `POST` | `/api/auth/sign-out`                |
| `POST` | `/api/auth/password-reset/request`  |
| `POST` | `/api/auth/password-reset/complete` |
| `POST` | `/api/auth/password/change`         |

## Current Scope

`effect-auth` is backend-first and currently focuses on email/password authentication. OAuth, passkeys, multi-factor authentication, organization auth, and database-specific storage packages are not shipped yet.

Use `AuthStorage` and `AuthEmail` to connect your own database and email provider today.

## Example

```sh
bun run example:minimal
bun run --cwd examples/minimal demo
```

The minimal example uses Dev Memory Storage and Mock Auth Email, so no `.env` file is needed.

## Development

```sh
bun install
bun run check
bun run test
bun run build
```

## Contributing

Issues and pull requests are welcome while the API is still young. Please keep changes small, tested, and aligned with the server-side Effect model.

## Security

Please do not open public issues for suspected vulnerabilities. Report them privately through GitHub security advisories for this repository.
