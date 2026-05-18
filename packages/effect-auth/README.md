# effect-auth

[![npm version](https://img.shields.io/npm/v/effect-auth.svg)](https://www.npmjs.com/package/effect-auth)
[![PR Check](https://github.com/EduSantosBrito/effect-auth/actions/workflows/pr.yml/badge.svg)](https://github.com/EduSantosBrito/effect-auth/actions/workflows/pr.yml)
[![pkg.pr.new](https://pkg.pr.new/badge/EduSantosBrito/effect-auth)](https://pkg.pr.new/~/EduSantosBrito/effect-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/EduSantosBrito/effect-auth/blob/main/LICENSE)

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
- Better Auth-aligned public Users with `name`, `image`, `emailVerified`, and timestamps.
- Credential Accounts for email/password proof material plus secret-free account listing.
- Authenticated profile updates for `name` and `image`.
- Email Verification with one-time hashed Verification Tokens.
- Password Reset and authenticated Password Change.
- Server-side Sessions with listing, revocation, policy configuration, and token rotation.
- HttpOnly SameSite=Lax Session Cookie support for browser flows.
- Bearer Session Token extraction for server-owned API flows.
- Trusted Origin checks for state-changing browser requests.
- Boundary Parse for external email, password, token, and URL inputs.
- Secure Default Password Policy and native Scrypt password hashing.
- Rate Limiter service boundary that applications provide explicitly.
- OAuth provider registry plus authorization-start APIs for sign-in/link flows.
- Storage-backed OAuth State with hashed handles and encrypted PKCE/OIDC secrets.

## Install

```bash
bun add effect-auth effect
```

## Backend Usage

```typescript
import { Effect, Layer } from "effect";
import { Auth, AuthLive } from "effect-auth";
import { MockAuthEmail } from "effect-auth/email/mock";
import { BoundedDevRateLimiter } from "effect-auth/rate-limit";
import { DevMemoryAuthStorage } from "effect-auth/storage/dev-memory";

const AuthTestLayer = AuthLive().pipe(
  Layer.provide(
    Layer.mergeAll(DevMemoryAuthStorage(), MockAuthEmail(), BoundedDevRateLimiter()),
  ),
);

const program = Effect.gen(function* () {
  const auth = yield* Auth;

  const signUp = yield* auth.signUp({
    email: "user@example.com",
    password: "correct horse battery staple",
    name: "Ada Lovelace",
    verificationCallbackUrl: "https://app.example.com/verify",
  });

  return signUp.user;
}).pipe(Effect.provide(AuthTestLayer));
```

`AuthLive(config?)` wires Boundary Parse, Secure Default Password Policy, native Scrypt hashing, token generation, and workflow composition. Auth Storage, Auth Email, and Rate Limiter are always application-provided layers. `DevMemoryAuthStorage`, `MockAuthEmail`, and `BoundedDevRateLimiter` are explicit helpers for examples and tests.

Token TTLs, Session Policy, and encrypted OAuth feature keys are configured through nested Auth Live Config:

```typescript
import { Redacted } from "effect";

const AuthServicesLive = AuthLive({
  session: { ttl: "7 days", updateAge: "1 day" },
  verification: { emailVerificationTtl: "24 hours", passwordResetTtl: "15 minutes" },
  encryptionKey: Redacted.make(process.env.AUTH_ENCRYPTION_KEY ?? ""),
  oauthState: { ttl: "10 minutes" },
}).pipe(
  Layer.provide(Layer.mergeAll(AppAuthStorage, AppAuthEmail, AppRateLimiter)),
);
```

Session Policy controls how long issued/refreshed Sessions remain valid and how old a Session must be before lookup rotates its Session Token. Defaults remain 7 days for `session.ttl` and 1 day for `session.updateAge`. OAuth State defaults to 10 minutes. Encrypted OAuth features require a redacted base64url-encoded 32-byte `encryptionKey` or feature-specific override.

Programmatic Session Management verbs are available on `Auth`:

```typescript
const listed = yield* auth.listSessions({ sessionToken });

yield* auth.revokeSession({ sessionToken, sessionId: listed.sessions[0].id });
yield* auth.revokeOtherSessions({ sessionToken });
yield* auth.revokeSessions({ sessionToken });
```

Listed Sessions include `id`, `userId`, `createdAt`, `updatedAt`, `expiresAt`, `isCurrent`, and optional `ipAddress` / `userAgent`. They never expose raw Session Tokens or token hashes, and listing returns active Sessions only.

Programmatic Identity Core verbs are also available on `Auth`:

```typescript
const updated = yield* auth.updateUser({
  sessionToken,
  name: "Ada Lovelace",
  image: "https://app.example.com/avatar.png",
});

const accounts = yield* auth.listAccounts({ sessionToken });

yield* auth.deleteUser({ sessionToken, password: "current password" });
```

`updateUser` accepts `name` and `image` only; email changes are intentionally out of scope. `listAccounts` returns linked Accounts for the current User without password hashes or provider tokens. Email/password sign-up creates the first Credential Account automatically, and password hashes live on Credential Accounts rather than the User.
`deleteUser` requires the current password for the current Credential Account, is rate-limited, deletes the User and dependent auth records, and returns no deleted user payload.

## OAuth Authorization Start

OAuth start APIs live under `effect-auth/oauth`. `OAuthProviders.layer(...)` validates provider IDs, scopes, PKCE mode, token auth method, and managed authorization parameters. `OAuth.layer` creates authorization URLs and stores short-lived OAuth State rows with hashed public handles and encrypted PKCE verifier/OIDC nonce secrets.

```typescript
import { Effect, Layer, Redacted } from "effect";
import { AuthLiveConfig } from "effect-auth";
import { OAuth, OAuthProviders } from "effect-auth/oauth";
import type { AuthStorage } from "effect-auth/storage";
import type { HttpClient } from "effect/unstable/http/HttpClient";

declare const AppAuthStorage: Layer.Layer<AuthStorage>;
declare const AppHttpClient: Layer.Layer<HttpClient>;

const ProvidersLive = OAuthProviders.layer({
  providers: [
    {
      id: "github",
      clientId: process.env.GITHUB_CLIENT_ID ?? "",
      clientSecret: Redacted.make(process.env.GITHUB_CLIENT_SECRET ?? ""),
      defaultScopes: ["read:user", "user:email"],
      endpoints: {
        authorizationUrl: new URL("https://github.com/login/oauth/authorize"),
        tokenUrl: new URL("https://github.com/login/oauth/access_token"),
      },
      mapProfile: ({ userInfo }) =>
        Effect.succeed({
          providerAccountId: String(userInfo?.id),
          email: String(userInfo?.email),
          emailVerified: false,
          name: String(userInfo?.name ?? "GitHub User"),
          image: null,
        }),
    },
  ],
}).pipe(Layer.provide(AppHttpClient));

const OAuthLive = OAuth.layer.pipe(
  Layer.provideMerge(
    Layer.mergeAll(
      AuthLiveConfig.layer({ encryptionKey: Redacted.make(process.env.AUTH_ENCRYPTION_KEY ?? "") }),
      AppAuthStorage,
      ProvidersLive,
    ),
  ),
);

const program = Effect.gen(function* () {
  const oauth = yield* OAuth;
  return yield* oauth.startSignIn({
    providerId: "github",
    redirectUri: new URL("https://app.example.com/api/auth/oauth/github/callback"),
    scopes: ["repo"],
  });
}).pipe(Effect.provide(OAuthLive));
```

`startSignIn` returns data for your HTTP layer to redirect or serialize. `startLink` additionally requires a valid current Session Token and stores the state-bound User Id. OAuth callback completion, provider token storage, and mounted OAuth HTTP routes are separate follow-up slices.

## Drizzle Postgres Storage

```typescript
import { PgClient } from "@effect/sql-pg";
import { Layer, Redacted } from "effect";
import { AuthLive } from "effect-auth";
import type { AuthEmail } from "effect-auth/email";
import type { RateLimiter } from "effect-auth/rate-limit";
import { DrizzlePg } from "effect-auth/storage/drizzle-pg";
import { authSchema } from "./auth/schema.js";

declare const ResendAuthEmail: Layer.Layer<AuthEmail>;
declare const RedisRateLimiter: Layer.Layer<RateLimiter>;

const PgLive = PgClient.layer({
  url: Redacted.make(process.env.DATABASE_URL ?? ""),
});

const PostgresAuthStorage = DrizzlePg.layer({ schema: authSchema }).pipe(
  Layer.provide(PgLive),
);

export const AppLive = AuthLive().pipe(
  Layer.provide(Layer.mergeAll(PostgresAuthStorage, ResendAuthEmail, RedisRateLimiter)),
);
```

`DrizzlePg.layer(...)` accepts plain Drizzle tables with plural keys: `Users`, `Accounts`, `Sessions`, `Verifications`, and `OAuthStates`. It provides `AuthStorage` from an Effect SQL Postgres client layer and keeps token consumption, OAuth State consumption, session rotation, password reset, password change, revocation, and user deletion operations transactional.

Generate the Drizzle schema TypeScript file once, use its `authSchema` for runtime, and let Drizzle Kit own SQL migrations:

```bash
npx effect-auth generate
npx drizzle-kit generate
npx drizzle-kit migrate
```

The generated schema file exports top-level table values so Drizzle Kit can discover them, plus `authSchema` for runtime wiring:

```typescript
import { pgTable, text } from "drizzle-orm/pg-core";

export const Users = pgTable("auth_users", {
  id: text("id").primaryKey(),
  // ...
});

export const Accounts = pgTable("auth_accounts", {
  // ...
});

export const Sessions = pgTable("auth_sessions", {
  // ...
});

export const Verifications = pgTable("auth_verifications", {
  // ...
});

export const OAuthStates = pgTable("auth_oauth_states", {
  // hashed state handle, provider/flow binding, encrypted PKCE/OIDC secrets, expiry
});

export const authSchema = { Users, Accounts, Sessions, Verifications, OAuthStates };
```

## HTTP Usage

```typescript
import { Effect, Layer, Option } from "effect";
import { AuthLive } from "effect-auth";
import { AuthHttp, AuthHttpConfig, AuthSession, CurrentAuthSession } from "effect-auth/http";
import * as HttpRouter from "effect/unstable/http/HttpRouter";

const AuthServicesLive = AuthLive().pipe(
  Layer.provide(Layer.mergeAll(PostgresAuthStorage, ResendAuthEmail, RedisRateLimiter)),
);

const AuthHttpLive = Layer.mergeAll(
  AuthServicesLive,
  AuthHttpConfig.layer({
    trustedOrigins: [new URL("https://app.example.com")],
    sessionCookieName: "__Host_effect_auth_session",
    secureCookies: true,
  }),
);

const app = HttpRouter.layer.pipe(
  AuthHttp.mount({ basePath: "/api/auth" }),
  Layer.provideMerge(AuthHttpLive),
);

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

Mounted browser sign-in sets the configured HttpOnly SameSite=Lax Session Cookie and does not return Session Tokens in JSON. Programmatic `Auth.signIn` returns a redacted Session Token for server-owned bearer/API flows. The mounted router uses `Layer.provideMerge` intentionally so request-time `Auth` and `AuthHttpConfig` services remain available to the web handler.

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
| `GET`  | `/api/auth/sessions`                |
| `POST` | `/api/auth/update-user`             |
| `GET`  | `/api/auth/accounts`                |
| `POST` | `/api/auth/sessions/revoke`         |
| `POST` | `/api/auth/sessions/revoke-others`  |
| `POST` | `/api/auth/sessions/revoke-all`     |
| `POST` | `/api/auth/password-reset/request`  |
| `POST` | `/api/auth/password-reset/complete` |
| `POST` | `/api/auth/password/change`         |
| `POST` | `/api/auth/delete-user`             |

`GET /sessions` requires a valid Session Token from the configured extractor and returns active, token-free listed sessions. State-changing Session Management routes enforce trusted-origin checks. Cookie-authenticated `POST /sessions/revoke` clears the session cookie when the current Session is revoked, and `POST /sessions/revoke-all` clears it after revoking every current-user Session. `POST /sessions/revoke-others` keeps the current Session cookie valid. Listed-session revocation is Session Id scoped; see `docs/adr/0004-session-id-scoped-revocation.md` for the design rationale.

`POST /update-user` requires a valid Session Token and trusted origin, updates `name` and/or `image`, and returns `{ user }`. `GET /accounts` requires a valid Session Token and returns `{ accounts }`; account responses never include password hashes, access tokens, refresh tokens, ID tokens, or other provider secrets.
`POST /delete-user` requires a valid Session Token, trusted origin, and a `password` body field. Cookie-authenticated deletion clears the Session Cookie and returns `{ ok: true }`.

Identity Core changes the `AuthStorage` contract before 1.0: storage adapters should create Users and Credential Accounts atomically via `createUserWithCredentialAccount`, store password hashes only on Credential Accounts, use the User Id as the credential `accountId`, update User-level `emailVerified`, and expose secret-free account projections through `listUserAccounts`. No legacy credential storage shim is provided.

## Current Scope

`effect-auth` is backend-first and currently focuses on email/password authentication plus the first OAuth authorization-start/state slice. OAuth callback completion, passkeys, multi-factor authentication, organization auth, and additional database-specific storage adapters beyond the built-in Drizzle Postgres adapter are not shipped yet.

Use `AuthStorage` and `AuthEmail` to connect your own database and email provider today. We suggest [`effect-email`](https://github.com/EduSantosBrito/effect-email) for the email provider boundary.

## Example

```bash
bun run example:minimal
bun run --cwd examples/minimal demo

docker compose -f examples/postgres-storage/docker-compose.yml down -v

docker compose -f examples/postgres-storage/docker-compose.yml up -d --wait
bun run build
bun run --cwd examples/postgres-storage auth:schema
bun run --cwd examples/postgres-storage db:generate
bun run --cwd examples/postgres-storage db:migrate
bun run example:postgres
```

The minimal example runs sign-up, email verification, sign-in, and current-session lookup with `DevMemoryAuthStorage` and `MockAuthEmail`, so no `.env` file is needed.

The Postgres storage example runs the same small auth flow with generated Drizzle schema TypeScript, committed Drizzle Kit migrations, `DrizzlePg.layer`, and `@effect/sql-pg`. It does not create or mutate tables at runtime.

See [`examples/minimal/README.md`](https://github.com/EduSantosBrito/effect-auth/blob/main/examples/minimal/README.md) and [`examples/postgres-storage/README.md`](https://github.com/EduSantosBrito/effect-auth/blob/main/examples/postgres-storage/README.md) for the integration shapes.

## Development

```bash
bun install
bun run check
bun run test
bun run build
```

## Contributing

Issues and PRs are welcome.

For non-trivial features or API changes, please open an issue first. PRs that do not fit the project direction, maintenance budget, or current scope may be closed even if the implementation is correct.

Small bug fixes, docs fixes, examples, tests, and clearly scoped improvements are the easiest to review and merge. See [CONTRIBUTING.md](https://github.com/EduSantosBrito/effect-auth/blob/main/CONTRIBUTING.md).

## Security

Please do not open public issues for suspected vulnerabilities. Report them privately through GitHub security advisories for this repository. See [SECURITY.md](https://github.com/EduSantosBrito/effect-auth/blob/main/SECURITY.md).
