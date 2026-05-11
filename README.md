# effect-auth

Backend-first email/password auth for Effect applications.

## Backend DX

```ts
import { Effect, Layer, Option } from "effect";
import { Auth, AuthLive } from "effect-auth";
import { AuthHttp, AuthHttpConfigLayer, AuthSession, CurrentAuthSession } from "effect-auth/http";
import * as HttpRouter from "effect/unstable/http/HttpRouter";

const appLayer = Layer.mergeAll(
  AuthLive.default,
  AuthHttpConfigLayer({
    trustedOrigins: ["https://app.example.com"],
  }),
).pipe(Layer.provide(PostgresAuthStorage), Layer.provide(ResendAuthEmail));

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

`AuthLive.default` wires boundary parsing, secure password policy, native scrypt hashing, token generation, rate limiting, and the flat `Auth` service. Applications still provide storage and email explicitly.

Mounted browser sign-in sets an HttpOnly SameSite=Lax session cookie and does not return session tokens in JSON. Programmatic `Auth.signIn` returns a redacted session token for server-owned bearer/API flows.

## Scripts

```sh
bun install
bun run check
bun run test
bun run build
```
