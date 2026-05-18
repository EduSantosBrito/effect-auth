# Minimal effect-auth Example

Smallest useful `effect-auth` flow: in-memory storage, mock email, sign-up, email verification, sign-in, and current-session lookup.

## Run

From the repository root:

```bash
bun run example:minimal
```

Or run the example directly:

```bash
bun run --cwd examples/minimal demo
```

No `.env` file is needed.

## OAuth extension sketch

OAuth is not wired into this smallest example, but the secure shape is the same explicit-dependency style:

```typescript
import { Config, Effect, Layer } from "effect";
import { AuthLive, OAuth, OAuthProviders } from "effect-auth";
import { AuthHttp } from "effect-auth/http";

const AuthSettings = Config.all({
  encryptionKey: Config.redacted("AUTH_ENCRYPTION_KEY"),
});

const ProvidersLive = OAuthProviders.layer(
  Config.all({
    providers: Config.all([
      Config.all({
        id: Config.succeed("github"),
        clientId: Config.string("GITHUB_CLIENT_ID"),
        clientSecret: Config.redacted("GITHUB_CLIENT_SECRET"),
        defaultScopes: Config.succeed(["read:user", "user:email"]),
        endpoints: Config.succeed({
          authorizationUrl: new URL("https://github.com/login/oauth/authorize"),
          tokenUrl: new URL("https://github.com/login/oauth/access_token"),
          userInfoUrl: new URL("https://api.github.com/user"),
        }),
      }),
    ]),
  }),
);

const AuthLiveLayer = Layer.unwrap(
  AuthSettings.asEffect().pipe(
    Effect.map(({ encryptionKey }) =>
      AuthLive({ encryptionKey }).pipe(
        Layer.provide(Layer.mergeAll(AppAuthStorage, AppAuthEmail, AppRateLimiter)),
      ),
    ),
  ),
);

const authHttp = AuthHttp.configure({ basePath: "/api/auth", oauth: true });

const OAuthRoutes = authHttp.routes.pipe(
  Layer.provideMerge(
    Layer.mergeAll(
      OAuth.layer,
      ProvidersLive,
      authHttp.layer({ baseUrl: new URL("https://app.example.com") }),
    ),
  ),
);
```

Use the package README for the full OAuth/OIDC setup, including provider endpoints, HTTP client wiring, and Provider Token Protection.

## What to read

- `src/main.ts` composes `AuthLive()`, `DevMemoryAuthStorage`, `MockAuthEmail`, and an explicit `BoundedDevRateLimiter`.
- `src/main.ts` then calls `Auth.signUp`, reads the mock verification email token, verifies the email, signs in, and loads the current session.

For the same flow backed by Drizzle Postgres and Drizzle Kit migrations, see `../postgres-storage`.
