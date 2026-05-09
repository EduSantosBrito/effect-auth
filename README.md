# effect-auth

TypeScript SDK for `effect-auth`, built with Bun.

## Imports

```ts
import { AuthBoundaryLive, PublicAuthError } from "effect-auth/domain";
import { NativeScryptPasswordHasher, SecureDefaultPasswordPolicy } from "effect-auth/password";
import { AuthTokenLive } from "effect-auth/token";
import { AuthStorage } from "effect-auth/storage";
import { DevMemoryAuthStorage } from "effect-auth/storage/dev-memory";
import { MockAuthEmail } from "effect-auth/email/mock";
import { BoundedDevRateLimiter, PermissiveDevRateLimiter } from "effect-auth/rate-limit";
import {
  EmailPasswordWorkflowsLive,
  PasswordRecoveryWorkflowsLive,
  SessionWorkflowsLive,
} from "effect-auth/workflows";
import { AuthApi, AuthHttpAdapter, AuthHttpHandlersLive, TrustedOrigins } from "effect-auth/http";
```

The root module intentionally stays minimal. Use deep imports for stable service contracts,
schemas, public errors, workflow layers, and explicitly named dev/mock layers.

## Scripts

```sh
bun install
bun run check
bun test
bun run build
```
