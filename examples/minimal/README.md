# Minimal effect-auth Example

Uses `effect-auth` from this monorepo with `workspace:*` and `effect-email/test` for inspectable no-network email sends.

## Flow

1. Provide an `AuthStorage` layer for public Users, Credential Accounts, verification tokens, active session listing, user-scoped session revocation, and self-service user deletion.
2. Bridge `effect-email`'s `Email` service to `effect-auth`'s `AuthEmail` port.
3. Compose those layers with `AuthLive.dev`.
4. Call `Auth.signUp` with an email, password, display name, and verification callback URL.
5. Read the captured `effect-email/test` message and extract the verification token from the email URL.
6. Call `Auth.verifyEmail`, then `Auth.signIn`, then `Auth.currentSession`.

The example logs each step as structured JSON. The email log includes the `effect-email/test` adapter, sender, recipients, subject, redacted body preview, and redacted token preview.

## Run

Run from the repository root:

```bash
bun run example:minimal
```

Run the same deterministic auth flow directly:

```bash
bun run --cwd examples/minimal demo
```

No `.env` file is needed.

## Important Files

- `src/dev-adapters.ts` provides the local in-memory storage adapter and the `effect-email` to `AuthEmail` bridge.
- `src/main.ts` composes the layers and runs the sign-up, verification, sign-in, and session flow.
