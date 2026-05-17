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

## What to read

- `src/main.ts` composes `AuthLive.dev`, `DevMemoryAuthStorage`, and `MockAuthEmail`.
- `src/main.ts` then calls `Auth.signUp`, reads the mock verification email token, verifies the email, signs in, and loads the current session.

For the same flow backed by Drizzle Postgres and Drizzle Kit migrations, see `../postgres-storage`.
