# Minimal effect-auth Example

Uses `effect-auth` from this monorepo with `workspace:*`.

Run from the repository root:

```sh
bun run example:minimal
```

Run the interactive auth flow:

```sh
bun run --cwd examples/minimal demo
```

The `demo` command asks before each step and emits one structured wide event per step. This example uses in-memory storage and mock email, so no `.env` file is needed.
