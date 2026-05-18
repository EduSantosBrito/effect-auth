# Changelog

All notable user-facing changes should be documented here.

This project follows npm package versions for `effect-auth`. While the package is `0.x`, minor releases may include breaking changes.

## 0.5.0

- Add first-class configured Effect HttpApi integration via `AuthHttp.configure(...)`, including package-owned API contract, routes, middleware, auth helpers, runtime layer wiring, cookie metadata, bearer refresh metadata, exported public HTTP schemas, and OAuth route-family support.
- Document the configured HTTP integration path in the package README and examples.
- Breaking: the configured HTTP surface supersedes the legacy opaque mount-style HTTP DX for new applications.

## 0.4.0

- Add `effect-auth generate` to emit Drizzle Postgres schema TypeScript for Drizzle Kit migrations.
- Export `DevMemoryAuthStorage` and `MockAuthEmail` helpers for examples and tests.

## 0.3.0

- Add Drizzle Postgres Auth Storage as an optional production storage adapter.
- Add authenticated self-service user deletion through Auth and HTTP, including password proof, rate limiting, cookie clearing, and storage-backed deletion.

## 0.2.2

- Improve test runtime by using deterministic password hashing in workflow and HTTP tests.

## 0.2.1

- Include package README in published metadata.

## 0.2.0

- Email/password workflows.
- Email verification and password reset tokens.
- Server-side sessions with revocation and token rotation.
- HTTP auth adapter.
- Rate limiter service boundary.
