# Changelog

All notable user-facing changes should be documented here.

This project follows npm package versions for `effect-auth`. While the package is `0.x`, minor releases may include breaking changes.

## Unreleased

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
