# Contributing

Thanks for your interest in `effect-auth`.

## Contribution Policy

Issues and PRs are welcome.

For non-trivial features or API changes, please open an issue first. PRs that do not fit the project direction, maintenance budget, or current scope may be closed even if the implementation is correct.

Small bug fixes, docs fixes, examples, tests, and clearly scoped improvements are the easiest to review and merge.

By participating, you agree to follow the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Setup

```sh
bun install
bun run check
bun run test
bun run build
```

## Pull Requests

- Keep PRs small and focused.
- Include tests for behavior changes.
- Update docs and examples for public API changes.
- Use a conventional PR title, such as `fix: reject expired sessions` or `docs: clarify storage adapter`.
- Do not include unrelated formatting or refactors.

Public API changes should consider updates to:

- `README.md`
- `examples`
- `packages/effect-auth/test/public-api-imports.ts`

## Issues

Before opening an issue, search existing issues to avoid duplicates.

Bug reports should include:

- Version.
- Reproduction.
- Current behavior.
- Expected behavior.
- Runtime and package manager versions.

Feature requests should describe the problem first, then the proposed API or behavior.

## Security

Do not report vulnerabilities in public issues. See [SECURITY.md](./SECURITY.md).
