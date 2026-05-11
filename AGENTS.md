./.repos/effect is used as reference to check Effect v4 API implementations and documentations. Always use this before deciding on which Effect API to use. Read the TSDocs properly.

./.repos/better-auth is used as reference to check which authentication features we need to implement

./.repos/opencode and ./.repos/t3code are used as reference of big applications that uses Effect in production.

Every public API change must consider whether these also need updates:
- README.md
- examples
- packages/effect-auth/test/public-api-imports.ts
