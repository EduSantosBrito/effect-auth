# Opaque Stored Sessions

Effect Auth v1 uses opaque **Session Tokens** with server-side **Rolling Session** records instead of JWT sessions. The default lifetime follows Better Auth's shape: 7-day expiry with refresh after 1 day, but each refresh atomically rotates the **Session Token** and updates the **Session Cookie**. This favours immediate revocation, server-enforced expiry, token hash-at-rest, narrower stolen-token lifetime, and familiar web-app session UX over stateless validation and reduced storage access.
