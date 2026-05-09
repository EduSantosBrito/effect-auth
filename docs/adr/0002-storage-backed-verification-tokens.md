# Storage-Backed Verification Tokens

Email verification and password reset use opaque random **Verification Tokens** that are hashed at rest, short-lived, and consumed once through **Auth Storage**. The default TTL is 24 hours for email verification and 15 minutes for password reset, with per-workflow configuration. This rejects stateless signed email-verification JWTs because replay resistance, revocation, and atomic one-time consumption are more important for Effect Auth's security-first default than avoiding token storage.
