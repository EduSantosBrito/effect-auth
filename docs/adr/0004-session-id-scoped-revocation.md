# SessionId-Scoped Session Revocation

Session Management revokes listed sessions by **Session Id** scoped to the current User instead of by **Session Token**. This deliberately diverges from Better Auth's token-based revoke API because Effect Auth stores only hashed Session Tokens at rest; exposing raw tokens in session lists or storing revocable token material would weaken the security boundary, so storage must enforce current-user ownership when revoking by Session Id.
