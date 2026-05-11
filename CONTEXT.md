# Effect Auth

Effect Auth provides server-side authentication workflows for Effect applications while keeping persistence, delivery, and transport boundaries explicit.

## Language

**Session Core**:
The foundational signed-in user lifecycle: issue, look up, refresh, list, and revoke sessions.
_Avoid_: Session plugin, session extras

**Session**:
A server-side record proving that a user is signed in until expiry or revocation.
_Avoid_: Login, cookie

**Session Token**:
An opaque secret presented by a client to identify a Session.
_Avoid_: Session id, JWT

**Session Id**:
A non-secret identifier used to refer to a Session after ownership has been proven.
_Avoid_: Session token

**Session Management**:
Authenticated user operations for viewing and revoking that user's Sessions.
_Avoid_: Device plugin, admin sessions

**Current Session**:
The Session identified by the Session Token used for the current request.
_Avoid_: Active device

**Session Policy**:
The product rules that determine Session lifetime and refresh cadence.
_Avoid_: Token config

## Relationships

- A **Session** belongs to exactly one **User**.
- A **Session Token** identifies exactly one active **Session** until rotation, expiry, or revocation.
- A **Session Id** may be used for **Session Management** only after the current User is known.
- **Session Management** lists Sessions and revokes Sessions for the current User.
- A listed **Session** exposes metadata and whether it is the **Current Session**, never token material.
- **Session Management** lists only active Sessions; expired or revoked Sessions are audit/history data.
- **Revoke All Sessions** revokes every Session for the current User, including the current Session.
- **Session Policy** defines Session TTL and update age; freshness policy is separate and deferred until needed.
- **Session Core** must be stable before adding OAuth account linking or advanced authenticators.

## Example Dialogue

> **Dev:** "Should OAuth be next?"
> **Domain expert:** "No. Finish **Session Core** first so every future authenticator shares the same session lifecycle."

## Flagged Ambiguities

- "Next step" resolved as **Session Core**, not OAuth/accounts, user management, passkeys, or 2FA.
- First **Session Core** slice resolved as **Session Management** with list and revoke operations.
- Revoking a listed **Session** uses **Session Id** scoped to the current User, not **Session Token**.
- "Revoke all sessions" resolved to include the current **Session**; use "revoke other sessions" to stay signed in locally.
- Listed **Sessions** expose id, timestamps, current-session marker, and optional IP/user-agent metadata; never token hash or raw token.
- **Session Policy** first includes `sessionTtl` and `sessionUpdateAge`; `freshAge` is deferred.
- Public workflow names follow Better Auth verbs where semantics match: list sessions, revoke one session, revoke other sessions, revoke sessions.
- **Session Management** is an end-to-end capability: core workflows plus HTTP endpoints.
- Storage enforces current-user ownership for SessionId-scoped revocation.
- Session lists exclude expired and revoked Sessions.
