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
A non-secret opaque identifier used to refer to a Session after ownership has been proven.
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

**Identity Core**:
The foundational signed-in identity surface: User profile fields plus provider-specific Accounts used across first-party and future linked authenticators.
_Avoid_: OAuth, user metadata plugin, account plugin

**Display Name**:
The required non-blank user-facing name stored on a User and returned to clients.
_Avoid_: Username, full name, account name

**Normalized Email**:
The lowercase trimmed email address used as the canonical sign-in identifier for a User.
_Avoid_: Raw email, login string

**Profile Image**:
An optional nullable URL user-facing image reference stored on a User and returned to clients.
_Avoid_: Avatar plugin, provider picture

**Account**:
A provider-specific authentication record linked to a User, holding credential or future provider authentication data.
_Avoid_: User, Session, profile

**Credential Account**:
An Account for email/password authentication where the password hash belongs to the Account, not the User.
_Avoid_: Email password credential

**Account Visibility**:
Authenticated user ability to list linked Accounts without exposing provider secrets or credential hashes.
_Avoid_: Account management, OAuth token access

**User Deletion**:
Compliance-driven hard deletion of the Current User and that User's dependent auth records after proof of control.
_Avoid_: Account deactivation, session cleanup

**Auth Storage**:
The persistence boundary that stores Users, Accounts, Sessions, and Verification Tokens while preserving auth invariants.
_Avoid_: User-implemented auth logic, generic repository

**Storage Adapter**:
A packaged integration that wires Auth Storage to a specific persistence technology without making app developers reimplement auth behavior.
_Avoid_: ORM abstraction, custom AuthStorage implementation

**Drizzle Postgres Storage Adapter**:
The first production Storage Adapter, backed by Drizzle and Postgres.
_Avoid_: Drizzle ORM abstraction, SQL adapter

**Verification Token**:
An opaque short-lived secret used for email verification or password reset and consumed exactly once.
_Avoid_: JWT verification link, reset code

## Relationships

- A **Session** belongs to exactly one **User**.
- A **Session Token** identifies exactly one active **Session** until rotation, expiry, or revocation.
- A **Session Id** may be used for **Session Management** only after the current User is known.
- **Session Management** lists Sessions and revokes Sessions for the current User.
- **Session Management** lists active Sessions newest first by creation time.
- A listed **Session** exposes metadata and whether it is the **Current Session**, never token material.
- **Session Management** lists only active Sessions; expired or revoked Sessions are audit/history data until **User Deletion**.
- Consumed or expired **Verification Tokens** are audit/history data until cleanup or **User Deletion**.
- **User Deletion** deletes the User's Accounts, Sessions, and all Verification Tokens whose value is the User Id.
- **User Deletion** is an atomic Auth Storage operation.
- Drizzle Postgres uses cascading foreign keys for User-owned Accounts and Sessions, with explicit cleanup for user-scoped Verification Tokens.
- Initial **User Deletion** is self-service for the **Current User** and requires the current password for Credential Accounts.
- Public **User Deletion** workflow name is `deleteUser`; its inputs scope it to the Current User, not admin deletion.
- Public **User Deletion** HTTP endpoint is `POST /delete-user` and requires the current password in v1.
- Failed **User Deletion** password proof uses `InvalidCredentials`, including missing Credential Account cases.
- **User Deletion** attempts are rate-limited like other sensitive password-proof workflows.
- Multiple unexpired **Verification Tokens** may coexist for the same User and purpose; each issued link is independently one-time-use.
- **Revoke All Sessions** revokes every Session for the current User, including the current Session.
- **Session Policy** defines Session TTL and update age; freshness policy is separate and deferred until needed.
- **Session Core** must be stable before adding OAuth account linking or advanced authenticators.
- **Identity Core** follows **Session Core** and precedes OAuth, plugins, client SDKs, and packaged storage adapters.
- **Identity Core** must exist before social/OAuth account linking can preserve provider display names, images, and provider account records.
- A **User** has one required **Display Name** and one optional nullable **Profile Image**.
- A **User** has one unique **Normalized Email**.
- A **User** may have one or more **Accounts**.
- A **Credential Account** is the first Account type and belongs to exactly one **User**.
- **Account Visibility** lists Accounts for the current User and never exposes passwords or provider tokens.
- **Auth Storage** owns auth invariants; applications configure Storage Adapters rather than implement auth workflows.
- **Auth Storage** owns multi-step auth invariants that must commit atomically.
- The **Drizzle Postgres Storage Adapter** stores **Credential Accounts** in the Accounts table and **Verification Tokens** in the Verifications table.

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
- Public workflow names follow Better Auth verbs where semantics match: list sessions, revoke one session, revoke other sessions, revoke sessions, delete user.
- **Session Management** is an end-to-end capability: core workflows plus HTTP endpoints.
- **Identity Core** is an end-to-end capability: storage contract, workflows, Auth facade, HTTP endpoints, tests, and docs.
- Storage enforces current-user ownership for SessionId-scoped revocation.
- Session lists exclude expired and revoked Sessions.
- Current "next step" resolved as **Identity Core**, not OAuth, plugins, client SDKs, or storage adapters.
- **Identity Core** aligns with Better Auth's core User shape: `name` required, `image` optional/nullable, `emailVerified`, `createdAt`, and `updatedAt` on the User response.
- **Identity Core** may break `AuthStorage` implementations; avoid compatibility shims before 1.0.
- Account records are included in the next slice; email/password credentials should become **Credential Accounts** instead of separate user credential records.
- Password hashes live only on **Credential Accounts** to avoid duplicate credential sources of truth.
- The account behavior in the next slice is **Account Visibility** only; unlink, set-password, OAuth token access, and account-info are deferred.
- End-user `AuthStorage` implementations were resolved as the wrong public extension point; production apps should use packaged **Storage Adapters**.
- Primitive storage calls alone are insufficient for workflows like password reset and password change; **Storage Adapters** must preserve atomic auth invariants.
- **User Deletion** is required for compliance regimes such as GDPR and LGPD; audit retention must not silently override deletion rights.
