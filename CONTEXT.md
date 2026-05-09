# Effect Auth

Effect Auth is a server-side authentication library for Effect applications. Its first supported authentication method is email/password.

## Language

**Effect Auth SDK**:
A server-side Effect library that owns authentication workflows, session issuance, and storage boundaries.
_Avoid_: Full-stack SDK, client-only SDK

**Authentication Method**:
A supported way for a user to prove identity to the server.
_Avoid_: Integration, provider

**Auth User**:
The stable authenticated subject that sessions identify.
_Avoid_: Account, profile

**Email Password Credential**:
The email/password proof record that maps one normalized email address to one Auth User.
_Avoid_: Account, password user

**Normalized Email**:
An email address after trimming, lowercasing, and syntax validation, without provider-specific alias rules.
_Avoid_: Raw email, canonical Gmail address

**Boundary Parse**:
The conversion of external input into validated Effect Auth domain types before workflows run.
_Avoid_: Inline validation, storage validation

**Email Verification**:
The process of proving control of the email address on an Email Password Credential.
_Avoid_: Email confirmation, activation

**Verification Token**:
A short-lived one-time secret used to complete Email Verification.
_Avoid_: Code, magic link token

**Password Reset**:
The email-mediated flow that lets an Auth User replace a forgotten password.
_Avoid_: Forgot password, recovery

**Password Change**:
The authenticated flow that lets an Auth User replace a known password after proving the current password.
_Avoid_: Password update, reset while signed in

**Email Change**:
The flow that moves an Auth User from one login email address to another.
_Avoid_: Update email, change account email

**Auth Storage**:
An Effect service that persists Auth Users, credentials, sessions, and token records without owning their security semantics.
_Avoid_: Database adapter, repository

**Dev Memory Storage**:
An in-memory Auth Storage implementation intended only for development and tests.
_Avoid_: Memory adapter, default storage

**Auth Workflow**:
A transport-neutral operation that performs an authentication use case.
_Avoid_: Route handler, endpoint

**Auth HTTP Adapter**:
The official HTTP integration that maps requests and responses to Auth Workflows while owning web security defaults.
_Avoid_: Framework wrapper, route examples

**Trusted Origin**:
An origin allowed to make state-changing browser requests to the Auth HTTP Adapter.
_Avoid_: CORS origin, callback URL

**Rate Limiter**:
An Effect service that enforces attempt limits for security-sensitive authentication flows.
_Avoid_: Throttle helper, middleware

**Rate Limit Bucket**:
A named authentication attempt limit defined by Effect Auth and enforced by the Rate Limiter.
_Avoid_: Route throttle, limiter key

**Public Auth Error**:
An authentication failure exposed to an HTTP caller.
_Avoid_: Internal error, domain error

**Secret Auth Value**:
A password, token, or hash that must not appear in logs, traces, errors, or JSON output.
_Avoid_: Sensitive string, secret

**Session Token**:
A high-entropy bearer secret that authenticates one active session.
_Avoid_: JWT session, access token

**Session**:
A revocable server-side login state for one Auth User.
_Avoid_: JWT, cookie payload

**Rolling Session**:
A Session whose expiry can be extended after a configured refresh interval.
_Avoid_: Sliding JWT, cookie refresh

**Session Cookie**:
A host-only HTTP cookie that carries a Session Token to the Auth HTTP Adapter.
_Avoid_: Auth cookie, JWT cookie

**Password Hasher**:
An Effect service that derives and verifies password hashes for email/password authentication.
_Avoid_: Hash callback, crypto helper

**Password Policy**:
An Effect service selected by the application that decides whether a candidate password is acceptable.
_Avoid_: Password rules, validator

**Secure Default Password Policy**:
The bundled Password Policy preset with length bounds and email-derived password rejection.
_Avoid_: Default rules, strong password checker

**Password Text**:
A user-supplied password after NFKC normalization and before policy checks or hashing.
_Avoid_: Raw password, plain password

**Password Hash**:
A self-describing stored credential containing the hashing algorithm, parameters, salt, and derived key.
_Avoid_: Password, encrypted password

**Native Scrypt Runtime**:
A JavaScript runtime that provides built-in Scrypt support without third-party packages.
_Avoid_: Universal runtime, WebCrypto-only runtime

## Relationships

- The **Effect Auth SDK** supports one or more **Authentication Methods**
- Email/password is the first **Authentication Method**
- The email/password **Authentication Method** uses a **Password Hasher**
- The email/password **Authentication Method** uses a selected **Password Policy** before hashing candidate passwords
- The **Secure Default Password Policy** requires length 12-128 and rejects Password Text equal to the full Normalized Email or its local-part
- Candidate passwords become **Password Text** through NFKC normalization only
- External email, password, token, callback URL, and ID inputs pass through a **Boundary Parse** before entering Auth Workflows
- **Password Policy** and **Password Hasher** operate on **Password Text**
- An **Auth User** owns one or more credentials
- An **Email Password Credential** belongs to exactly one **Auth User** and exactly one **Normalized Email**
- A session identifies an **Auth User**, not an **Email Password Credential**
- An **Email Password Credential** must complete **Email Verification** before a session is issued
- **Email Verification** is completed with a **Verification Token**
- Effect Auth owns **Verification Token** semantics: opaque token generation, hash-at-rest, expiry, and one-time consumption
- **Auth Storage** persists **Verification Token** records but does not define their security semantics
- **Verification Tokens** are 32 random bytes encoded as base64url, with SHA-256 hashes stored in **Auth Storage**
- **Password Reset** uses the same one-time token semantics as **Email Verification**
- Successful **Password Reset** revokes all existing sessions for the **Auth User** and does not issue a new session
- **Password Change** requires current-password proof before storing a new Password Hash
- Successful **Password Change** rotates the current Session Token and revokes other sessions for the **Auth User**
- **Email Change** is outside v1 scope
- **Auth Storage** exposes atomic authentication operations rather than generic CRUD
- A **Session** belongs to exactly one **Auth User**
- V1 sessions are **Rolling Sessions** by default
- Refreshing a **Rolling Session** rotates its Session Token atomically
- A **Session Token** authenticates one **Session**
- **Session Tokens** are 32 random bytes encoded as base64url
- Effect Auth stores only a hash of each **Session Token** in **Auth Storage**
- The **Auth HTTP Adapter** sends the **Session Token** in a host-only **Session Cookie** by default
- A **Session Cookie** uses HttpOnly, Secure in secure contexts, SameSite=Lax, Path=/, and no Domain
- Production **Auth Storage** is supplied by the application as an Effect layer
- **Dev Memory Storage** is not production storage
- An **Auth Workflow** owns use-case semantics without depending on HTTP
- V1 **Auth Workflows** are sign-up, email verification, resend verification, sign-in, current-session lookup, sign-out, password reset, and password change
- The **Auth HTTP Adapter** invokes **Auth Workflows** and owns cookie, response, and generic-error semantics
- The **Auth HTTP Adapter** rejects state-changing browser requests from untrusted origins
- A **Trusted Origin** is configured explicitly or derived from the base URL
- Production email/password authentication requires a **Rate Limiter**
- Effect Auth owns **Rate Limiter** key semantics for authentication flows
- Effect Auth defines **Rate Limit Buckets** for sign-in, password reset, and verification-email flows
- The **Rate Limiter** enforces **Rate Limit Buckets** but does not define them
- V1 **Rate Limit Buckets** default to 100 attempts per 10 seconds in production only, following Better Auth's default
- **Public Auth Errors** avoid revealing whether an Auth User or Email Password Credential exists
- `EmailNotVerified` is a **Public Auth Error** only after password proof succeeds
- Password Text, Password Hashes, Session Tokens, and Verification Tokens are **Secret Auth Values**
- **Secret Auth Values** are represented with redacted types inside Effect Auth
- The default **Password Hasher** requires a **Native Scrypt Runtime**
- The **Password Hasher** produces and verifies a **Password Hash**

## Example dialogue

> **Dev:** "Does the first SDK include browser helpers?"
> **Domain expert:** "No — the **Effect Auth SDK** starts as a server-side library; browser helpers come after the server contract is secure and typed."

> **Dev:** "Can email/password run anywhere WebCrypto exists?"
> **Domain expert:** "No — the default **Password Hasher** requires a **Native Scrypt Runtime**; other runtimes must provide their own hasher or disable email/password."

> **Dev:** "Do we store the password hash on the user?"
> **Domain expert:** "No — the **Auth User** is the session subject, while the **Email Password Credential** stores the **Password Hash**."

> **Dev:** "Is password length hard-coded by the SDK?"
> **Domain expert:** "No — the application selects a **Password Policy** layer, usually from bundled presets."

> **Dev:** "Do we trim or lowercase passwords before hashing?"
> **Domain expert:** "No — **Password Text** is NFKC-normalized only."

> **Dev:** "Can workflows receive raw request bodies?"
> **Domain expert:** "No — external input must pass a **Boundary Parse** into domain types first."

> **Dev:** "Can sign-up immediately create a session?"
> **Domain expert:** "No — the **Email Password Credential** must complete **Email Verification** before the **Auth User** gets a session."

> **Dev:** "Do we apply Gmail dot or plus-addressing rules?"
> **Domain expert:** "No — **Normalized Email** is trim plus lowercase plus syntax validation only."

> **Dev:** "Does the storage adapter decide whether verification tokens are reusable or hashed?"
> **Domain expert:** "No — Effect Auth owns **Verification Token** semantics; **Auth Storage** only persists and atomically consumes token records."

> **Dev:** "Can password reset have separate token rules?"
> **Domain expert:** "No — **Password Reset** uses the same one-time, hash-at-rest token semantics, revokes all sessions after success, and does not auto-sign-in."

> **Dev:** "Can a signed-in user change password without entering the current one?"
> **Domain expert:** "No — **Password Change** requires current-password proof and revokes other sessions."

> **Dev:** "Can v1 change the login email?"
> **Domain expert:** "No — **Email Change** is a separate high-risk flow outside v1 scope."

> **Dev:** "Is the session a JWT?"
> **Domain expert:** "No — a **Session Token** is an opaque bearer secret, and **Auth Storage** persists the revocable **Session**."

> **Dev:** "Does a session expire exactly seven days after sign-in?"
> **Domain expert:** "Not always — a **Rolling Session** can be refreshed after the configured refresh interval."

> **Dev:** "Does rolling refresh keep using the same token?"
> **Domain expert:** "No — refreshing a **Rolling Session** rotates the **Session Token** and updates the **Session Cookie**."

> **Dev:** "Can the default session cookie span subdomains?"
> **Domain expert:** "No — the default **Session Cookie** is host-only; cross-subdomain cookies are an explicit later opt-in."

> **Dev:** "Can I use the bundled memory storage in production?"
> **Domain expert:** "No — **Dev Memory Storage** exists for development and tests; production supplies **Auth Storage** as an Effect layer."

> **Dev:** "Does Auth Storage expose generic table CRUD?"
> **Domain expert:** "No — **Auth Storage** exposes atomic authentication operations so Effect Auth can preserve invariants across storage implementations."

> **Dev:** "Should apps write their own sign-in cookie handling?"
> **Domain expert:** "No — the **Auth HTTP Adapter** owns web security defaults and delegates business semantics to **Auth Workflows**."

> **Dev:** "Does v1 include OAuth or passkeys?"
> **Domain expert:** "No — v1 **Auth Workflows** cover only the minimal email/password lifecycle."

> **Dev:** "Is SameSite=Lax enough for auth endpoints?"
> **Domain expert:** "No — state-changing requests must also come from a **Trusted Origin**."

> **Dev:** "Can production run email/password without rate limiting?"
> **Domain expert:** "No — production email/password requires a **Rate Limiter**, with only explicit unsafe opt-out."

> **Dev:** "Can sign-in say whether the email exists?"
> **Domain expert:** "No — **Public Auth Errors** stay generic unless the password has already been proven."

> **Dev:** "Can we log a verification token while debugging email delivery?"
> **Domain expert:** "No — a **Verification Token** is a **Secret Auth Value** and must remain redacted."

## Flagged ambiguities

- "SDK" was used broadly — resolved: **Effect Auth SDK** initially means a server-side Effect library.
- "built-in" was used broadly — resolved: the default email/password hasher uses runtime-native Scrypt plus Effect, not third-party hashing packages.
- "account" was avoided for v1 auth records — resolved: use **Auth User** for the subject and **Email Password Credential** for proof material.
