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

**OAuth Client Integration**:
External-provider sign-in and account-linking where Effect Auth acts as an OAuth/OIDC client.
_Avoid_: OAuth provider, social plugin, account provider

**OAuth Service**:
The separate Effect service exported as `OAuth` that owns OAuth Client Integration workflows without expanding the core Auth service.
_Avoid_: Core Auth methods, social plugin, AuthOAuth

**OAuth HTTP**:
The optional HTTP route-mount adapter for OAuth Client Integration, exported from the HTTP subpath rather than root.
_Avoid_: Core Auth HTTP, mandatory OAuth routes

**External Provider**:
A third-party OAuth/OIDC identity provider used to authenticate or link a User.
_Avoid_: App provider, storage provider

**OAuth Providers**:
An Effect service provided by the application that supplies configured External Provider definitions to OAuth Client Integration workflows.
_Avoid_: Auth Live Config providers, provider registry config, OAuthProviderRegistryLive

**Provider Account**:
An Account whose proof material comes from an External Provider rather than an email/password credential.
_Avoid_: OAuth user, social profile

**Provider Profile Mapping**:
The provider-specific conversion from External Provider claims or user-info responses into Effect Auth account and User fields.
_Avoid_: User metadata sync, profile overwrite

**ID Token Validation**:
Cryptographic and claims validation performed before OIDC ID Token claims may identify or update a User or Provider Account.
_Avoid_: JWT decode, token parsing

**OIDC Nonce**:
A transaction-specific random value sent to an OIDC External Provider and validated in the ID Token to bind claims to the OAuth State.
_Avoid_: OAuth State token, callback code

**Provider Token**:
A secret token or token expiry returned by an External Provider and stored on a Provider Account.
_Avoid_: Session Token, Verification Token

**Provider Token Metadata**:
Non-secret token response fields such as token type, granted scope string, and token expiry timestamps stored on a Provider Account.
_Avoid_: Raw provider token response, OAuth state

**OAuth Scope**:
A provider permission string requested during an OAuth Client Integration redirect and recorded on a Provider Account when returned by the External Provider.
_Avoid_: Auth permission, application role

**OAuth Authorization Params**:
Provider-specific query parameters added to the authorization request by server-side External Provider configuration.
_Avoid_: Client request params, callback params

**OAuth Client Secret**:
A redacted External Provider credential supplied from Effect Config for OAuth Client Integration.
_Avoid_: Plain string secret, process.env example

**Token Endpoint Client Authentication**:
The method Effect Auth uses to authenticate an External Provider client when exchanging an authorization code for Provider Tokens.
_Avoid_: User authentication, session authentication

**Provider Token Protection**:
Effect Auth's responsibility to protect stored Provider Tokens before they reach Auth Storage.
_Avoid_: Storage encryption hook, raw token storage

**Account Linking**:
Connecting an additional Account to an existing User after ownership checks pass.
_Avoid_: Account merge, profile merge

**Trusted External Provider**:
An External Provider whose identity claims are allowed to support Account Linking even without a provider-verified email claim.
_Avoid_: Safe provider, allowed provider

**Provider Verified Email**:
An email claim that the External Provider explicitly reports as verified for the provider account.
_Avoid_: Verified user, trusted email

**Different-Email Account Linking**:
Explicitly configured Account Linking where a Provider Account email may differ from the current User's Normalized Email.
_Avoid_: Account merge, email mismatch

**OAuth State**:
An opaque short-lived redirect correlation record for an OAuth Client Integration attempt.
_Avoid_: Verification Token, callback token

**OAuth State Secret**:
A callback-required secret stored with OAuth State, such as a PKCE code verifier or OIDC nonce.
_Avoid_: Provider Token, Session Token

**PKCE**:
Proof Key for Code Exchange used to bind an OAuth authorization code to the client-side redirect transaction.
_Avoid_: Optional OAuth hardening, client-side secret

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

**Rate Limiter**:
An application-provided abuse-control boundary for bounding authentication attempts across sensitive workflows.
_Avoid_: Auth Storage, dev limiter, storage adapter

**Security Default**:
The package posture that authentication runs with production-level protections unless an application explicitly replaces them.
_Avoid_: Dev default, convenience mode

**Auth Live Config**:
The primary application-provided configuration layer for composing Effect Auth defaults and optional features.
_Avoid_: App config, dev layer

**Auth Encryption Key**:
The default redacted symmetric encryption key in Auth Live Config used by Effect Auth-owned encrypted protections unless a narrower feature-specific key overrides it.
_Avoid_: Password hash secret, OAuth client secret

**Auth Encryption Key Id**:
The non-secret key identifier used in encrypted envelopes for Auth Encryption Key material, inherited by encrypted protections unless overridden.
_Avoid_: Database id, provider id

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
- **OAuth Client Integration** uses an **External Provider** to create or link a **Provider Account** and then issue a normal **Session**.
- **OAuth Client Integration** workflows live behind an **OAuth Service**, not as additional methods on the core Auth service.
- The first **OAuth Client Integration** slice includes external-provider sign-in and manual **Account Linking** while preserving room for later access-token APIs, account info, unlinking, additional scopes, and provider helpers.
- An OAuth callback must provide a **Normalized Email** to create a new **User** in the first **OAuth Client Integration** slice.
- OAuth-created Users are email-verified only when the callback has a **Provider Verified Email** or comes from a **Trusted External Provider**.
- OAuth sign-in may issue a **Session** even when the User's local email remains unverified.
- OAuth sign-in may create a new **User** by default, unless implicit sign-up is disabled by configuration for the provider or flow.
- OAuth sign-in uses provider profile fields when creating a new User, but does not overwrite existing User profile fields unless explicitly configured.
- OAuth sign-in with an already-linked Provider Account updates returned Provider Token fields and metadata by default while preserving existing stored token fields omitted by the latest token response.
- If a callback returns an unlinked **Provider Account** whose email matches an existing **User**, **Account Linking** may happen automatically only with a **Provider Verified Email** or a **Trusted External Provider**.
- Automatic same-email OAuth **Account Linking** during sign-in is an atomic **Auth Storage** invariant, not a sequence of primitive find/create calls in the OAuth Service.
- Manual **Account Linking** requires the provider email to match the current User's **Normalized Email** unless **Different-Email Account Linking** is explicitly configured.
- Manual **Account Linking** is idempotent when the same Provider Account is already linked to the current User; Effect Auth updates returned Provider Tokens/metadata and treats the flow as successful.
- Manual **Account Linking** fails when the Provider Account is already linked to a different User.
- An **OAuth State** is created before redirecting to an **External Provider** and consumed once when the provider callback returns.
- **OAuth State** stores the public state handle hashed at rest.
- **OAuth State Secrets** are encrypted at rest because callback handling requires the original PKCE code verifier and OIDC nonce values.
- **OAuth State** records bind the External Provider, flow type, exact redirect URI, requested scopes, sign-up intent, expiry, and consumption metadata for the redirect transaction.
- Better Auth-style public `callbackUrl`, `errorCallbackUrl`, and `newUserCallbackUrl` are not OAuth standard fields and are deferred from the first slice.
- First-slice OAuth post-auth redirects are server-configured through the configured Auth HTTP runtime layer, not supplied by public OAuth start requests or provider callbacks.
- OAuth callbacks set the normal session cookie on sign-in success and then redirect to server-configured success or error destinations without placing Provider Tokens or Session Tokens in URLs.
- New OAuth users use the same first-slice success redirect as existing users; separate new-user redirect behavior is deferred.
- **OAuth State** defaults to a 10-minute TTL, configurable through `oauthState.ttl` in **Auth Live Config**.
- Link-flow **OAuth State** records also bind the current User.
- Public **OAuth Client Integration** HTTP endpoints use `/sign-in/oauth2`, `/oauth2/link`, and `/oauth2/callback/:providerId`.
- OAuth start endpoints return JSON containing the authorization URL; first-slice OAuth HTTP does not issue automatic redirects or expose a Better Auth-style `disableRedirect` flag.
- Public **OAuth Client Integration** HTTP routes are included by opting into `AuthHttp.configure({ oauth: true })` on the package-owned Auth HTTP facade.
- **Configured Auth HTTP** is exported from `effect-auth/http`, not the root package.
- The configured object exposes `api`, `routes`, `middleware`, `middleware.layer`, `requireAuth`, `optionalAuth`, `layer`, cookie metadata, and bearer refresh-header metadata for Effect HTTP servers.
- Public **OAuth Client Integration** callback accepts provider responses through GET query parameters and POST form/body parameters.
- Public **OAuth Client Integration** sign-in and link requests may include client-provided raw **OAuth Scopes** for Better Auth parity.
- Client-provided **OAuth Scopes** augment configured External Provider default scopes for both sign-in and link flows.
- **OAuth Scopes** are validated as RFC 6749 scope tokens, not trimmed, and deduplicated while preserving order before redirect.
- **OAuth Client Integration** uses authorization-code flow with **PKCE** enabled by default using `S256`; legacy External Providers may explicitly disable PKCE in provider configuration.
- Public OAuth HTTP request bodies cannot toggle **PKCE**.
- **OAuth Authorization Params** are configured server-side per External Provider; public OAuth HTTP request bodies cannot supply arbitrary authorization parameters in the first slice.
- **OAuth Authorization Params** cannot override Effect Auth-managed protocol parameters such as `client_id`, `redirect_uri`, `response_type`, `state`, `scope`, `code_challenge`, or `code_challenge_method`.
- **Token Endpoint Client Authentication** defaults to `client_secret_basic`; `client_secret_post` is an explicit per-provider compatibility opt-in.
- First-slice **OAuth Client Integration** does not support public-client `none`, `private_key_jwt`, or mTLS token endpoint authentication.
- **Provider Profile Mapping** is required for generic OAuth providers and optional for OIDC providers that can use Effect Auth's standard-claims mapper.
- For OIDC providers, Effect Auth performs **ID Token Validation** when an ID Token is present and may map standard claims such as `sub`, `email`, `email_verified`, `name`, and `picture`.
- **ID Token Validation** is required before ID Token claims may identify a User or Provider Account; Effect Auth has no decode-only identity mode.
- OIDC providers use an **OIDC Nonce** generated per authorization request; Effect Auth stores it as an encrypted **OAuth State Secret** and validates it against the ID Token on callback.
- OIDC discovery metadata is resolved at **OAuth Providers** layer construction and cached for the process lifetime.
- OIDC JWKS are cached separately for **ID Token Validation** and refreshed once when an unknown key id is encountered before failing closed.
- If ID Token claims cannot be validated, Effect Auth may only continue through a valid user-info fallback; otherwise the OAuth callback fails closed.
- Generic OAuth providers use a configured user-info endpoint and provider-specific **Provider Profile Mapping**.
- A **Provider Account** uses `providerId` for the External Provider and `accountId` for the provider's subject/user id.
- **Provider Tokens** belong to **Provider Accounts** and are never exposed through **Account Visibility**.
- The first **OAuth Client Integration** slice stores standard **Provider Tokens** and **Provider Token Metadata** only; unknown raw token response fields are not persisted.
- Stored standard token fields include optional access token, refresh token, ID token, token type, provider-returned scope string, access-token expiry, and refresh-token expiry.
- **Provider Token Protection** is owned by Effect Auth by default and remains replaceable by the application.
- **Auth Live Config** supports encrypted **Provider Token Protection** only; plaintext/no-op protection requires an application-owned replacement service.
- Default **Provider Token Protection** uses the top-level **Auth Encryption Key** unless a Provider Token-specific key override is configured.
- The top-level **Auth Encryption Key** and any feature-specific override are redacted single 32-byte encoded encryption keys, typically loaded with Effect `Config.redacted(...)`.
- The top-level **Auth Encryption Key Id** defaults to `default` and may be overridden by feature-specific encrypted protections.
- Default **Provider Token Protection** uses AES-256-GCM with a versioned `ea_pt_v1` envelope, random nonce, key id, and contextual authenticated associated data.
- The first default Provider Token Protection key id is an optional configured non-secret slug that defaults to `default`; only one active key is supported initially.
- Provider Token ciphertext is bound through authenticated associated data to the External Provider id, provider account id, and token kind.
- Effect Auth does not generate ephemeral Provider Token Protection keys because restarts must preserve readability of stored Provider Tokens.
- A **Credential Account** is the first Account type and belongs to exactly one **User**.
- **Account Visibility** lists Accounts for the current User and never exposes passwords or provider tokens.
- **Auth Storage** owns auth invariants; applications configure Storage Adapters rather than implement auth workflows.
- **Auth Storage** owns multi-step auth invariants that must commit atomically.
- **Auth Storage** owns OAuth sign-in/linking invariants such as unique Provider Accounts, unique Normalized Emails, automatic same-email linking races, and safe failure when a Provider Account is already linked to another User.
- **Auth Live Config** is the primary configuration surface for common Effect Auth setup.
- **Auth Live Config** is applied through a single secure `AuthLive(config?)` factory, not `production`, `dev`, or `default` layer variants.
- `AuthLive(config?)` provides built-in defaults and internal workflows, while `AuthStorage`, `AuthEmail`, and **Rate Limiter** remain application-provided requirements.
- The top-level **Auth Encryption Key** is optional for core email/password `AuthLive(config?)` and required only when an encrypted feature default is composed without a feature-specific override.
- A **Security Default** may be replaced by an application through **Auth Live Config**, but weaker development conveniences must not be separate package-provided dev shortcuts.
- **Auth Live Config** does not provide a switch to disable rate limiting; applications that want no-op rate limiting must provide their own **Rate Limiter**.
- Effect Auth does not provide a package-owned default **Rate Limiter** backend in the OAuth prerequisite slice; applications provide one suitable for their deployment.
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
- "OAuth integration" resolved as **OAuth Client Integration** for external-provider sign-in/linking, not making Effect Auth an OAuth/OIDC provider.
- First OAuth deliverable resolved as a narrow end-to-end generic OAuth/OIDC sign-in and manual account-linking slice, planned to leave space for broader Better Auth-like account capabilities.
- First OAuth HTTP routes resolved as Better Auth generic-OAuth-like `/sign-in/oauth2`, `/oauth2/link`, and `/oauth2/callback/:providerId`; social aliases are deferred.
- OAuth callback method support resolved as GET and POST from the first slice to allow query and form-post provider responses.
- First-slice OAuth user creation requires provider email; emailless provider accounts are deferred until User identity supports non-email anchors.
- OAuth-created User email verification copies provider trust only when the email is provider-verified or the External Provider is trusted; otherwise the User starts unverified.
- OAuth sign-in session issuance is not blocked by local email verification status because the External Provider is the authenticator for that sign-in.
- Manual OAuth **Account Linking** defaults to same-email linking; different-email linking must be explicitly configured.
- OAuth implicit sign-up defaults to enabled, with configuration to require explicit sign-up intent or disable sign-up for invite-only applications.
- OAuth profile update on sign-in defaults to off; provider profile fields may overwrite existing User profile fields only when explicitly configured.
- OAuth Account identifier semantics resolved as Better Auth-compatible: `providerId` is the External Provider id, `accountId` is the provider subject/user id, and internal Account id remains separate.
- Auth composition defaults resolved as **Security Default**: production-level safety by default, with weaker behavior available only by explicit **Auth Live Config** override.
- **Auth Live Config** resolved as the primary DX and umbrella config; focused config layers may remain as lower-level exports.
- Public `AuthLive` shape resolved as a single secure factory, not `.production`, `.dev`, or `.default` variants.
- `AuthLive(config?)` resolves only Effect Auth defaults and internal workflows; applications still provide `AuthStorage`, `AuthEmail`, and **Rate Limiter**.
- **Auth Live Config** refactor precedes OAuth implementation so OAuth provider, token-protection, and rate-limit decisions compose against the secure default model.
- The first **Auth Live Config** slice includes existing session and verification-token policy and omits rate-limit configuration entirely.
- **Auth Live Config** accepts Effect `Duration.Input` values for session and verification-token TTL policy.
- **Auth Live Config** uses nested policy sections such as `session` and `verification`, plus a top-level **Auth Encryption Key** and **Auth Encryption Key Id** for Effect Auth-owned encrypted protections.
- Feature-specific encrypted protections may override the top-level **Auth Encryption Key** and **Auth Encryption Key Id** when separate keys are needed.
- External Provider definitions are provided through application-owned **OAuth Providers**, not through `AuthLiveConfig.oauth.providers`.
- **OAuth Providers** exposes a static `OAuthProviders.layer(...)` constructor for common static provider definitions.
- `OAuthProviders.layer(...)` accepts either plain provider definitions or Effect `Config` for provider definitions so provider secrets can be loaded through Effect configuration.
- Plain provider definitions are supported primarily for tests, examples, and integrations where another Effect service has already loaded redacted secrets.
- Public **OAuth Providers** endpoint fields use `URL` values, not strings.
- Public provider definitions accept `id: string`, but `OAuthProviders.layer(...)` validates and stores it internally as a branded `OAuthProviderId`.
- `OAuthProviderId` is an Effect Auth local provider alias, not an OAuth RFC protocol value; it uses the URL-path-safe slug pattern `^[a-z0-9_-]{1,64}$`.
- `OAuthProviders.layer(...)` rejects duplicate External Provider ids during layer construction; duplicate ids have no override or merge semantics.
- Core `AuthLive(config?)` does not require **OAuth Providers**; only OAuth-specific workflows or routes require it.
- OAuth workflows are exposed through a separate **OAuth Service** layer rather than added to the core Auth service.
- The exported **OAuth Service** is named `OAuth`, not `AuthOAuth`.
- The **OAuth Service** default layer is exposed as `OAuth.layer`, not `OAuthLive`.
- OAuth HTTP routes are exposed through opt-in `AuthHttp.configure({ oauth: true })` and require the **OAuth Service**.
- `AuthHttp.configure({ basePath, oauth: true })` adds `POST /sign-in/oauth2`, `POST /oauth2/link`, and `GET|POST /oauth2/callback/:providerId` under the configured base path.
- `authHttp.layer(...)` provides cookies, trusted origins, base URL-derived callback URLs, and server-configured OAuth callback redirects; `authHttp.middleware.layer` provides the configured middleware for application route groups.
- `authHttp.layer({ baseUrl })` requires a public base URL; OAuth callback URL derivation must not depend on untrusted request headers.
- `authHttp.layer({ oauth })` accepts relative same-origin `signInSuccessPath`, `linkSuccessPath`, and `errorPath` with safe defaults for OAuth callback redirects.
- The first **OAuth Client Integration** slice derives provider callback URLs from `authHttp.layer({ baseUrl })`, the configured base path, and `providerId`; provider-specific redirect URI overrides are deferred.
- First-slice **OAuth Providers** may define either explicit OAuth/OIDC endpoints or an OIDC discovery URL.
- **OAuth Providers** requires provider `clientSecret` as a redacted value, not a plain string.
- Effect Auth OAuth examples use Effect `Config` such as `Config.redacted(...)` for **OAuth Client Secret** values instead of reading `process.env` directly.
- **OAuth Providers** resolves OIDC discovery during layer construction and caches resolved endpoints for the process lifetime.
- The nested `session` section uses `ttl` and `updateAge` field names rather than repeating the session prefix.
- The nested `verification` section keeps purpose-named TTL fields such as `emailVerificationTtl` and `passwordResetTtl`.
- **Auth Live Config** duration values must be positive and finite; invalid durations fail layer construction with `BoundaryParseError`.
- `AuthLive(config?)` exposes `BoundaryParseError` in its layer error type for invalid **Auth Live Config** values.
- Rate limiting policy, backend, and disablement are outside **Auth Live Config**; no-op behavior requires an application-owned **Rate Limiter** implementation.
- Automatic OAuth **Account Linking** by matching email resolved as allowed only when the email is provider-verified or the External Provider is explicitly trusted.
- OAuth redirect state resolved as storage-backed **OAuth State**, not a self-contained signed URL value and not an overloaded Verification Token.
- OAuth State at-rest handling resolved as hashed public state handles plus encrypted callback-required OAuth State Secrets such as PKCE code verifiers and OIDC nonces.
- OAuth provider definition wiring resolved as Effect-idiomatic service composition: applications provide an **OAuth Providers** layer separately from `AuthLiveConfig`.
- OAuth provider layer naming resolved as `OAuthProviders.layer(...)`, not `OAuthProviderRegistryLive`.
- **OAuth Providers** requirement resolved as OAuth-specific, not a dependency of core email/password `AuthLive(config?)`.
- OAuth public service shape resolved as a separate **OAuth Service**, not extra methods on the core Auth service.
- OAuth service export name resolved as `OAuth`, not `AuthOAuth`.
- OAuth layer naming resolved as `OAuth.layer`, not `OAuthLive`.
- OAuth HTTP route inclusion resolved as opt-in `AuthHttp.configure({ oauth: true })` from `effect-auth/http`, on the same configured Auth HTTP facade as core auth routes.
- OAuth HTTP endpoint set resolved as `POST /sign-in/oauth2`, `POST /oauth2/link`, and `GET|POST /oauth2/callback/:providerId` under the configured base path.
- OAuth HTTP runtime dependency resolved as `authHttp.layer(...)` for session cookies, trusted origins, middleware, and callback URL derivation.
- OAuth HTTP public base URL resolved as required for `authHttp.layer({ baseUrl })`.
- Provider-specific OAuth redirect URI overrides are deferred; first-slice callback URLs are derived only from configured HTTP base URL, mount base path, and provider id.
- OIDC discovery URL support is included in the first provider definition slice as an alternative to explicit endpoints.
- OIDC discovery resolution happens at **OAuth Providers** layer construction, not lazily per request.
- Provider `clientSecret` resolved as `Redacted<string>` and documented through Effect `Config.redacted(...)`, not direct `process.env` access.
- `OAuthProviders.layer(...)` resolves Effect `Config` provider definitions directly rather than requiring users to hand-write `Layer.unwrap(...)` wiring.
- `OAuthProviders.layer(...)` also accepts plain provider definitions for tests and integrations with non-Config secret stores.
- OAuth provider endpoint fields resolved as `URL` objects in public configuration, not strings.
- OAuth provider id handling resolved as string at config boundary and branded `OAuthProviderId` after validation.
- OAuth provider id syntax resolved as Effect Auth-owned, not RFC-defined: `^[a-z0-9_-]{1,64}$`.
- Duplicate OAuth provider ids resolved as hard startup validation failures, not last-wins overrides.
- Client-provided raw OAuth scopes resolved as included in the first slice for Better Auth parity despite the stricter app-allowlist alternative.
- OAuth scope combination resolved as augmentation: request scopes are unioned with provider default scopes for both sign-in and link flows rather than replacing defaults.
- OAuth scope validation resolved as strict RFC 6749 scope-token validation, no trimming, and order-preserving deduplication.
- OAuth flow type resolved as authorization-code only in the first slice.
- PKCE resolved as enabled by default with `S256`, with provider-level explicit opt-out for legacy providers and no public request toggle.
- OAuth authorization extra params resolved as server-side static provider configuration only in the first slice; client-provided arbitrary authorization params are deferred.
- OAuth authorization extra params cannot override Effect Auth-managed protocol parameters.
- Token endpoint client authentication resolved as `client_secret_basic` by default with explicit provider-level `client_secret_post` fallback; `none`, `private_key_jwt`, and mTLS are deferred.
- Provider profile extraction resolved as OIDC standard-claims mapping when possible, with required `mapProfile` for generic OAuth providers.
- OIDC ID Token handling resolved as validated-only identity: no decode-only mode, with user-info fallback allowed only when configured and successful.
- OIDC nonce resolved as always generated for OIDC providers, sent in authorization request, stored encrypted at rest with OAuth State, and validated during ID Token validation.
- OIDC metadata/JWKS behavior resolved stricter than Better Auth generic OAuth: discovery is cached at provider-layer construction, while JWKS are cached for validation and refreshed once on unknown `kid`.
- Provider token storage resolved as first-slice account fields for standard token fields only, excluding unknown raw token response JSON.
- Auth encryption key configuration resolved as one top-level `encryptionKey` in **Auth Live Config**, with optional feature-specific overrides for narrower encrypted protections.
- Auth encryption key id configuration resolved as one top-level `encryptionKeyId` defaulting to `default`, with optional feature-specific overrides inherited by encrypted envelopes.
- Top-level `encryptionKey` resolved as optional for core email/password AuthLive and required only by encrypted feature defaults such as OAuth Provider Token or OAuth State protection when no feature-specific override exists.
- OAuth State TTL resolved as 10 minutes by default, configurable via positive finite `oauthState.ttl` duration.
- Better Auth-style OAuth post-auth callback URL fields resolved as deferred because they are not OAuth standard fields and increase open-redirect risk; first-slice redirects are server-configured.
- OAuth start HTTP response resolved as JSON authorization URL only, with no automatic redirect or `disableRedirect` behavior in the first slice.
- OAuth callback HTTP behavior resolved as setting normal session cookie on sign-in success and redirecting to server-configured success/error destinations without URL token material.
- OAuth HTTP redirect configuration resolved as nested `authHttp.layer({ oauth })` relative paths: `signInSuccessPath`, `linkSuccessPath`, and `errorPath`, with defaults `/`, `/settings/accounts`, and `/auth/error`.
- Manual OAuth account linking idempotency resolved as success when the Provider Account is already linked to the current User, including token/metadata refresh; linking to a different User remains an error.
- OAuth sign-in token update resolved as default behavior for already-linked Provider Accounts: update returned token fields/metadata, preserve existing fields omitted by provider response.
- OAuth sign-in/linking storage invariants resolved as dedicated atomic AuthStorage behavior rather than service-level primitive find/create/update sequences.
- Encryption keys are required redacted single encoded 32-byte keys for default encrypted implementations, not passphrase-derived keys and not ephemeral generated keys.
- Provider Token Protection encryption resolved as AES-256-GCM with versioned `ea_pt_v1.<kid>.<nonce>.<ciphertext>.<tag>` envelope and contextual AAD, stricter than Better Auth's opt-in token encryption posture.
- Provider Token Protection key id resolved as optional configured `encryptionKeyId` defaulting to `default`, with single-active-key support in the first slice and future rotation shape left open.
- Provider token storage resolved as first-slice account fields so future access-token, refresh, account-info, and additional-scope workflows do not require another storage shape break.
- **Provider Token Protection** resolved as Effect Auth-owned with an application-replaceable boundary, rather than raw token persistence or adapter-specific encryption hooks.
- Plaintext/no-op **Provider Token Protection** resolved as outside **Auth Live Config**; applications that want it must provide their own replacement service.
- Rate limiter backend resolved as deferred: no Auth Storage rate-limit table, separate rate-limit storage boundary, package-owned memory backend, or `rateLimit` field in **Auth Live Config** in the OAuth prerequisite slice.
