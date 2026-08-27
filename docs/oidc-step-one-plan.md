# OIDC step one — build plan

This plan wires `github.com/luikyv/go-oidc` v0.25.0 into the Go Fiber backend and
delivers the basic OpenID Connect profile.

Read these first. They hold the decisions this plan assumes:

- [CONTEXT.md](../CONTEXT.md) — the domain glossary.
- [docs/adr/0003](adr/0003-go-oidc-provider-per-tenant.md) — go-oidc as the protocol
  engine, one provider per tenant.
- [docs/adr/0004](adr/0004-login-handoff-redirect-resume.md) — login by redirect and
  resume, with a blind authentication policy.
- [CLAUDE.md](../CLAUDE.md) and the `ao-go-api`, `ao-db-migration`, and `ao-nextjs-ui`
  skills.

## Scope

**In scope.** Discovery, JWKS, authorize, token, userinfo, introspection, revocation,
RP-initiated logout. Authorization code grant, with PKCE per the tenant's
`require_pkce` column. A client that uses PKCE must use S256, because `plain` is never
offered. A public client always uses PKCE, whatever the column says, because the
protocol engine requires it of a client that holds no secret. Refresh token grant with
rotation and reuse detection. JWT access tokens. Public subjects. Consent. Claim
mappers into the ID token and userinfo. Eight audit events.

**Out of scope.** Dynamic client registration, DPoP, mTLS, JAR, PAR, CIBA, device
flow, pairwise subjects, opaque access tokens, key rotation, multi-factor
authentication, passkeys, password reset, email verification, and invitations.

`web/login-ui` ships pages for passkey, forgot, reset, verify-email, enroll, and
accept-invite. Those pages fail until later work adds their endpoints. This is
expected.

## Rules that hold in every slice

- One provider per tenant. The request hostname resolves the tenant through
  `tenant_domains`. The registry caches a built provider for 5 minutes.
- Only `internal/api/oidc` imports `goidc`. `internal/oidc` holds the domain.
- Every store method takes a tenant id.
- Grants, authn sessions, and login sessions persist as an encrypted blob plus the
  extracted lookup columns. AES-256-GCM, through the existing cipher.
- Every knob comes from `oidc_provider_configs`. No OIDC lifetime lives in the
  environment or in `config.yaml`.
- Never log a code, a token, a secret, or a password. Log the tenant id, the client
  id, the error code, and the request id.
- An audit write runs in the same transaction as the change it records. A failed audit
  write fails the request.
- Each slice leaves the build green and the tests passing.

## Slices

Slices 2, 3, 4, 5, and 7 have no dependency on each other. Run them in any order, or
in separate conversations at the same time.

### S1 — JWK key encoding

**Goal.** Signing keys are stored as JWK, not DER.

**Files.** `internal/platform/crypto/keygen.go` and its test,
`internal/platform/db/migrations/mysql/00010_oidc_keys.sql` (edit in place),
`cmd/bootstrap.go` and its test.

**Work.** `crypto.Generate` returns JWK JSON for the public and the private half. The
private half stays sealed by the cipher. Edit migration 00010: the two `BLOB` columns
now hold JWK JSON, `algorithm` duplicates the JWK `alg`, and `key_config` is removed.

**Done when.** `go test ./internal/platform/crypto/... ./cmd/...` passes, `bootstrap`
runs against a fresh database, and the seeded rows hold readable JWK JSON.

### S2 — Key repository and the JWKS function

**Depends on.** S1.

**Goal.** A tenant's key set is readable as a `goidc.JSONWebKeySet`.

**Files.** `internal/oidc/key_repo.go`, `internal/oidc/key_service.go`, `go.mod`.

**Work.** Add the `go-oidc` dependency. Read the keys of one tenant. Publish `active`
(state 1) and `inactive` (state 2). Exclude `retired` (state 3) and soft-deleted rows.
Unseal the private half for signing. Select the active signing key.

**Done when.** A unit test seeds a tenant with two keys and asserts that the key set
holds both public keys and one usable signer.

### S3 — Provider config and tenant resolution

**Goal.** A hostname resolves to a tenant and its protocol settings.

**Files.** `internal/oidc/provider_repo.go`, `internal/tenant/repo.go`,
`internal/api/http/middlewares/tenant.go`.

**Work.** Read `oidc_provider_configs` for one tenant. Read `tenant_domains` to map a
domain to a tenant id. Resolve the request host, with a trusted header override for
local development. Reject a mismatch between the resolved host and the stored issuer.

**Done when.** A unit test maps a seeded domain to its tenant and reads the config
row, and an unknown host returns a not-found error.

### S4 — Client store

**Goal.** A client loads from the database into a `goidc.Client`.

**Files.** `internal/oidc/client_repo.go`, `internal/api/oidc/storage.go`,
`internal/platform/db/migrations/mysql/00005_application_oidc_configs.sql` (rename
`scope_ids` to `scopes`), `cmd/bootstrap.go`.

**Work.** Join `applications` to `application_oidc_configs` and map the row into
`goidc.Client`. Implement the DCR manager: `Client` reads the database, `SaveClient`
and `DeleteClient` return an error, and an initial-token validator refuses every
registration. Verify the client secret with bcrypt through
`crypto.VerifyPassword`. Refuse a client row that asks for `pairwise`.

**Done when.** A unit test loads a seeded first-party client, a secret check passes
and fails correctly, and a registration attempt is refused.

### S5 — Grant and authn session stores

**Goal.** `go-oidc` can persist and reload its own state.

**Files.** `internal/oidc/storage_repo.go`, `internal/api/oidc/storage.go`.

**Work.** Implement `GrantManager` (`SaveGrant`, `Grant`), `AuthManager`
(`SaveSession`, `Session`, `GrantByAuthCode`), and `RefreshTokenManager`
(`GrantByRefreshToken`). Seal the serialized value into `data`. Extract `client_id`,
`subject`, `expires_at`, and the SHA-256 digests of the code and the refresh token
into their columns. Every miss returns `goidc.ErrNotFound`.

**Done when.** A unit test round-trips a grant and a session, finds a grant by code
and by refresh token, and gets `ErrNotFound` for an unknown id.

### S6 — Provider build, registry, and mount (first runnable)

**Depends on.** S2, S3, S4, S5.

**Goal.** Discovery and JWKS answer over HTTP for the bootstrap tenant.

**Files.** `internal/api/oidc/provider.go`, `internal/api/oidc/registry.go`,
`internal/api/http/oidc_route.go`, `internal/api/oidc/errorlog.go`,
`internal/api/http/router.go`.

**Work.** Build the provider from the tenant config: issuer, `WithPathPrefix`,
`WithAuthCodeGrant`, `WithRefreshTokenGrant`, `WithPKCE(S256)` with
`WithPKCERequired` per the `require_pkce` column, `WithSecretBasicAuthn`,
`WithSecretPostAuthn`, `WithNoneAuthn`, the lifetimes, and `WithDCR`. Advertise only
the algorithms an active key can sign with. Fail the build when `access_token_type`
is 2. The build logs no error, because the handler logs it once and answers 503.
Cache the built provider per tenant for 5 minutes. Mount through
`adaptor.HTTPHandler` at `/oidc/v1`, with discovery at the root. `WithDCR` makes the
engine serve the client management endpoints, so the mount refuses `GET`, `PUT`, and
`DELETE` on `/register`. Install `WithErrorHandler`, which logs the error code and
never the engine's description. The policy is a stub that fails with `login_required`.

**Done when.** `GET /.well-known/openid-configuration` and `GET /oidc/v1/jwks` return
correct documents for the bootstrap tenant, and an unknown host returns 404.

### S7 — Audit recorder

**Goal.** An action can be recorded inside a transaction.

**Files.** `internal/audit/recorder.go`, `internal/audit/repo.go`.

**Work.** Write one `audit_events` row on the caller's transaction. Define the eight
actions: `login.succeeded`, `login.failed`, `consent.granted`, `consent.denied`,
`token.issued`, `token.refresh_reused`, `token.revoked`, `logout.succeeded`. The
`metadata` bag holds the client id, the scopes, and the grant id, and never a
credential. A failed write returns an error to the caller.

**Done when.** A unit test records an event on a transaction, and a rolled-back
transaction leaves no row.

### S8 — Login session store, `/identifier`, `/session`

**Depends on.** S7.

**Goal.** A person can be looked up, and a partial login session exists.

**Files.** `internal/session/login_session.go`, `internal/session/repo.go`,
`internal/api/http/handler/login.go`, `internal/api/http/dto/login.go`,
`web/login-ui/src/app/(login)/identifier/actions.ts`.

**Work.** Store the login session as an encrypted blob with a rotating `token_hash`.
`POST /api/v1/login/identifier` looks up the user and opens a partial session.
`GET /api/v1/login/session` returns `{active, email}` for a fully authenticated
session only. Rename the `login-ui` call from `/check` to `/identifier`, one line.

**Done when.** The identifier page reaches the password page against the real backend.

### S9 — `/password`, `/complete`, and the real policy (flow works)

**Depends on.** S6, S8.

**Goal.** The authorization code flow completes end to end.

**Files.** `internal/api/oidc/policy.go`, `internal/api/http/handler/login.go`,
`internal/session/login_session.go`.

**Work.** `POST /api/v1/login/password` verifies the password with bcrypt, upgrades
the login session, and rotates its token. It does not touch the authn session.
`POST /api/v1/login/complete` loads the authn session, sets `Subject` and
`GrantedScopes`, saves it, and returns `{redirectTo}` pointing at
`{issuer}/oidc/v1/authorize/{id}`. The policy redirects on the first pass, reads the
`Store` error marker, and succeeds when a subject is present. On `prompt=none`,
`login-ui` renders nothing and either completes or writes a `login_required` marker.
Record `login.succeeded`, `login.failed`, and `token.issued`.

**Done when.** A browser signs into `console-ui` through the real flow and receives an
ID token and an access token.

### S10 — Consent

**Depends on.** S9.

**Goal.** A third-party client asks for consent, and the answer is remembered.

**Files.** `internal/oidc/consent_repo.go`, `internal/oidc/consent_service.go`,
`internal/api/http/handler/login.go`.

**Work.** Skip consent when `is_first_party = 1`. Skip when the stored scope set
already covers the request, and ask only for the new scopes otherwise. `prompt=consent`
forces the screen. `prompt=none` without consent writes a `consent_required` marker.
`POST /api/v1/login/consent` records the answer. Consent, not the request, is the
source of `GrantedScopes`. Record `consent.granted` and `consent.denied`.

**Done when.** A third-party client sees the consent screen once, and not on the second
sign-in.

### S11 — Scopes and claim mappers

**Depends on.** S9.

**Goal.** Tokens and userinfo carry the tenant's claims.

**Files.** `internal/oidc/scope_repo.go`, `internal/oidc/claims_service.go`,
`internal/api/oidc/claims.go`.

**Work.** Advertise the tenant's enabled scopes, with `openid` always present. Read
`oidc_claim_mappers` for source type 1 (standard attribute) and type 2 (user bag, from
`user_attributes`). Honour `in_id_token` and `in_userinfo`. Ignore `in_access_token`,
and ignore source types 3 and 4.

**Done when.** A `profile` and `email` request returns the mapped claims from
`/oidc/v1/userinfo` and in the ID token.

### S12 — Refresh rotation and reuse detection

**Depends on.** S9.

**Goal.** A replayed refresh token kills the grant.

**Files.** `internal/oidc/storage_repo.go`, `internal/api/oidc/provider.go`.

**Work.** Enable `WithRefreshTokenRotation()`. On each refresh, write the old token
digest into `oidc_superseded_refresh_tokens`. `GrantByRefreshToken` checks that table
first. On a hit, revoke the whole grant and fail. Prune rows after `expires_at`.
Record `token.refresh_reused`.

**Done when.** A test refreshes twice with the same token and finds the grant revoked.

### S13 — Introspection and revocation

**Depends on.** S12.

**Goal.** A client can inspect and revoke a token.

**Files.** `internal/api/oidc/provider.go`, `internal/api/oidc/tokenadmin.go`.

**Work.** `WithTokenIntrospection` for confidential clients only.
`WithTokenRevocation` for any authenticated client, with
`WithTokenRevocationRevokeGrantOnAccessToken`. Record `token.revoked`.

**Done when.** A confidential client introspects its own token, a public client is
refused, and a revocation ends the grant.

### S14 — RP-initiated logout

**Depends on.** S9.

**Goal.** Signing out ends the login session everywhere.

**Files.** `internal/api/oidc/logout.go`, `internal/api/http/handler/login.go`,
`internal/session/login_session.go`.

**Work.** `WithLogout` and a logout policy. Require `id_token_hint`. Validate
`post_logout_redirect_uri` against the client list, and fall back to `AO_LOGIN_URL`.
Terminate the `login_sessions` row named by the `sid` claim.
`POST /api/v1/login/logout` does the same from the account side. Record
`logout.succeeded`.

**Done when.** Signing out of one application signs the person out of the other.

### S15 — End-to-end integration test

**Depends on.** S10 to S14.

**Goal.** One test proves the wiring.

**Files.** `internal/api/oidc/flow_integration_test.go`.

**Work.** Against a real MySQL and Redis: read discovery, call `/authorize`, sign in,
consent, exchange the code, call `/userinfo`, refresh, replay the old refresh token,
introspect, revoke, and log out.

**Done when.** The test passes from a clean database after `bootstrap`.
