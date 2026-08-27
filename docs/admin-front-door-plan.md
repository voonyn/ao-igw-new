# Admin front door — build plan

This plan wires the one admin endpoint that `console-ui` cannot reach a dashboard
without, and it makes sign-out real.

Read these first. They hold the decisions this plan assumes:

- [CONTEXT.md](../CONTEXT.md) — the domain glossary.
- [docs/oidc-step-one-plan.md](oidc-step-one-plan.md) — the OIDC build plan. This plan
  starts after it.
- [CLAUDE.md](../CLAUDE.md) and the `ao-go-api`, `ao-db-migration`, and `ao-nextjs-ui`
  skills.

## The problem

A person signs in at `console-ui` and lands on
`/no-access?error=me_unavailable`.

The sign-in itself works. The token exchange passes and the ID token validates. The
callback then calls `GET /api/v1/admin/me`, and no such route exists. The Go server
answers 404, and the callback treats any failed answer as
`me_unavailable`. See
[web/console-ui/src/app/auth/callback/route.ts](../web/console-ui/src/app/auth/callback/route.ts)
lines 84 to 89.

The admin API was never in the OIDC plan. `console-ui` calls about 60 admin paths,
and the backend serves none of them.

## Scope

**In scope.** One endpoint, `GET /api/v1/admin/me`. A bearer middleware that protects
it. Audience-scoped access tokens. RP-initiated logout from the console. The console
changes that these three need.

**Out of scope.** The other 59 admin paths. The self-service account API. Machine
callers and the `client_credentials` grant. A roles table, RBAC, and ReBAC. A scope
check on the admin API.

The console degrades on a 404. A list read reports `missing`, and a count reads zero.
See `getOptional` and `getTotal` in
[web/console-ui/src/lib/console-api.ts](../web/console-ui/src/lib/console-api.ts). So
the dashboard renders with empty tiles until the remaining paths arrive. This is
expected.

## Decisions

| Topic | Decision |
|---|---|
| Console access | An admin role is required. `IAM_OWNER` or `IAM_ADMIN` on the tenant, or `ORG_OWNER` or `ORG_USER_MANAGER` in any organization. A person without one belongs in `portal-ui`. |
| Package layout | No `internal/admin` package. A domain is an entity. `/me` lives in `internal/user`. Each membership read lives with the entity that owns it. |
| Path | `/api/v1/admin/me` stays. `/me` is the common convention for a self endpoint. |
| Token check | Verify the JWT locally against the tenant key set. Check the signature, `iss`, `exp`, and `aud`. |
| Audience | The tenant declares its allowed resource identifiers. Resource indicators are enabled, and they are not required. |
| Roles | Four names as Go constants. No roles table. |
| Response | The envelope stays. An error gains a machine-readable slug. The console BFF unwraps `data` for the browser. |
| Logout | RP-initiated. The console redirects to the gateway logout endpoint. |
| Accessible orgs | `/me` lists every organization in the tenant. The console filters what it renders. |

## Rules that hold in every slice

- The handler lives in the domain package. Only `router.go`, `middlewares/`, and
  `response/` stay central.
- A handler is three lines: bind, call, respond.
- Every store method takes a tenant id.
- Never log a token, a code, a secret, or a password. Log the tenant id, the user id,
  and the request id.
- Every answer goes through a helper in `internal/api/http/response`.
- Each slice leaves the build green and the tests passing.

## Slices

Slices A1 and A2 must run before A5. Slice A3 and slice A4 have no dependency on each
other, and both must run before A5.

### A1 — Resource identifiers on the provider config

**Goal.** A tenant declares which resource identifiers its clients can ask for.

**Files.** `internal/platform/db/migrations/mysql/00031_provider_resource_indicators.sql`
(new), `internal/oidc/provider_repo.go`, `cmd/bootstrap.go` and its test.

**Work.** Add one nullable JSON column to `oidc_provider_configs` that holds a list of
resource identifiers. Read the column into the provider config struct. Seed the list
with `urn:alphaomega:admin-api` and `urn:alphaomega:account-api`.

The account identifier is seeded now and used later. `web/portal-ui` already sends it
at `/authorize`. Its resource server is not in this plan.

**Done when.** `goose up` applies to the existing database, and a fresh `bootstrap`
writes both identifiers.

### A2 — Audience-scoped access tokens

**Depends on.** A1.

**Goal.** An access token names the API it is for.

**Files.** `internal/api/oidc/provider.go`.

**Work.** Call `provider.WithResourceIndicators` with the tenant's list when the list
is not empty. Do not call `WithResourceIndicatorsRequired`. A client that sends no
`resource` then receives a token with no `aud`, and the resource server refuses it.

`web/console-ui` already sends `resource=urn:alphaomega:admin-api` at `/authorize`.
See [web/console-ui/src/app/auth/login/route.ts](../web/console-ui/src/app/auth/login/route.ts)
line 40. No console change is needed for this slice.

**Done when.** A sign-in through `console-ui` yields an access token whose `aud`
carries the admin identifier.

### A3 — The bearer middleware

**Depends on.** A2.

**Goal.** A protected route knows who is calling.

**Files.** `internal/api/http/middlewares/bearer.go` and its test.

**Work.** Read the `Authorization` header. Resolve the tenant with the existing tenant
middleware, and read its public key set with `oidc.KeyService.PublicKeySet`. Verify the
signature. Check that `iss` matches the tenant issuer, that `exp` is in the future, and
that `aud` carries the required resource identifier. Put the subject on the request for
the handler to read.

Refuse with 401 and the slug `unauthenticated`.

An access token stays valid until `exp`, even after a logout. It is a JWT that no store
holds. This is already true, and
[internal/api/oidc/logout.go](../internal/api/oidc/logout.go) lines 118 to 121 record
it.

**Done when.** A unit test admits a valid token and refuses four bad ones: an expired
token, a wrong audience, a bad signature, and a missing header.

### A4 — Membership reads

**Goal.** The tenant and the organizations of one person are readable.

**Files.** `internal/tenant/repo.go`, `internal/organization/repo.go` (new package),
`internal/user/repo.go`, and their tests.

**Work.**

In `internal/tenant`: read one tenant row, read its live domains, and read the
`tenant_members` row of one user. Declare `IAM_OWNER` and `IAM_ADMIN` as constants
here, because the tenant owns tenant membership.

In `internal/organization`: read every live organization of one tenant, and read the
`organization_members` rows of one user. Declare `ORG_OWNER` and `ORG_USER_MANAGER` as
constants here.

In `internal/user`: read one user with the human profile, by id. The existing reads
take an identifier, not an id.

Every read filters on `deleted_at IS NULL`.

**Done when.** A unit test seeds the bootstrap shape and reads each part back.

### A5 — `GET /api/v1/admin/me`

**Depends on.** A3 and A4.

**Goal.** The console reaches its dashboard.

**Files.** `internal/user/handler.go`, `internal/user/dto.go`, `internal/user/service.go`,
`internal/api/http/response/error_response.go`, `internal/api/http/router.go`, and the
service test.

**Work.** Compose the answer from the reads of A4. The service takes the tenant reads
and the organization reads as injected functions, the way `session.Deps` already does
in `router.go`.

Refuse with 403 and the slug `not_a_console_user` when the caller holds none of the
four roles.

Answer this shape inside the envelope `data`:

```json
{
  "userId": "…",
  "username": "…",
  "displayName": "…",
  "email": "…",
  "tenant": {
    "id": "…", "name": "…", "state": 1, "defaultOrgId": "…",
    "created": "…",
    "domains": [{ "domain": "…", "isPrimary": true, "isVerified": true, "state": 1 }]
  },
  "isInstanceManager": false,
  "tenantRoles": [],
  "orgMemberships": [
    { "tenantId": "…", "orgId": "…", "userId": "…", "userName": "", "roles": ["ORG_OWNER"], "created": "…" }
  ],
  "accessibleOrgs": [{ "id": "…", "name": "…" }]
}
```

`isInstanceManager` is true when `tenantRoles` holds `IAM_OWNER` or `IAM_ADMIN`. The
console derives the same value for itself, so the server computes it once and both
agree.

`accessibleOrgs` holds every live organization of the tenant.

Add an `error` field to the error envelope, so an answer reads
`{code, status, message, error, errors?}`. The console already reads that field. See
`errorCode` in
[web/console-ui/src/lib/console-api.ts](../web/console-ui/src/lib/console-api.ts).

Mount the group in `router.go` at `/api/v1/admin`, behind the tenant middleware and the
bearer middleware, and register the one route.

**Done when.** A unit test covers three callers: an instance manager, an
organization-only admin, and a person with no role who receives 403.

### A6 — Console changes

**Depends on.** A5.

**Goal.** The console reads the envelope, and sign-out is real.

**Files.** `web/console-ui/src/app/api/admin/[...path]/route.ts`,
`web/console-ui/src/lib/server/secure-cookie.ts`,
`web/console-ui/src/app/auth/callback/route.ts`,
`web/console-ui/src/app/auth/logout/route.ts`,
`web/console-ui/src/app/no-access/page.tsx`, `web/console-ui/src/lib/types.ts`,
`web/console-ui/.env.example`.

**Work.**

Unwrap the envelope in the BFF. On a successful answer, forward the `data` value to the
browser. On a failed answer, forward the body unchanged, because the slug already sits
at the top level.

Keep the ID token in the sealed session, and stop dropping it in the callback.

Rewrite `/auth/logout`. Read `end_session_endpoint` from discovery. Redirect to it with
`id_token_hint` and with `post_logout_redirect_uri` set to the console URL with a
trailing slash. `bootstrap` registers exactly that value, and the protocol engine
refuses any other. Clear the console cookie on the way out.

Rewrite the `no-access` copy for the `not_a_console_user` case. State that console
access needs an administrator role. Add a link to `portal-ui`, from a new
`AO_PORTAL_URL` environment variable, and document it.

Remove the `kind` field from the `Tenant` type. No column backs it, and no concept
behind it exists.

**Done when.** A sign-in reaches `/overview`, and a sign-out reaches the login page and
then asks for a password.

### A7 — Dead code

**Goal.** The tree holds no unreachable Go file.

**Files.** `internal/api/http/handler/health.go`.

**Work.** Delete the file and the empty folder. Nothing imports the package.
`router.go` serves health through Fiber's own middleware.

**Done when.** `go build ./...` passes.

### A8 — Documentation

**Depends on.** A5 and A6.

**Goal.** The glossary and the decision record match the code.

**Files.** `CONTEXT.md`, `docs/adr/0005-audience-scoped-resource-servers.md` (new),
`docs/adr/0006-admin-management-api.md` (new).

**Work.**

Add three terms to `CONTEXT.md`: **Membership**, **Role**, and **Resource**. The
glossary today tells the reader to avoid the word "role" as a synonym for **Scope**.
These decisions give the word its own meaning, so the glossary must say what that
meaning is.

Write ADR 0005. It records why every API requires an audience, why both front ends send
a `resource` value, and why the indicator is enabled but not required.

Write ADR 0006. It records why the admin API keeps the response envelope, why an error
carries a slug, and why access is gated on membership roles instead of scopes.

**Done when.** Both files exist, and `CONTEXT.md` holds the three terms.

## Verification

- `go test ./...` passes.
- `goose up` applies to the existing database.
- `go build ./...` passes after slice A7.
- A person with an admin role signs in at the console and reaches `/overview`. The
  tiles read zero, because the list endpoints are not built.
- The same person signs out, reaches the login page, and must type a password to
  return.
- A person without an admin role reaches `/no-access` and reads a message that names
  the missing role and links to the portal.

## Known gaps after this plan

These are listed so that a later plan can pick them up.

- The remaining 59 admin paths answer 404.
- The self-service account API answers 404, and `portal-ui` cannot load.
- The console expects cursor paging, `{items, nextCursor, total}`. The backend
  helpers give offset paging in `meta`. The first list endpoint must settle this.
- A machine caller has no way to obtain a token.
- An access token survives a logout until it expires.
