# Admin CRUD — build plan

This plan builds the admin management API that `console-ui` already calls. It
starts after [docs/admin-front-door-plan.md](admin-front-door-plan.md), which
delivered `GET /api/v1/admin/me`.

Read these first:

- [CONTEXT.md](../CONTEXT.md) — the domain glossary.
- [docs/adr/0006-admin-management-api.md](adr/0006-admin-management-api.md) — the
  envelope, the error slug, and the membership gate.
- [CLAUDE.md](../CLAUDE.md) and the `ao-go-api`, `ao-db-migration`, and
  `ao-nextjs-ui` skills.

## What is true today

The console is finished. `web/console-ui/src/lib/console-api.ts` declares clients
for about 60 admin paths. 22 view and route files import it. The BFF at
`web/console-ui/src/app/api/admin/[...path]/route.ts` forwards GET, POST, PUT,
PATCH, and DELETE, and unwraps the envelope for the browser.

The backend serves one route. `internal/user/handler.go` registers `GET /me`. The
repositories in `internal/tenant`, `internal/organization`, and `internal/user`
hold only reads. No package writes an entity.

This plan closes that gap. Almost all of the work is Go.

## Decisions

| Topic | Decision |
|---|---|
| Where the work lands | The Go API. `web/console-ui` changes only where a contract forces it. |
| The contract | `console-api.ts` is the specification for paths, bodies, and error slugs. The glossary outranks it on names. |
| Tenant lifecycle | Create and delete stay in `cmd/bootstrap.go`. The API serves the domain list and the tenant read. Full tenant CRUD is a later task. |
| Roles | Four names as Go constants: `IAM_OWNER`, `IAM_ADMIN`, `ORG_OWNER`, `ORG_USER_MANAGER`. No roles table. |
| Naming | "Instance" is not a term. The code renames to "tenant" in slice 0. |
| Pagination | Offset, with a page number. The console shows a pager. This reverses `paginate-admin-list-api` and changes the console. See below. |
| Role gate | In the service, in the function that performs the write. Not in a handler and not in middleware. |
| Transactions | Every admin write runs in one transaction through `tx.RunInTx`. |
| Audit | Every admin write records one audit event on the caller's transaction. |
| Dead columns | A setting that no Go code reads is not exposed as writable, with one labelled exception (project settings). |

## Pagination

The console shows page numbers, so the admin lists page by offset.

`middlewares.Paginate` and `response.List` already implement it, and `ao-go-api`
already documents it. No new Go package is needed, and the skill needs no
amendment.

This reverses the earlier `paginate-admin-list-api` change, which windowed the
lists by keyset. Two costs come with the reversal, and both are accepted:

- A row written while an operator reads page 3 shifts every later row by one
  place. One row can then appear twice, or not at all. Nothing reports it. The
  lists sort newest first, so a write lands on page 1 and disturbs the pages below
  by one row. A refresh corrects the view.
- A deep page reads and discards every row before it. A tenant large enough to
  feel this will search instead of paging.

The keyset indexes in migrations 00033 and 00035 stay correct. `ORDER BY
created_at DESC, id DESC` with `LIMIT` and `OFFSET` reads the same index. No
migration changes.

## Rules that hold in every slice

- The handler lives in the domain package. Only `router.go`, `middlewares/`, and
  `response/` stay central.
- A handler is three lines: bind, call, respond.
- Every store method takes a tenant id.
- Every request body is a DTO with `validate:` tags. The backend is the
  enforcement point.
- Each domain declares its own sentinel errors. One mapper in
  `internal/api/http/response` turns a sentinel into a status.
- An entity is soft deleted with `deleted_at`. A consumed row is hard deleted. See
  `CLAUDE.md`.
- Never log a credential. Log the tenant id, the user id, and the request id.
- Each slice leaves the build green and the tests passing.

## Slice 0 — Foundation

Nothing else starts until this lands. Three parts, one slice.

### 0a — Rename "instance" to "tenant"

33 occurrences across 10 files.

**Go.** `internal/user/dto.go`, `internal/user/service.go`, and its test.
`IsInstanceManager` becomes `IsTenantManager`, and the JSON field becomes
`isTenantManager`.

**Console.** `src/lib/console-api.ts`, `src/components/console/sidebar.tsx`, and
the `audit`, `notifications`, `organizations`, `policies`, and `users` views.
`isInstanceManager` becomes `isTenantManager`. `canManageInstance` becomes
`canManageTenant`. `instanceOnly` becomes `tenantOnly`. `/api/admin/instance`
becomes `/api/admin/tenant`, and `/api/admin/instance/domains` becomes
`/api/admin/tenant/domains`.

This is a rename. It does not convert the grandfathered client to Server Actions.

### 0b — Move the console from cursors to page numbers

No Go package is built. Every list route mounts
`middlewares.Paginate("created_at", …)` with its own sort allowlist, and answers
`response.List(c, rows, total)`. The envelope carries
`meta: {page, limit, total, totalPages}`.

The console changes in six files. Three hold the work:

- `src/lib/console-api.ts` — `PageOpts.cursor` becomes `page`. `Page<T>` carries
  `page` and `totalPages` in place of `nextCursor`. `readPicker`, `PICKER_PAGE`,
  and `PICKER_MAX_PAGES` go: a picker reads one page sized by `total`.
  `getTotal` reads `meta.total`.
- `src/components/console/store.tsx` — `usePagedList` holds a page number, and
  replaces its rows instead of appending them. The rule that a cursor is only
  valid in the ordering it was minted in is deleted with the cursor.
- `src/components/console/primitives.tsx` — `LoadMore` becomes a pager: first,
  previous, the numbered pages, next, last.

Three follow: `src/components/views/audit.tsx` runs its own cursor walk for the
feed and for the export, and `src/lib/csv.ts` walks it for the file.

The typed filters are unchanged: `q`, `state`, `type`, `orgId`, and `userId`. A
sort key outside a list's allowlist is refused, and the message names the
permitted set.

Tests cover: a sort key outside the allowlist, a limit above the maximum, and a
page past the end answering an empty list with a correct `total`.

### 0c — The admin group takes its dependencies

`mountAdmin` in `internal/api/http/router.go` takes the `audit.Recorder` built at
line 61 and the `tx.RunInTx` runner built at line 78, exactly as `mountLogin`
does.

## Slice 1 — Organizations

**Endpoints.** `GET /organizations` (paged), `GET /organizations/:id`,
`POST /organizations`, `PATCH /organizations/:id`, `DELETE /organizations/:id`.

**Files.** `internal/organization/`: `handler.go`, `dto.go`, `service.go`,
`model.go`, and writes added to `repo.go`.

**Gate.** A tenant manager writes any organization. An `ORG_OWNER` writes its own.

**Notes.** The delete is a soft delete. A tenant's default organization cannot be
deleted, because self-registration points at it.

## Slice 2 — Projects

**Endpoints.** `GET /projects` (paged), `GET /projects/:id`, `POST /projects`,
`PATCH /projects/:id`, `DELETE /projects/:id`.

**Files.** A new `internal/project/` package.

**Gate.** A tenant manager, or an `ORG_OWNER` in the project's organization.

**Notes.** A project carries `roleAssertion`, `roleCheck`, `hasProjectCheck`, and
`privateLabeling`. The columns exist in `00003_projects.sql`, and no Go code reads
them. The API stores them, and the console labels them **not enforced yet**. This
label is required. `roleCheck` and `hasProjectCheck` block sign-in in Zitadel and
block nothing here, so an administrator who reads no label expects a lock that
does not exist.

## Slice 3 — Applications

**Endpoints.** `GET /applications` (paged), `GET /applications/:id`,
`POST /applications`, `PATCH /applications/:id`, `DELETE /applications/:id`,
`POST /applications/:id/rotate-secret`.

**Files.** A new `internal/application/` package. It writes `applications` and
`application_oidc_configs` in one transaction.

**Gate.** A tenant manager, or an `ORG_OWNER` in the application's organization.

**Notes.** The OIDC body carries the nine fields of `AppOidcBody` and no more.
`00005_application_oidc_configs.sql` holds six JSON blobs — `crypto_config`,
`authn_config`, `token_binding_config`, `ciba_config`, `federation_config`, and
`custom_attributes` — that no Go code reads. They stay out of the API. A form
field for a setting the engine ignores is a false statement to the operator.

Before a field is exposed, confirm that `internal/oidc/client_service.go` or
`client_repo.go` reads it.

The rotation answers the new secret exactly once. The column stores a bcrypt hash.
The secret never reaches a log line.

## Slice 4 — Users

**Endpoints.** `GET /users` (paged), `GET /users/:id`, `POST /users`,
`PATCH /users/:id`, `DELETE /users/:id`, `POST /users/:id/activate`,
`POST /users/:id/deactivate`, `POST /users/:id/unlock`,
`POST /users/:id/password-reset`, `DELETE /users/:id/mfa`,
`GET /users/:id/memberships`.

**Files.** `internal/user/`: writes added to `repo.go` and `service.go`, the DTOs
added to `dto.go`, the routes added to `handler.go`.

**Gate.** A tenant manager, or an `ORG_USER_MANAGER` in the user's organization.

**Notes.** A create writes the user and its membership in one transaction —
`CreateUserBody` carries `orgId` because a user without a membership belongs
nowhere. The password is hashed before it is stored, and it never reaches a log
line. `unlock` clears `user_lockout`. `DELETE /users/:id/mfa` clears `user_totp`
and `user_webauthn_credentials`.

`GET /users/:id/memberships` answers whole, not paged. One person's memberships
are bounded.

## Slice 5 — Members and invitations

**Endpoints.** `GET /members/tenant` (paged), `GET /members/org` (paged),
`POST /members`, `PATCH /members/:userId`, `DELETE /members/:userId?orgId=`,
`POST /invitations`.

**Files.** `internal/tenant/` for `tenant_members`. `internal/organization/` for
`organization_members`. The invitation lives in `internal/user`.

**Gate.** `IAM_OWNER` for a tenant membership. `ORG_OWNER` or
`ORG_USER_MANAGER` for an organization membership.

**Notes.** One rule needs its own function: only a tenant manager, or a sitting
`ORG_OWNER` in the same organization, may confer `ORG_OWNER`. Without it, an
`ORG_USER_MANAGER` mints an owner and outranks itself.

The function lives in the members service, beside the write it guards. It must not
be named `Scope`. `CONTEXT.md` gives `Scope` a different meaning, and one word with
two meanings is what the glossary exists to prevent.

`GET /members/tenant` is tenant-scoped. An organization manager reads an empty page,
not a refusal.

An invitation is a membership grant, so it carries `orgId` and passes the same gate.

## Slice 6 — Sessions and grants

**Endpoints.** `GET /sessions` (paged), `GET /grants` (paged),
`DELETE /sessions/:id`, `DELETE /users/:id/sessions`.

**Files.** `internal/session/` and `internal/oidc/`.

**Gate.** A tenant manager.

**Notes.** A session and a grant are consumed rows. A revoke hard deletes the
session from the database and from Redis, per
[docs/adr/0002-session-storage.md](adr/0002-session-storage.md).

An administrative force-logout takes the grants too, `offline_access` included, so
no refresh token survives. An access token already issued lives out its lifetime at
the relying party. The console states this.

## Slice 7 — Tenant, provider config, and keys

**Endpoints.** `GET /tenant`, `POST /tenant/domains`,
`DELETE /tenant/domains/:domain`, `GET /provider`, `PATCH /provider`, `GET /keys`,
`GET /bootstrap`.

**Files.** `internal/tenant/` and `internal/oidc/`.

**Gate.** `IAM_OWNER` for every write.

**Notes.** A domain remove is a soft delete. The row flips to inactive, so the
globally unique host is not freed for another tenant.

`PATCH /provider` writes six fields: the four lifetimes, `requirePkce`, and
`refreshRotation`.

`access_token_type` is **not writable**. `ProviderConfigBody` carries the field so
that the gateway refuses a format it does not serve, and the service answers
`ErrOpaqueAccessToken` for every value except `JWT`. The engine reads the column at
`internal/api/oidc/provider.go:80` and refuses to build a provider for an opaque
tenant, so a tenant switched to `Opaque` would answer no OIDC request at all, and
every sign-in would stop. Making it writable requires the engine to serve the opaque
format. Build the format before the field.

The provider screen also renders `access_token_type`, `issuer`, `state`, and
`resource_indicators` as **read only**. Each describes live behaviour the operator needs to see.
`signing_alg_config` is not rendered at all, because no Go code reads it.

`resource_indicators` is not writable. It is read at
`internal/api/oidc/provider.go:157` and it decides which audiences a client may
request. The admin bearer guard admits only `urn:alphaomega:admin-api`. An
administrator who removed that value could not mint another admin token, and the
console could not reach the endpoint that would restore it. Recovery would be a SQL
statement. Making it writable requires a server-side guard that refuses to remove
the admin resource identifier. Build the guard before the field.

`GET /keys` is a read. Key rotation is not in this plan.

## Slice 8 — Scopes and claim mappers

**Endpoints.** `GET /scopes`, `POST /scopes`, `PATCH /scopes/:id`,
`DELETE /scopes/:id`, `GET /scopes/:id/mappers`, `POST /scopes/:id/mappers`,
`PATCH /mappers/:id`, `DELETE /mappers/:id`.

**Files.** `internal/oidc/`, beside `scope_repo.go` and `scope_service.go`.

**Gate.** `IAM_OWNER`.

**Notes.** These lists are bounded and are not paged. Three error slugs are already
specified and must be answered by name: `protected_claim` for a reserved claim,
`scope_in_use` for a scope a client still holds, and `limit_exceeded` for too many
mappers or an oversized value.

A builtin scope, seeded by migration 00020, cannot be deleted.

## Slice 9 — Auth policy

**Endpoints.** `GET /settings/auth`, `PUT /settings/auth`,
`GET /orgs/:orgId/settings/auth`, `PUT /orgs/:orgId/settings/auth`,
`DELETE /orgs/:orgId/settings/auth`.

**Files.** A new `internal/authpolicy/` package, over `00028` and `00031`.

**Gate.** A tenant manager for the tenant default. An `ORG_OWNER` for its own
organization.

**Notes.** The read answers the resolved policy and, per field, whether the value is
set at this level or inherited. A `PUT` field that is absent or null inherits. A
stored `0` or `false` is an explicit setting — `lockoutThreshold` `0` disables
lockout and does not mean "inherit".

`DELETE` exists at organization level only. It removes the override.

## Slice 10 — Notifications

**Endpoints.** `GET /notifications/settings`, `PATCH /notifications/settings`,
`POST /notifications/test`, `GET /notifications/templates`,
`GET /notifications/templates/:key`, `PUT /notifications/templates/:key`,
`DELETE /notifications/templates/:key`,
`GET /notifications/templates/:key/preview`, and the
`/orgs/:orgId/notifications/templates` variants.

**Files.** A new `internal/notification/` package, over `00023`, `00024`, and
`00029`.

**Gate.** A tenant manager for the settings. An `ORG_OWNER` for its own templates.

**Notes.** The SMTP password is write only. The read reports `passwordSet` and
never the value. An omitted password keeps the stored one, and an empty string
clears it. The password never reaches a log line.

A template resolves in three steps: organization override, then tenant override,
then the embedded default. The read reports which one applied.

`POST /notifications/test` answers the slug `send_failed` when the transport
refuses.

## Slice 11 — Audit

**Endpoints.** `GET /audit`.

**Files.** `internal/audit/`, beside the existing recorder.

**Gate.** A tenant manager.

**Notes.** The feed filters on actor, action, entity type, entity id, and a time
range. It pages the same way every other list does, so `AuditQuery.cursor` becomes
`page` and the CSV export walks page numbers. Migration 00025 already indexes
`(tenant_id, created_at)`.

This slice is last on purpose. Slice 0c makes every write from slice 1 onward
record an event, so by the time the feed is readable it has something to show.

## Out of scope

- Tenant create and delete through the API. They stay in `cmd/bootstrap.go`.
- Cross-tenant authority. No operator identity exists outside a tenant, and no
  token signed by one tenant can authorize a write to another. A system resource
  identifier and a separate key set are a later task with their own ADR.
- The External Identity Provider: the redirect kind, which hands the gateway the
  answer instead of a password. No table, no migration, and no login flow branch
  exists for it. User Federation is a separate concept and it is built. See
  `docs/adr/0014`.
- Project roles, project grants, and branding. Without them the four project
  settings enforce nothing, which is why they carry a label.
- The six unread OIDC JSON blobs on an application, and `signing_alg_config` on the
  provider.
- Key rotation.
- The self-service account API.
