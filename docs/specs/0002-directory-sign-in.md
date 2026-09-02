# Directory Sign-In

Status: ready for agent. Vocabulary: `CONTEXT.md`. Decisions: `docs/adr/0013`.

## Problem Statement

A person signs in to this gateway with a password the gateway stores. A company that
already runs Active Directory holds every password of its staff, with its own rules,
its own expiry, and its own disable switch.

That company cannot use this gateway without a second password for every person. The
person keeps two passwords and forgets one of them. The company loses the control it
bought the directory for: a person disabled in the directory keeps a working password
here, because nothing tells the gateway.

The gateway has one credential check and one place that runs it.
`session.Service.VerifyPassword` compares a bcrypt hash at
`internal/session/service.go:172`. Nothing else proves a password at sign-in. The
change is small in surface and large in consequence.

Nothing in the schema serves an external credential today. The only occurrence of the
word "federation" is `application_oidc_configs.federation_config`, which belongs to a
relying party and not to a credential. `applications.app_type = 2` names SAML for an
application the gateway would serve, which is the opposite direction. No table, no
package, and no dependency exists for this work.

## Solution

A Tenant administrator registers an **Identity Provider** in the Console: the servers,
the transport, the bind credential, the search, and the attribute names. The row lives
at the Tenant level, or at one Organization.

A person whose account belongs to that provider types the directory password into the
same sign-in screen as everybody else. The gateway resolves the provider at the
identifier step, and the password step proves the password with an LDAP bind instead
of a bcrypt compare. The front end sees no difference, and the answer never says which
people a Tenant holds.

The first successful bind creates the person here, in the Organization the provider
names, with an **Identity Link** to the directory account. The person holds no local
password from that moment on.

Everything after the password is unchanged. The person owes the same Pending Steps,
proves the same Second Factors, meets the same MFA Requirement, and the ID token
reports `pwd` in `amr`, exactly as a local password does.

## User Stories

### The person who signs in

1. As a person whose company runs a directory, I want to sign in with the password I already have, so that I keep one password and not two.
2. As a person who types an email address, I want the gateway to find my directory itself, so that I pick nothing and learn nothing new.
3. As a person who types a bare username, I want to sign in without a domain, so that I type what I type at my desk every day.
4. As a person whose directory is unreachable, I want a message that says the directory is unavailable, so that I call the right helpdesk.
5. As a person whose directory password is wrong, I want the same message a local password gives, so that no attacker learns which of us exists.
6. As a new member of staff, I want my first sign-in to work with no administrator step, so that I start on my first day.
7. As a person who holds a Second Factor, I want the same challenge as everybody, so that nothing about my sign-in is weaker.

### The Tenant administrator

8. As a Tenant administrator, I want to register a directory in the Console, so that no operator and no database access is needed.
9. As a Tenant administrator, I want to test the connection before I save it, so that I find a wrong bind DN myself and not from an employee.
10. As a Tenant administrator, I want the bind password write-only, so that nobody reads it back out of the Console.
11. As a Tenant administrator, I want to claim the email domains of my company, so that my people are routed with no extra typing.
12. As a Tenant administrator, I want one directory for the whole Tenant, or one for a single Organization, so that a group company serves each part.
13. As a Tenant administrator, I want to switch a directory off without deletion, so that I stop sign-ins while I fix the connection.
14. As a Tenant administrator, I want the Console to refuse a change that locks every administrator out, so that one mistake cannot end my access.

### The person who manages their own account

15. As a person the directory owns, I want the portal to hide the password change, so that I never edit a password that does not exist here.
16. As a person the directory owns, I want to disable my TOTP Enrolment with my directory password, so that the rule is the same one I signed in with.

### The operator and security

17. As an operator, I want every failed bind in the audit trail, so that a sign-in report stays correct.
18. As an operator, I want the bind capped, so that this endpoint cannot be turned on a customer network.
19. As an operator, I want the bind password sealed at rest, so that a database copy discloses no directory credential.
20. As a security reviewer, I want the transport to default to LDAPS, so that a plaintext bind is a stated choice and never an accident.

## Implementation Decisions

### Scope and role

- This spec covers one Identity Provider type: LDAP, which serves Active Directory.
- A bind proves a password. It is the credential check, and nothing more. The gateway
  stays the only OpenID Provider.
- Redirect providers, which is every social and enterprise SSO provider, are out of
  scope. The tables here are built to hold them, and no code here serves them.
- A machine account is never owned by a directory. It holds no `user_humans` row, and
  a bind writes to that row.

### Modules

- A new `identityprovider` domain package holds the provider record and the LDAP
  client. It follows the layout of `authpolicy`: model, repository, DTO, service,
  handler.
- The package imports neither the user domain nor the login session domain. It takes
  what it needs as function values in a `Deps` struct, the way `totp` and `passkey`
  already do. The composition root wires every crossing.
- `session` gains no import of the new package. The router hands `session.Deps` two new
  function values: one that resolves a provider, and one that proves a password against
  it.
- The pending-step closure in the composition root, `internal/api/http/router.go:1112`,
  does not change. A person the directory owns holds a local row, and every step reads
  that row.

### Storage

Three tables, in migration `00045`.

- `identity_providers` — one row per provider. Keyed `(id, tenant_id)`, with `org_id`
  where `''` is the Tenant-wide row and a UUID is that Organization's own. `type` is
  `1` for LDAP. `state` is active or inactive, beside `deleted_at`, which is the
  `applications` shape. Per-type fields are inline and nullable.
- `identity_provider_domains` — `(tenant_id, domain)` unique. A domain belongs to at
  most one provider of a Tenant, and the database enforces it. A JSON list could not.
- `identity_provider_user_links` — the Identity Link. Primary key
  `(tenant_id, idp_id, external_id)`, so one directory account maps to one person. A
  second unique key `(tenant_id, idp_id, user_id)` means one person holds at most one
  account per provider. One person can hold several links, one per provider, which is
  what a redirect provider will need.

Rules that ride with them:

- The provider is an entity. It carries `deleted_at`, and every read filters
  `deleted_at IS NULL`.
- The Identity Link is not an entity. It is hard deleted, and the audit row is the
  record. See `CLAUDE.md`.
- `bind_password` is `VARBINARY`, sealed by `crypto.Cipher`. Copy
  `internal/notification/repo.go:88-96` exactly: the repository holds the cipher, seals
  on write, opens on read, and nils the ciphertext field so that no layer above ever
  holds it. The DTO answers a boolean and takes a `*string`, which is
  `internal/notification/dto.go:29`: absent keeps, empty clears, a value replaces.
- No bootstrap seed. A Tenant with no directory holds no rows, and the repository
  answers "no provider" the way `notification_settings` answers `ErrNoSettings`.
- The resolved row wins **whole, never merged**. `auth_policy_settings` merges knob by
  knob in Go, at `internal/authpolicy/dto.go:146-153`. A connection row must not: half a
  bind DN from the Tenant and half from an Organization is nonsense. Resolution never
  walks the two levels either — no case below reads `org_id` — so there is no level
  precedence to write. See ADR 0013.
- `default_org_id` is required when `org_id` is `''`. `users.org_id` is mandatory
  (`00006`), so a Tenant-wide provider that names no Organization creates nobody, and the
  first bind would fail after the password was proved. The service refuses to save one,
  and the Console marks the field required at that level.

### Provider Resolution

The identifier step resolves one of four cases and records the result on the Login
Session. The front end sees one answer for every case, and the same answer for a person
who does not exist.

1. The identifier carries a domain that `identity_provider_domains` holds, live and
   active. That provider answers.
2. No domain match, and the person holds exactly one Identity Link whose provider
   accepts a typed password. That provider answers.
3. No domain match, and the person holds a password hash. The local bcrypt compare
   answers, as it does today.
4. No domain match and no local person. If the Tenant holds exactly one live active
   provider, that provider answers. If it holds two or more, refuse.

Case 4 is how a person the directory owns signs in for the first time with a bare
username. The count covers both levels, Tenant-wide rows and Organization rows
together, because case 4 knows no Organization yet.

**"No local person" in case 4 means no row at all, whatever its state.**
`FindByIdentifier` filters `state = active` inside the query,
`internal/user/repo.go:141-143`, so a deactivated, locked, or soft-deleted person reads
as absent. Case 4 must ask a second read that filters neither `state` nor `deleted_at`,
and it refuses when that read finds a row. Without it, an administrator who soft-deletes
a person whose directory account still lives undoes the deletion at that person's next
sign-in: `uq_username` maps a NULL `deleted_at` to an epoch (`00006`), so the username
is free and the first bind writes a brand-new active person. A deactivated person, whose
row is not deleted, instead trips `uq_username` and answers a 500 after the password was
proved.

The same read runs again in the write, and it must. Case 1 answers a claimed domain and
returns before the case 4 read, so a claim alone routes an offboarded person straight to
the first bind. The refusal therefore lives in `Provision`, where every case arrives.
See "Never revive a person the Tenant already holds" below.

A Tenant that registers a second provider therefore loses the bare-username route for
everybody. That is stated, not accidental. The alternative sends one customer's
password to another customer's server. See ADR 0013.

Case 2 refuses when a person holds two links that both accept a password. The unique
key above makes that impossible inside one provider, so it can happen only across two
directories.

The resolved provider id goes into the Login Session blob. That costs one struct field
and no migration: the blob is `SealJSON(LoginSession)` and no SQL read names a field
inside it, `internal/session/model.go:147-158`. Sessions already in flight decode the
new field to its zero value, which is case 3, which is what they were.

### The password step, and the bind

- The bind runs at the password step, never at the identifier step. A search at the
  identifier step would say whether the directory holds that person, and the gateway
  does not hold the password yet.
- The credential read runs first and unchanged. `FindByIdentifier` and `FindCredential`
  filter `state = active` and `user_type = human` **inside the query**, and the comment
  at `internal/user/account_repo.go:55-66` says one predicate serves both paths on
  purpose. A bind that ran before that read would silently drop deactivation, soft
  delete, and the machine-account refusal.
- The bind sequence is: dial by `mode`, bind as `bind_dn` with the sealed password, one
  search under `base_dn` built from `user_object_classes` and `user_filters`, then a
  second bind as the entry that was found, with the password the person typed. This is
  the sequence Zitadel runs, and it is the only sequence that proves the password.
- A successful bind records the Factor `pwd`, and the session upgrade is the existing
  one. Nothing downstream learns that the password came from a directory. See ADR 0013.
- **One slug for every bind failure.** A wrong password, an entry that does not exist,
  and a search that returns two entries all answer `invalid_credentials`.
- **A fixed floor on the whole password step**, measured from entry and applied to every
  answer, local and directory alike. `decoyPasswordHash` at
  `internal/session/service.go:237-239` gives the local path a constant cost, and a bind
  does not: an unknown entry answers faster than a wrong password. Without the floor,
  account enumeration returns at `/login/password`. Nothing in the test suite asserts
  the existing property, so this one must be asserted by a new test.
- **A directory that does not answer is not a wrong password.** A dial failure, a
  timeout, a TLS failure, and a bind failure of the service credential answer
  `directory_unavailable`. Neither is a credential failure and neither spends the budget.
  That answer discloses that the identifier is served by a directory, and story 4 pays
  for it on purpose: the state is transient, and the person needs to call the right
  helpdesk.
- **A provider that is inactive or soft deleted answers `invalid_credentials` at
  sign-in**, the same slug an unknown identifier gets. It is not a credential failure
  and it spends no budget, but a slug of its own would name every directory-owned person
  for as long as the provider stays off, which is a permanent enumeration oracle at
  `/login/password`. `directory_disabled` is the answer of the admin and test routes,
  where the caller is already authenticated.
- **Every failure still reaches `refuse`.** `internal/session/service.go:249-260` is the
  only writer of `login.failed` and it has one caller. A bind that returns early writes
  no audit row. Route every outcome through it.

### Abuse limits

The password step carries no budget of any kind today. `session.Deps` holds no limiter,
`internal/session/service.go:54-64`. The lockout that migration `00026` describes is
half built: the columns, the policy knobs, the seed, and the Console editor all exist,
and the only non-test writers are the `WHERE` guard and three resets inside
`Repository.Unlock`. Nothing counts a failure and nothing sets a lock.

That gap is a defect of the local password path, and this spec does not fix it. It does
refuse to inherit it, because a bind is an outbound call into a customer network that
any caller can drive with a fresh partial token.

- **A bind budget**, keyed by Tenant and person, on a Redis key of its own. A first
  bind names no person, and that one is keyed by Tenant and identifier. Copy
  `totp.Service.spendGuess`, `internal/totp/service.go:656-695`, including its refusal
  on a Redis error.
- This is a **fifth** Redis-only exception to the stateless rule, and `CLAUDE.md` is
  amended in the same change. A budget that a table held would let a cache failure pass
  the request through, and an unmetered bind is a lever against a customer directory.
- Ceiling: the key caps one person, so both forms of one identifier spend one counter.
  A spray across many identifiers still reaches the directory. An IP key is the
  upgrade, and it is not built here.
- The connection test carries a budget of its own, keyed by Tenant. It is an outbound
  call that an authenticated Console user drives.

### Transport

- `mode` is `1` plain, `2` StartTLS, `3` LDAPS, and it defaults to `3`. A boolean cannot
  tell StartTLS from LDAPS, and those two differ in port and in handshake.
- Certificate checks are on. `root_ca` holds one optional PEM for a private authority.
- `mode = 1` is supported and it is a stated choice. The Console prints a warning beside
  it and refuses it without an explicit confirmation. A plain bind puts the password of
  every person on the wire in clear.
- Do not copy the egress precedent. `internal/di/di.go:96` builds
  `&http.Client{Timeout: ...}` with no TLS configuration at all, and `DIConfig.Validate`
  never checks the URL scheme. Set `MinVersion: tls.VersionTLS12` explicitly, the way
  `cmd/server.go:128` pins Redis, and validate every server string against `mode`.
- The library is `github.com/go-ldap/ldap/v3`. It is the only maintained LDAP client for
  Go and it is what Zitadel uses. `go.mod` holds no LDAP dependency today.

### The person the first bind creates

- The insert writes `users` and `user_humans` in one transaction, plus the Identity
  Link, and it writes `state = active`. Not state 5. `Invite` writes state 5 with a NULL
  hash and `SetPassword` requires state active, so an invited person can never set a
  first password. That defect is real, it predates this work, and this spec does not
  ride on it.
- `org_id` is the Organization of the provider row. A Tenant-wide provider names the
  Organization in a column of its own, because `users.org_id` is mandatory.
- `password_hash` stays NULL for ever. There is no local password for a person the
  directory owns.
- The person holds no Role. An administrator grants one. A person created by a bind can
  therefore reach nothing in the Console until somebody says so.
- **Create only.** A later bind changes no attribute. A rename in the directory never
  arrives here. That is the stated ceiling, and refresh-on-bind is the upgrade.
- **Never revive a person the Tenant already holds.** Before the insert, the write asks
  whether the Tenant holds an account for the identifier the person typed, or for the
  username or the email address of the directory entry, in any state and soft-deleted
  rows included. If it holds one, the sign-in is refused with the slug a directory that
  did not answer gets. The password was proved and the person exists, so the gateway
  cannot carry on, and a slug of its own would say that the Tenant holds a row for that
  identifier. One refusal covers both shapes: the soft-deleted person `uq_username` would
  let through, and the deactivated person it answers a 500 for.
- **Three forms are read, not one.** The typed identifier is the read case 4 makes, moved
  to where case 1 also arrives. The two entry attributes catch a person held under a form
  they did not type, and a provider that maps no email attribute leaves one of them
  empty. Any single read leaves the others through.
- Six attributes are mapped: the stable external id, the username, the email, the first
  name, the last name, and the display name. Zitadel maps thirteen. Nine of those would
  write columns that no token can carry: `ScopeRepository.Profile` never selects
  `h.phone`, `standardClaim` holds an eight-key whitelist with no phone,
  `users.attributes` has no Go writer, and a mapper of source type 3 or 4 passes
  validation and is then dropped at `internal/oidc/claims_service.go:129-139`.
- `attr_id` is the stable id of the directory, `objectGUID` in Active Directory. The
  Identity Link stores it, so a username changed in the directory never orphans the
  person.

### Guard rails

Three refusals, each of the same shape as the rule that forbids deletion of the last
owner. The first one runs in three places, and the bullet under it says why.

- **Never leave a Tenant with zero local `IAM_OWNER`.** The check runs where a Role is
  removed, where a person is tied to a provider, and **where a domain is claimed**. One
  directory outage must not lock every administrator out of the Console.
- A domain claim ties people the same way a link does, and it is the easier one to miss.
  Case 1 outranks case 3, so claiming `corp.example` routes every person whose email
  carries it to the directory, including the people who hold a local password and no
  directory account. The claim is refused when it would take the last local `IAM_OWNER`
  of the Tenant with it, and the Console names the people the claim moves before it
  saves.
- **Never remove the last Identity Link of a person who holds no password hash.** That
  removal looks like tidy-up and it locks the person out for ever.
- **A provider that is inactive or soft deleted refuses every sign-in of the people tied
  to it.** Both states behave alike. Two states that treat the same person differently
  surprise everybody, and a delete that is blocked by live links traps an administrator
  whose directory is gone for good.

### The portal

- `checkPassword`, `internal/user/account_service.go:221-231`, is the single proof
  behind three destructive routes: TOTP disable at
  `internal/totp/account_service.go:123`, recovery-code regeneration at `:173`, and
  passkey removal at `internal/passkey/account_service.go:147`.
- A person the directory owns re-proves with a **bind**, the same credential they signed
  in with. One rule serves everybody: prove the credential that signs you in.
- **Provider Resolution decides the credential, and the stored hash never does.**
  Case 1 routes a person whose email domain a live active provider claims, and the
  claim writes no row, so that person keeps the hash the claim retired. A compare
  against it would refuse the password that signs them in. `passwordLocal` asks the
  resolver the question the sign-in asks.
- **An empty hash routes to the bind as well.** It is what the person the first bind
  created holds. Without that guard the empty value reaches bcrypt, trips
  `crypto.ErrMalformedHash`, writes an `error` line that says the stored hash cannot
  be read, and answers 401. The sign-in path guards exactly this at
  `internal/session/service.go:237-239`. One predicate in the shared function beats
  four call-site guards.
- The password change and the forgotten-password flow refuse for that person, with a
  slug of their own.
- The password policy knobs govern nothing for a person the directory owns. The
  directory owns the rules. The Console must say so on that screen.

### API contracts

Admin routes, on the shared admin group beside `authpolicy`:

- `GET /api/v1/admin/identity-providers`
- `POST /api/v1/admin/identity-providers`
- `GET /api/v1/admin/identity-providers/:id`
- `PUT /api/v1/admin/identity-providers/:id`
- `DELETE /api/v1/admin/identity-providers/:id`
- `POST /api/v1/admin/identity-providers/:id/test`
- `GET /api/v1/admin/users/:id/identity-links`
- `DELETE /api/v1/admin/users/:id/identity-links/:linkId`

Every answer uses the one envelope. Every error carries a slug. New slugs:
`directory_unavailable`, `directory_disabled`, `provider_ambiguous`,
`domain_already_claimed`, `last_local_owner`, `last_identity_link`,
`password_not_local`, `directory_no_entry`, `directory_misconfigured`.

`directory_no_entry` is the portal re-proof only, and it answers 409. A person whom
no single directory entry proves holds a broken account: no live active Identity
Link, more than one, a search that matched none, or a search that matched two. The
state stays until somebody edits the links or the directory, so the answer never
tells the person to try again. The sign-in keeps `invalid_credentials` for the same
states, because the password step must not say which people a tenant holds.

`directory_misconfigured` is the sign-in only, and it answers 409. Two states reach
it, and both are configuration faults of the first bind: the provider names no
organization to create people in, and the directory entry carries no username. The
bind proved the password, so it is not a credential failure, and only an
administrator or somebody with the directory can mend it, so the answer never tells
the person to try again. The slug discloses no more than `directory_unavailable`
already does. It names a fault of the configuration, and never which people a tenant
holds.

The login routes gain nothing. `/login/identifier` and `/login/password` keep their
request and their answer, which is the point.

### Audit

- Sign-in keeps its two actions, `login.succeeded` and `login.failed`. A bind failure is
  a `login.failed` with a metadata key that names the cause. `recorder.go` holds a
  metadata allow-list at `:258-283`, and the new key is added there.
- Four new admin actions: `idp.created`, `idp.updated`, `idp.deleted`, `idp.tested`. Two
  link actions: `idp.linked` and `idp.unlinked`. `idp.linked` is what records the person
  a bind created, because the link is hard deleted and the trail is the record.
- One new Entity constant. `internal/audit/recorder.go` is a merge-conflict hotspot: the
  Action block, the Entity constant, and the result map are three separate edits in one
  file.
- No credential reaches a log line or an audit row. Not the typed password, not the bind
  password, not the DN of the bind account.

### Console

One screen, in the Tenant section beside policies and notifications, at
`web/console-ui/src/components/console/sidebar.tsx:59-68`, with `tenantOnly: true`.

- `web/console-ui/src/app/(console)/identity-providers/page.tsx`, a Server Component
  that seeds the tenant scope through `serverRead`, copying `policies/page.tsx`.
- `web/console-ui/src/components/views/identity-providers.tsx`, the client view.
- Edits: `lib/console-api.ts` for the interfaces and the path builder, `lib/helpers.ts`
  for `PAGE_PATH` and `PAGE_TITLES`, and one `NAV` entry.
- No new BFF route file. `app/api/admin/[...path]/route.ts` already proxies every method
  under `/api/v1/admin/*`.
- The bind password field is write-only, and the view renders a boolean.

## Testing Decisions

### The seam

The gateway integration harness in the OIDC API package. The directory tests join the
sign-in flow tests already on it. The production code gains no new seam.

One test-only helper is new: an in-process LDAP server that answers a bind and a search.
It lives in the test package. A `Binder` interface with a fake was weighed and refused,
because `CLAUDE.md` forbids an interface with one implementation, and a fake would test
the fake instead of the wire behaviour that carries every real defect.

### What is tested

- The full sign-in of a person the directory owns, end to end, and `pwd` in `amr`.
- Each of the four resolution cases, and the refusal when a Tenant holds two providers.
- The first bind: the row it writes, `state = active`, the NULL password hash, the
  Organization it lands in, and the link.
- A second sign-in of the same person, which creates nothing and changes no attribute.
- A wrong directory password and an entry that does not exist answer the same slug, and
  the password step takes the same time. This is the enumeration test, and it is the one
  the existing suite never had.
- A directory that does not answer: `directory_unavailable`, no budget spent, and a
  `login.failed` row present.
- The two configuration faults of the first bind, a provider that names no
  organization and an entry that carries no username: `directory_misconfigured` and
  never `directory_unavailable`, with a `login.failed` row that names the reason.
- The budget: the cap, the refusal on a Redis error, and the Guessing Budget untouched.
- An inactive provider and a soft-deleted provider both refuse, with the same slug an
  unknown identifier gets.
- A deactivated person and a soft-deleted person never reach case 4, and a claimed domain
  that routes them through case 1 is refused in the write: no second `users` row, no
  Identity Link, and no `idp.linked` row.
- The three guard rails, each with the row it refuses to leave behind, and the domain
  claim that would take the last local `IAM_OWNER` with it.
- The portal: the bind re-proof on TOTP disable, the empty hash, and the person a
  domain claim routes with a stale hash.
- A person the directory owns is offered and challenged for the same Second Factors.
- The repository, on the existing integration-tagged tests: the cipher round trip, the
  two-level resolution, the domain unique key, and the tenant scope.

### The front ends

The web tree holds one test file. This spec proposes no front-end test framework, for
the reason spec 0001 gives. The Console screen is checked by hand against the stories
above. This is a known gap.

## Out of Scope

- Every redirect provider: OIDC, SAML, Google, Microsoft Entra, and every other social
  or enterprise SSO provider. The tables hold them and no code here serves them.
- A sync job that reads the whole directory, and any disable that arrives before the
  next sign-in.
- Refresh of attributes on a later bind.
- Group membership, nested groups, and any Role that a directory decides.
- The missing account lockout. It belongs to the local password path and it needs its
  own ticket.
- An IP-keyed budget.
- An outbound agent for a directory that refuses to open a port.
- Any change to `user_humans.di_user_uuid`. A Scan Verifier is not an Identity Provider.
- Any change to `acr`, to the Assurance Level, or to the finalize gate.

## Further Notes

- The vocabulary of this spec is the project glossary. **Bind** is the LDAP operation
  that proves a password, and it is a fourth word in this repo that carries more than
  one meaning. The others are enrolment, session, and code.
- Two words are taken before this work names anything. `applications.app_type = 2` is
  SAML for an application the gateway would serve, which is the opposite direction.
  `application_oidc_configs.federation_config` belongs to a relying party. Neither is an
  Identity Provider, and neither is touched.
- ADR 0013 records the table shape, the replace rule, the bind at the password step, and
  the refusal when a Tenant holds two providers.
- `CLAUDE.md` gains the fifth Redis-only exception in the same change as the budget.
- Three defects were found while this spec was written, and each one is called out in
  place above: the lockout that only resets, the `checkPassword` guard that is missing,
  and the invitation that can never set a first password. The second is fixed here
  because this work reaches the same function. The other two are not.
