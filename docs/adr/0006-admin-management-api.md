# 0006 - The admin management API

## Context

`console-ui` is the administrative front end of a tenant. It signs a person in
through the gateway and then calls `/api/v1/admin/*`.

The console needs one answer before it can render anything: who is calling, what
tenant they administer, and which organizations they can switch between. That answer
is `GET /api/v1/admin/me`. Every other admin path degrades to an empty tile, and
this one does not.

Two questions had to be settled before the endpoint could be written. What decides
that a person may use the console, and what does a refusal look like on the wire.

## Decision

**The envelope stays.** The admin API answers
`{code, status, message, data, meta?}`, the same envelope every other API of the
gateway answers with. The console BFF unwraps `data` and hands the payload to the
browser, so the browser client reads a plain object and no view knows the envelope
exists.

**An error carries a slug.** The error envelope gains one field, and an answer reads
`{code, status, message, error, errors?}`. The `error` value is a machine-readable
name: `unauthenticated` from the bearer guard, `not_a_console_user` from `/me`. The
message is for a person, and the slug is what a client branches on, so a reworded
message never changes behaviour. A failed answer is forwarded through the BFF
unchanged, because the slug already sits at the top level.

**Access is gated on membership roles.** A caller reaches the console when they hold
`IAM_OWNER` or `IAM_ADMIN` on the tenant, or `ORG_OWNER` or `ORG_USER_MANAGER` in
any organization. A caller with none of the four is refused with 403 and the slug
`not_a_console_user`. The four names are Go constants, declared with the entity that
owns the membership. No roles table exists.

**No `internal/admin` package.** A domain package is an entity. `/me` lives in
`internal/user`, and each membership read lives with the entity that owns it:
`tenant_members` in `internal/tenant`, `organization_members` in
`internal/organization`.

## Alternatives

- **Gate on a scope.** The token already carries scopes, and the check costs no
  database read. A scope says what a client may ask for, and the console is a
  first-party client that asks for whatever it needs. The question here is what the
  person administers, and only a membership answers it.
- **A roles table with rows a tenant edits.** It is where this ends if a tenant ever
  defines its own roles. Four names that the code branches on need no table, and a
  table invites a fifth name that nothing reads.
- **Return the payload without the envelope.** The console would then read the body
  directly and the BFF would forward it verbatim. It also makes the admin API the one
  API of the gateway that answers differently, and a shared error helper could no
  longer serve it.
- **Branch on the HTTP status alone.** 403 already separates a refusal from a
  failure. It does not separate "you hold no administrative role" from "this tenant
  does not let you read that", and the console shows a different page for each.

## Consequences

- The BFF is the only place that knows the envelope. A route that bypasses it hands
  the browser a wrapped body, and the view reads `undefined`.
- Every protected admin route costs one database read for the roles. The read is not
  cached, so a role granted in the console takes effect on the next request.
- A person the tenant disabled cannot reach the admin API, even with a token that has
  time left. The user read filters on the active state, and the refusal is 401.
- Adding a fifth role means editing Go and deploying. This is accepted for now, and
  it is the point at which a roles table becomes the simpler answer.
