# 0013 - One Identity Provider table, and a bind at the password step

## Context

A Tenant that runs Active Directory holds every password of its staff. Today that
Tenant must give every person a second password here, and a person disabled in the
directory keeps a working password in this gateway.

The gateway proves a password in one place. `session.Service.VerifyPassword` compares
a bcrypt hash at `internal/session/service.go:172`, and nothing else proves a password
at sign-in. Two questions had to be answered before any of it could be written, and
they are one design.

**Where the provider record lives.** Zitadel is the closest system to this one. It
holds one generic `idp_templates` row per provider plus one detail table for each of
thirteen types, and it is moving away from that shape: the relational rewrite uses a
single `identity_providers` table with a `type` column and a JSON payload. The old
shape leaked version digits into table names, `idp_templates6_ldap2`, and a later
installation created `_ldap3`.

**Where the credential is proved.** An LDAP bind is not a redirect. The gateway itself
collects the password, so the bind can sit at the identifier step, at the password
step, or in a flow of its own. Zitadel gives LDAP its own entry point and its own form
because the person picks a provider from a button list first.

This deployment has no button list. `users.org_id` is mandatory, every person sits in
exactly one Organization, and the identifier step already answers alike for a person
who exists and a person who does not.

## Decision

**One table, `identity_providers`, with a `type` column and per-type columns inline.**
`type = 1` is LDAP. A second type adds nullable columns to the same table. The
Organization level is `org_id`, where `''` is the Tenant-wide row.

**The resolved row wins whole, never merged.** `auth_policy_settings` merges knob by
knob in Go at `internal/authpolicy/dto.go:146-153`, and this table must not: half a bind
DN from one row and half from another is nonsense. Resolution never walks the two levels
either. None of the four cases below reads `org_id`, so no level precedence exists to
write, and `org_id` decides only the Organization a bind creates people in.

**The tie to a person is a table, `identity_provider_user_links`.** One directory
account maps to one person, and one person holds at most one account per provider. One
person can hold several links, one per provider.

**A domain is a row, in `identity_provider_domains`, unique per Tenant.** A JSON list
cannot carry a unique key, and two administrators can otherwise claim one domain for
two providers at the same moment.

**The bind runs at the password step.** The identifier step resolves the provider and
records it on the Login Session. It is one of four cases:

1. The identifier carries a domain the Tenant claims.
2. The person holds exactly one Identity Link whose provider accepts a typed password.
3. The person holds a password hash, which is the local compare of today.
4. No local person, and the Tenant holds exactly one live active provider.

**Case 4 refuses when a Tenant holds two or more providers.** A person with no local
row and no domain in their identifier is then told to type the domain.

**A successful bind records the Factor `pwd`**, and the session upgrade is the existing
one. `acr` is unchanged, because it counts Factors and never names them.

## Alternatives

- **One table per provider type, named `ldap_providers`** — the honest name for one
  type, and a rename plus a data migration on the second. It also splits the shared
  fields, the name, the state, and the ownership, across every future table.
- **Zitadel's shipped shape, a base table plus a detail table for each type** — a join
  on every read and two repositories, for one type. It earns its place at the third
  type, and this deployment has one.
- **A JSON payload column, which is Zitadel's newest answer** — right at thirteen
  types. At one type it gives up schema validation, gives up an index, and makes the
  admin DTO map every field by hand.
- **Two columns on `user_humans`, beside `di_user_uuid`** — smaller, and it was the
  first recommendation. It holds one external identity per person, so a person who
  later signs in through a second provider needs the table anyway. The table is built
  once, now.
- **A domain list in a JSON `TEXT` column, the `pw_deny_list` shape** — no unique key,
  so the rule lives in application code and loses the race between two saves.
- **The bind at the identifier step** — it would let the gateway answer "no such
  person" early. That is exactly the disclosure the identifier step exists to prevent,
  and the gateway does not hold the password at that point.
- **A default provider per Tenant for a bare username** — it looks friendlier than a
  refusal. A Tenant with two directories would send one customer's password to the
  other customer's server, and nobody would see an error, because the bind simply
  fails. Zitadel offers no such flag either.
- **A Factor name of its own, for example `ldap`** — it teaches every relying party a
  second word for a proved password. The Assurance Level counts Factors and never names
  them, so no client gains anything. Which directory proved it belongs in the audit
  trail.

## Consequences

- A second provider type is additive: new nullable columns, a new `type` value, and no
  migration of any existing row. The stated ceiling is the third type, where the
  nullable columns turn ugly and a detail table or a payload column earns its place.
- A Tenant that registers a second provider loses the bare-username route for every
  person, including the people of the first directory. Every person must then type a
  domain, or hold a link already. This is the price of the refusal above, and it is
  visible to the administrator who adds the second provider.
- The Login Session gains one field. The blob is `SealJSON(LoginSession)` and no SQL
  read names a field inside it, so there is no migration. Sessions already in flight
  decode the new field to its zero value, which is case 3, which is what they were.
- The password step stops being constant time on its own. `decoyPasswordHash` gives
  the local path one cost for every answer, and a bind answers an unknown entry faster
  than a wrong password. The step therefore gains a fixed floor, applied to every
  answer, local and directory alike.
- Case 1 outranks case 3, so a domain claim moves every person whose email carries that
  domain onto the directory, including the people who hold a local password and no
  directory account. The claim therefore runs the same last-local-`IAM_OWNER` check that
  a role removal runs, and case 4 reads the person row without the `state` filter, so a
  deactivated or soft-deleted person never reads as "no local person".
- A person the directory owns holds a NULL `password_hash` for ever. Three destructive
  portal routes re-prove a password through one function, so that function proves the
  same credential the person signs in with: a bind.
- The bind is an outbound call into a customer network that any caller can drive. It
  gains a budget of its own, on a Redis key of its own, which is a **fifth** exception
  to the stateless rule in `CLAUDE.md`. That file is amended in the same change.
- `pwd` in `amr` means "the person proved a password" and never says whose password
  store answered. A relying party that must tell the two apart cannot, and none has
  asked. Adding a name later would be a breaking change to a published contract, which
  is the reason to decide it once, here.
