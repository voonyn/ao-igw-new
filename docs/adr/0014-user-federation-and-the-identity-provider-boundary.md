# 0014 - User Federation, and the External Identity Provider boundary

Supersedes the naming half of `docs/adr/0013`. The table shape, the four resolution
cases, the bind at the password step, and the constant-time floor of 0013 all stand.

## Context

ADR 0013 named the concept **Identity Provider** and gave it one table. It planned a
redirect provider as a second `type` value on that same table.

The word is wrong twice.

**It names the other thing.** The industry splits these two concepts, and Keycloak
splits them by name. User Federation reaches an external user store: the gateway
collects the password itself, proves it against the store, and creates the person here.
An Identity Provider is a redirect: the person types the password at the other system,
and the gateway receives an assertion. This deployment serves the first and none of the
second.

**The scope grew past "directory".** The external store can also be a database, MySQL
or PostgreSQL. The word Directory cannot name a SQL table of people, so no
directory-shaped name covers the concept.

The code half-made the split already. Four wire slugs say `directory_`:
`directory_unavailable`, `directory_no_entry`, `directory_misconfigured`, and
`directory_disabled`. No slug says `idp_`.

One more question came with the growth. Active Directory needs behaviour that plain
LDAP has no equivalent for: the `userAccountControl` disable bit, `pwdLastSet` expiry,
and the matching rule for nested groups. A branch point for that behaviour must exist
somewhere.

## Decision

**The concept is User Federation: an external user store a Tenant trusts to hold the
password of its people, and to prove it.** `CONTEXT.md` carries the full vocabulary.

**Identity Provider is a reserved word, and it names the redirect kind alone.** The term
is **External Identity Provider**: OIDC, SAML, Google, Microsoft Entra. Nothing serves
one today. It gets its own table, its own package, and its own link table when it lands.
The words **Identity Provider** and **Identity Link** are held for it and used nowhere
else.

**Two columns carry two axes, and neither carries both.**

| Column | Value | Meaning |
|---|---|---|
| `type` | 1 | directory |
| `type` | 2 | database, recorded and not served |
| `server_type` | 1 | LDAP |
| `server_type` | 2 | Active Directory |

`type` names the **Federation Method**, which is the shape of the row and the code path.
`server_type` names the server that method talks to. `server_type` values are numbered
globally and never restart per method, so MySQL and PostgreSQL take 3 and 4. A value
therefore means one thing on its own.

**Active Directory is a Server Type and never a Federation Method.** It is an LDAP
server with its own schema, and it shares every column with a plain LDAP server. The
code already proves it: `stableID` hex-encodes any attribute value that is not text, so
the binary `objectGUID` of Active Directory and the string `entryUUID` of OpenLDAP take
one path with no branch. Nothing else in `ldap.go` reads the vendor.

**`server_type` carries no behaviour today.** It exists because an administrator saves
an Active Directory row, reopens the form, and the Console must show which server was
picked. Nothing in Go branches on it yet. The first branch arrives with the
Active-Directory-only work above.

**Bind narrows, and External Proof is the category act.** A Bind is the LDAP operation.
An **External Proof** is the act that proves a password against a User Federation,
whatever the method. `Service.Prove` already carries that name, and the budget follows
it: `spendProof`, `proofKey`, `releaseProof`.

**The wire slugs move to the category.** A client branches on the slug, and no client
behaves differently for a directory outage than for a database outage. Method-named
slugs also tell every browser which kind of store a Tenant runs.

Four slugs move, and the fourth is not a directory word:

| Today | After |
|---|---|
| `directory_unavailable` | `federation_unavailable` |
| `directory_no_entry` | `federation_no_account` |
| `directory_misconfigured` | `federation_misconfigured` |
| `last_identity_link` | `last_federation_link` |

**`directory_disabled` is not in that list, because it is not a slug.** It is an audit
reason. `ErrDirectoryDisabled` answers the wire with `unauthenticated`, the slug an
unknown identifier gets, so a disabled row never names every person of one Tenant. That
decision is recorded at `ldap.go:52` and settled twice, in `3c86d71` and `b1f568d`. The
rename must not disturb it.

**Four audit reasons follow the category too**: `federation_disabled`,
`federation_unavailable`, `federation_misconfigured`, and `too_many_proofs`. They are
written at `session/service.go:363-369` and they reach no client.

**The names in code:**

| Today | After |
|---|---|
| `internal/identityprovider` | `internal/userfederation` |
| type `Provider` | `Federation` |
| `identity_providers` | `user_federations` |
| `identity_provider_domains` | `user_federation_domains` |
| `identity_provider_user_links` | `user_federation_links` |
| column `idp_id` | `federation_id` |
| `/identity-providers` | `/user-federations` |
| `/users/:id/identity-links` | `/users/:id/federation-links` |
| `ErrTooManyBinds` | `ErrTooManyProofs` |
| `ErrBindUnavailable` | `ErrProofUnavailable` |
| audit actions `idp.*` | `federation.*` |
| `audit_events.entity_type` value `identity_provider` | `federation` |
| Redis prefixes `idp_binds:`, `idp_tests:` | `federation_proofs:`, `federation_tests:` |

**The word "directory" stays wherever it names an LDAP or Active Directory server, or
the Directory method.** The errors inside `ldap.go` keep it: `ErrNoEntry`,
`ErrWrongPassword`, `ErrDirectory`. Console copy that tells a person about their
directory keeps it too.

**No behaviour changes.** Resolution keeps its four cases, the bind stays at the
password step, `pwd` stays the Factor, and every budget keeps its limit.

## Alternatives

- **Keep "Identity Provider" and change the Console label alone** — cheapest, and it
  hides a real boundary behind a screen title. The next person to add OIDC finds one
  table holding two credential models and one word for both.
- **"User Store" as the row noun** — Keycloak's own SPI name, and it reads well in a
  sentence. It puts a second word beside "User Federation" for one thing, and removing
  a second word is why this ADR exists.
- **One column: `type` = 1 LDAP, 2 Active Directory, 3 database** — two lines of code
  today, and it splits one axis into `type` values while the next axis needs a column
  anyway. MySQL and PostgreSQL are chosen by a driver string, not by a type. The table
  then carries two contradictory patterns.
- **One column and no vendor at all, with an Active Directory preset in the Console** —
  the lazy answer, and the form cannot show what was saved when it reopens.
- **Name the second column `vendor`, as Keycloak does** — honest only when every value
  is a vendor, which is why Keycloak's list ends in "Other". The first value here is
  `LDAP`, and LDAP is a protocol.
- **Name it `dialect`** — precise for SQL, where MySQL and PostgreSQL differ in the
  language itself. Active Directory and OpenLDAP both speak LDAP v3, RFC 4511, with the
  same operations on the wire. The difference is schema and extensions, so the word
  promises a protocol split that does not exist.
- **Name it `subtype`** — never wrong and never informative.
- **HashiCorp go-plugin for the database method** — it runs a plugin as a separate OS
  process over a gRPC pipe. `CLAUDE.md` forbids in-process state and requires that any
  instance serves any request, so a plugin process per instance is state to supervise,
  restart, and version-match. It adds no security, because the plugin runs on the same
  host with the same privileges. It buys one thing: a store a third party compiles. This
  gateway compiles every method it serves.
- **A registry of method implementations now** — `database/sql` is already the registry
  for the database method, and `sql.Open` takes the driver as a string. With two methods
  the seam is one function and a `switch` on `type`. `CLAUDE.md` forbids an interface
  with one implementation, and today there is one.
- **One table for both concepts, as 0013 decided** — a redirect provider carries a
  client id, a secret, an authorization endpoint, and issuer metadata. It carries no
  `bind_dn`, no `base_dn`, and no `user_filters`. One table leaves twenty columns always
  NULL for half the rows. One shared link table also needs one foreign key that points
  at two tables, which no database enforces.
- **Rewrite 0013 in place** — one file, and it deletes the alternative this was chosen
  over. A reader who asks why a directory is not an Identity Provider here needs both
  files to get an answer.

## Consequences

- The naming half of 0013 is superseded and its header says so. Everything else in 0013
  stands and is not restated here.
- Migration `00045` is edited in place and its file is renamed. Nothing is released, so
  every development database is dropped and re-run. A deployment that already ran 00045
  needs a rename migration instead.
- Audit rows already written keep `idp.*`. New rows carry `federation.*`, so a query
  over the full history reads two prefixes. Audit rows record a fact and are never
  edited.
- The Database method is recorded and not built. Three things stay open: what it does at
  the password step, whether it reads a hash or calls a query, and whether its columns
  join this table. ADR 0013 says a second type adds nullable columns to the same table,
  and that rule is the starting point.
- The Database method carries a security shape that the Directory method does not. A
  bind sends the password to the store and the store answers. A SQL table cannot, so the
  gateway reads credential material and compares it here. The "never log a credential"
  rule extends to that hash. A directory enforces its own expiry, lockout, and disable
  switch, and a SQL table enforces none of them.
- The glossary grew from five terms to nine. Two of the four new ones exist only to hold
  reserved words: External Identity Provider, and the Identity Link inside it.
- `CLAUDE.md` names the fifth Redis-only exception. It changes from
  `identityprovider.Service.spendBind` to `userfederation.Service.spendProof`.
- The Redis prefixes change, so every counter alive at the moment of deployment is
  stranded and each caller starts again from zero. Nothing is released, so the count is
  nothing. No test asserts either literal prefix, so no test catches this.
- The `server_type` column lands alone, and no Go names it yet. The column must reach
  the database before a bun field names it, because a field for a column that does not
  exist compiles and then fails every SELECT and every INSERT at runtime. The Go half
  waits for a second reason: the value cannot make the round trip today. No request DTO
  accepts it, `federationColumns` in `repo.go` excludes it so no write persists it, and
  no response DTO returns it. Constants and a bun field with no path to a saved value
  are the abstraction `CLAUDE.md` refuses. They land in the same change that lets the
  Console pick a server, and `repo.go` carries the note that says so.
- `ErrServerScheme` stays exactly as it is. It reports an address whose scheme does not
  match the transport, `ldap://` against `ldaps://`, and it has nothing to do with the
  new `server_type` column. Two near words now sit in one package, and neither is a
  synonym for the other.
