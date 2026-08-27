# Portal account API and Digital Identity

Status: ready to build. Settled over seven rounds of review on 2026-08-26.

This document uses the words of `CONTEXT.md`. Five terms are new, and they are
listed under **Vocabulary** below.

## Problem Statement

Two problems, and they are independent.

**The portal is dead.** The user portal is a complete front end. Every view is
written and every proxy route exists. The gateway serves no account API, so every
one of those screens answers nothing. A person signed in to this deployment cannot
read their own activity, change their own password, edit their own profile, list
their own Login Sessions, or disconnect an Application they connected.

**A tenant cannot use Digital Identity.** Every sign-in needs a password. A tenant
that wants a person to sign in by presenting a credential from a Wallet has no way
to offer it, and a person the tenant provisions is unknown to the Scan Verifier.

## Solution

**A self-service account API.** One route group, mounted for the account Resource,
serving the eight operations the portal already calls. Each route acts on the
Subject of the caller's own token and on nothing else.

**QR Login and DI Enrolment.** A person signs in by scanning a code with a Wallet.
A person the tenant creates or invites is registered with the Scan Verifier, so the
scan resolves to a real account. One deployment setting switches the whole
integration. With it off, the gateway behaves exactly as it does today.

## User Stories

1. As a person, I want to read my own profile, so that I can confirm the deployment holds the right name for me.
2. As a person, I want to edit my first name, last name, display name, and language, so that Applications show me correctly.
3. As a person, I want to change my own password, so that I can replace one I believe leaked.
4. As a person, I want a new password refused when it is too weak, so that I do not lock a weak secret onto my account.
5. As a person, I want the refusal to name no rule, so that nobody maps the tenant policy by trying passwords.
6. As a person, I want every other device signed out when I change my password, so that whoever took the old password loses access.
7. As a person, I want my own session kept when I change my password, so that I am not signed out of the page I am using.
8. As a person, I want to list my Login Sessions, so that I can see where I am signed in.
9. As a person, I want my current Login Session marked, so that I do not end the one I am using by mistake.
10. As a person, I want to revoke one Login Session, so that I can end access from a device I lost.
11. As a person, I want the Grants of a revoked Login Session deleted with it, so that the Application loses its Refresh Token too.
12. As a person, I want to sign out everywhere else in one action, so that I do not revoke sessions one at a time.
13. As a person, I want to read my own activity, so that I can see what happened on my account.
14. As a person, I want to page through my activity, so that I can look further back than one page.
15. As a person, I want my activity to show what I did, so that the feed is about me and not about administration.
16. As a person, I want to list the Applications I connected, so that I can see who holds my Consent.
17. As a person, I want each connected Application named, so that I recognise it.
18. As a person, I want to see which connected Applications hold a live Grant, so that I can tell an active one from a dormant one.
19. As a person, I want to disconnect an Application, so that it stops receiving my claims.
20. As a person, I want a disconnect to withdraw the Consent and delete the Grants together, so that the Application cannot keep using a Refresh Token.
21. As a person, I want the portal to hide what this deployment does not serve, so that I am not offered something that fails.
22. As a tenant administrator, I want the password policy I set enforced when I create a person, so that the policy is not advisory.
23. As a tenant administrator, I want the same policy enforced on a self-service change, so that a person cannot go around what I set.
24. As an operator, I want a warning when the policy asks for a check this deployment cannot run, so that I know the setting has no effect.
25. As a person, I want to sign in by scanning a QR code with my Wallet, so that I do not type a password.
26. As a person, I want the QR code to carry a fallback link, so that I can continue when I do not have the Wallet app.
27. As a person, I want the QR code to stop working after a short time, so that a photograph of my screen is not a way in.
28. As a person, I want a failed scan to tell me nothing about why, so that the endpoint cannot be probed.
29. As a person, I want a scan that names no account to fail, so that a scan never creates an account nobody approved.
30. As a person, I want the QR tab hidden when this deployment runs no Scan Verifier, so that I am not offered a dead option.
31. As a tenant administrator, I want each person I create registered with the Scan Verifier, so that they use QR Login with no further step.
32. As a tenant administrator, I want each person I invite registered too, so that an invited person is not silently unable to scan.
33. As a tenant administrator, I want a failed DI Enrolment to leave the person created, so that an outage at a third party does not lose my work.
34. As a tenant administrator, I want to see whether a person is enrolled, so that I can find the ones a failure left behind.
35. As a tenant administrator, I want the enrolment field hidden when this deployment runs no Scan Verifier, so that the console shows nothing that does not apply.
36. As an operator, I want the whole integration switched by one setting, so that the gateway runs with no Scan Verifier at all.
37. As an operator, I want a half-configured Scan Verifier to refuse to mount, so that a typo never decides who gets in.
38. As an operator, I want the push callback refused when it holds no credential, so that nobody who reaches it can assert a scan for any person.
39. As an operator, I want one log line for every Scan Verifier round trip, so that I can tell a call that never left from one the verifier refused.
40. As an operator, I want an administrative create to wait no longer than the configured timeout, so that a slow third party does not hang the console.
41. As an operator, I want a failed enrolment to leave a queryable mark, so that finding the unmirrored people does not mean reading logs.
42. As a developer, I want the QR Login Transaction addressable by the verifier's own identifiers, so that a push carrying no Tenant still finds its row.
43. As a developer, I want one response envelope across every API of this deployment, so that a client learns one shape.

## Implementation Decisions

### The account API and its gate

- The account API mounts behind the Tenant middleware and then the bearer guard,
  the same way the admin management API mounts (ADR 0006).
- The guard admits only a token minted for the account Resource. A token for the
  admin Resource never reaches these routes (ADR 0005).
- The Tenant is resolved from the host. The portal calls the Issuer origin, so the
  host already names the Tenant. The reference implementation instead derived the
  Tenant from the token Issuer and mounted no host middleware. That is not carried
  over, because it would add a second tenant path to this codebase.
- There is no Role gate. Every route acts on the token Subject alone.
- Eight operations: update profile, change password, list Login Sessions, revoke
  one, revoke every other one, read activity, list connected Applications, and
  disconnect one Application.
- There is **no** profile read. The userinfo endpoint already releases the fields
  the portal renders, through the Tenant's own Scope and Claim Mapper
  configuration. A second read would answer the same fields under a second set of
  rules about who sees what.

### Where the services live

- One self-service service inside each domain that owns the table it reads.
  Profile and password belong to the user domain, Login Sessions to the session
  domain, activity to the audit domain, connected Applications to the OIDC domain.
- No new domain package. A package that owns no table would reach into four that
  do.
- The router assembles the four, as it already assembles the admin management API.

### The response envelope

- The account API answers in the one envelope this deployment uses everywhere.
  The reference implementation deliberately answered bare payloads on both of its
  authenticated APIs. That choice is not carried over.
- The error half of the portal already matches. Every view branches on the
  top-level slug, which this envelope carries.
- The success half does not. Three portal reads expect a bare payload. The portal
  is adjusted to read the envelope. The portal is the only consumer of this API,
  so it is the cheaper side to change.

### The password policy

- One check reads the resolved two-level policy and refuses a password that fails
  it: minimum length, minimum character classes, and the deny list.
- Length counts characters, not bytes.
- A deny word matches anywhere in the password, and case does not matter. A tenant
  that denies its own product name means to refuse a password built around it.
- The refusal names no rule. One answer for every rule discloses neither the
  minimum length nor the list.
- The check reaches the user domain as a function value, so that domain imports
  nothing from the policy domain.
- Two writes call it: the administrative create, and the self-service change. The
  one-time bootstrap secret is generated, not chosen, and does not.
- The breach toggle is not honoured. This deployment builds no breach client.
  Refusing every password would be worse than the check being absent, so the write
  proceeds and the gap is logged once per call.
- A failed policy read is logged in the policy domain, which is the last layer
  that can name the Tenant and Organization the read was for. The caller receives
  an error it cannot classify. That is the price of the function value.

### Login Session self-service

- A revoke deletes the Login Session and the Grants that fanned out from it,
  exactly as the administrative revoke does. Both are consumed rows and neither is
  recoverable (ADR 0002).
- The bulk revoke takes an exception: every Login Session of the Subject except the
  one named.
- The caller's own Login Session is named by the portal, not by the gateway. The
  access token carries no session identifier. The portal holds a validated ID
  token, which carries one, and it sends the value. No token contract changes.
- A password change performs the same bulk revoke and keeps the caller's session.

### Activity

- The feed reads the audit trail filtered to events where the person is the actor.
  An event where the person is the entity, such as an administrative lock, is not
  shown. The cost is stated: an administrator locking the account never appears in
  that person's feed.
- Paging is by offset, like every other list of this deployment (ADR 0007). The
  portal is adjusted from cursor paging to page numbers.

### Connected Applications

- A connected Application is one remembered Consent, joined to the Grants that
  Consent produced. The answer names the Client, the Application name, the Scopes,
  whether a live Grant exists, and two timestamps.
- A disconnect soft-deletes the Consent and deletes the Grants of that Subject for
  that Client, in one transaction. The Consent table already carries a soft-delete
  column and a unique key that survives it (ADR 0001).
- Three repository reads are added: the Consents of one Subject, a soft delete of
  one Subject's Consent for one Client, and a delete of the Grants of one Subject
  for one Client.

### Digital Identity: the outbound client

- One client with two operations: start a verifiable-presentation transaction, and
  enrol a person.
- The Scan Verifier authenticates the caller in the request body, not in a header.
  A header produces a bare refusal.
- The response body is capped. The Scan Verifier is a third party, and an unbounded
  read makes this deployment's memory its decision.
- One log line per round trip records the method, the path, the status, and the
  duration. Without it, a call that never left and one the verifier refused look
  identical from outside.
- Settings are deployment-wide, not per Tenant. There is one Scan Verifier today.
  Per-Tenant credentials become an additive table the day a second Tenant needs
  different ones.

### Digital Identity: the flow

- QR Login lives in its own domain package, so the Scan Verifier dependency stays
  out of the package every sign-in path imports.
- The Scan Verifier **pushes** the result to a callback rather than being read back
  for it. This is why a queryable QR Login Transaction exists at all: the pushed
  body carries only the verifier's own identifiers, and the sealed Login Session
  blob is opaque to SQL. **This decision gets its own ADR.**
- Start opens a Login Session that names nobody, mints a nonce, calls the verifier,
  writes the transaction, and returns the verifier's QR object unchanged.
  Re-encoding it would drop any field the verifier adds, including the fallback
  link the sign-in page offers as "no app?".
- The callback writes the result on the transaction and never touches the Login
  Session. The browser polls with the Login Session token, and recording a factor
  rotates that token. A callback that recorded the factor would invalidate the
  token before the browser learned it had succeeded.
- The poll performs the binding and records the factor. It is the only party
  holding a valid token.
- The transaction has a short lifetime, sized above the verifier's own window, so a
  scan the verifier accepted is never rejected here.
- Three poll answers only: pending, authenticated, and expired. Expired, consumed,
  and unknown all answer expired. Telling them apart is free reconnaissance on an
  endpoint whose success means "sign somebody in".
- A presented name that resolves to no person fails the transaction. A scan never
  becomes a registration nobody approved.
- The transaction's unique keys on the verifier's two identifiers are global, not
  Tenant-scoped. The callback has no Tenant until that lookup answers, so global
  uniqueness makes replay a database constraint instead of application logic.

### Digital Identity: the Login Session

- The session domain gains two operations: open a Login Session that names nobody,
  and complete one by binding a Subject and recording a named factor. The second
  rotates the token and extends the lifetime, as the password step already does.
- QR Login calls both and never writes the Login Session table itself. One writer
  keeps the token-rotation rule in the domain that owns it.
- The completing operation takes the factor name as a parameter and knows nothing
  about the Scan Verifier. A later factor reuses it unchanged.
- The factor name for a scan is a value the AMR registry does not list. The
  registry permits other values. The existing note that factor names are registry
  values is amended to say a registry value is used where one fits, and this value
  where none does.

### Digital Identity: enrolment

- Two administrative writes enrol: the create, and the invitation. Both produce a
  person with a username, and the Scan Verifier keys on the username. A person with
  no username is skipped.
- The call runs after the commit and outside the transaction. The Scan Verifier is
  a third party with no compensating delete on this side, so letting its outage
  roll back a committed person would trade a missing mirror for a lost person.
- The call is synchronous, bounded by the configured timeout. A background call
  would be in-process state, which this deployment forbids: any Instance serves any
  request, and a shutdown mid-call would lose the enrolment with no record.
- Success stores the verifier's identifier for that person. A failure is a warning
  naming the person and leaves the column empty. The empty column is the queryable
  list of who is not mirrored, and a retry reads it to know whom to skip.

### The switch

- One deployment setting enables the whole integration. With it off, the QR routes
  are not mounted, no enrolment is attempted, and nothing else changes.
- A half-configured Scan Verifier refuses to mount. Each credential pair is set on
  both halves or on neither. A half-set pair is a typo, and a typo must never
  decide who gets in.
- Absent callback credentials refuse to mount. The reference implementation mounts
  the callback open with a warning, for a local loop with no verifier. That is not
  carried over: an endpoint whose success means "sign this person in" is the last
  one to leave open, and a local loop costs two configuration values.
- One open capability endpoint answers whether this deployment runs a Scan
  Verifier. Both front ends read it. The reference implementation used a second
  setting in the sign-in front end, unlinked from the gateway's own. Two unlinked
  switches is not one switch.
- The capability names the integration, not the flow, because it gates enrolment as
  well as QR Login.

### Front ends

- The portal's passkey and authenticator surfaces are removed: the proxy routes and
  the blocks that render them.
- The two portal navigation items no API serves are removed. One is an Application
  catalogue with access requests, which has no backend in any version of this
  product. The other is support content.
- Placeholders inside live views that already label themselves stay.
- The sign-in front end gains a QR step and its actions, ported from the reference
  implementation, which uses the identical folder structure.
- The sign-in front end reads the capability and renders the QR tab only when this
  deployment runs a Scan Verifier.
- The console gains a read-only enrolment field on the person detail, rendered only
  when the capability says the integration is on.

### Schema

- One nullable column on the person table for the Scan Verifier's identifier.
- One table for the QR Login Transaction. It carries the Tenant, the Login Session,
  the verifier's two identifiers, a digest of the nonce, the state, the resolved
  person, the expiry, and the consumption time. The nonce plaintext only ever goes
  to the verifier.
- The transaction is a consumed row, not an entity. It carries no soft-delete
  column, and a later prune hard deletes it.

### Vocabulary

Five terms are added to the glossary.

- **Scan Verifier** — an external service that turns a presented credential into a
  proven identity. Digital Identity is the first and today the only one.
- **QR Login** — the flow where a person proves who they are by presenting a Wallet
  credential, instead of typing a password.
- **QR Login Transaction** — one QR Login in flight: the code on screen, the nonce
  it binds, and the result the verifier pushes back.
- **Wallet** — the application on the person's phone that holds the credential and
  answers a scan.
- **DI Enrolment** — the account the Scan Verifier keeps for one gateway person,
  keyed by that person's username.

A note goes under QR Login Transaction: the Scan Verifier's own session identifier
is a **fourth** meaning of the word "session" in this system. It is not a Login
Session and it is not an Authn Session.

## Testing Decisions

**What makes a good test here.** It asserts on what a caller observes: the answer,
the status, the slug, or the row that survived. It never asserts on how the answer
was produced. A test that names an internal helper breaks on a refactor that
changed nothing a caller can see.

Six seams carry this work. Five already exist in this codebase. Six is more than
the ideal of one, and each one sits on a different boundary: in-process rules,
inbound HTTP, outbound HTTP, SQL, and the browser. No single seam crosses all five.

**1. The assembled gateway over HTTP.** The highest seam, and the only one that
sees the audience gate, the host-based Tenant lookup, the envelope, and the token
rotation. Prior art: the existing end-to-end authorization-code flow test, which
builds the real routes over a real database and cache and asserts on HTTP answers.
Gated on the integration environment variable. Two new flows:

- Account API: sign in, list Login Sessions, revoke one, confirm its Grant died,
  change the password, confirm the other sessions ended and the caller's did not.
- QR Login: start a transaction, post a callback as the Scan Verifier would, poll
  to authenticated, and complete the authorization request.

**2. The service, with its dependencies as closures.** The bulk of the work. Prior
art: every existing service test in this codebase. No database and no HTTP, so it
runs on any machine.

- The four account services: ownership, the Subject predicate, the exception on the
  bulk revoke, and the actor filter on the feed.
- The QR Login service: the nonce mismatch, the expired transaction, the consumed
  transaction, the unknown name, and the division of labour between the callback
  and the poll.
- The administrative create and invitation: a refused password, and an enrolment
  that fails without failing the write.

**3. The repository, on a scratch schema.** Prior art: the existing repository
tests over the scratch-schema helper, which applies every migration and drops the
schema afterwards. Gated on the database environment variable.

- The three new Consent and Grant queries. Their Tenant and Subject predicates are
  the whole point of them, and only a database proves a predicate.
- The QR Login Transaction reads, including the global lookup by the verifier's
  identifier.

**4. The Fiber middleware.** Prior art: the existing sign-in token and bearer
middleware tests, which mount one route and send requests at it.

- The static credential gate on the push callback: a correct pair, a wrong pair, an
  absent header, and a pair that differs only in case.

**5. The pure function.** Prior art: the error mapper test, and the password check,
which is already written and passing.

**6. The outbound HTTP client.** The one new seam. A local test server stands in
for the Scan Verifier. An outbound client has no higher seam, and the client's two
operations are the highest point inside it.

- A well-formed answer, a half-filled answer that must fail rather than store an
  empty identifier, a non-success status, a body that is not JSON, and the status
  word the verifier returns inside a success.

**7. The front-end pure function.** Prior art: the existing account-health test,
which runs on the built-in Node test runner with no framework and no new
dependency.

- The account-health derivation, which loses two checks when the passkey and
  authenticator surfaces go.

## Out of Scope

- Passkeys and the authenticator, on every surface. A later slice.
- Rate limiting on the account API. A limiter covering every API the portal calls
  is a later, separate piece. Every account route already sits behind a valid token
  for that exact person.
- Breach checking. This deployment builds no breach client.
- The Application catalogue and access requests. That navigation item is removed,
  not built. It has no backend in any version of this product.
- Support content.
- Scan-driven registration. A scan that names no person fails.
- Retrying a failed DI Enrolment from the console. The field is read-only.
- Per-Tenant Scan Verifier credentials.
- Cursor paging.
- The redeem endpoints for the invitation and the password-reset token. Both tokens
  are minted today and nothing redeems either one. The sign-in front end already
  holds the pages. The gap is named here and left.
- The dead authenticator and passkey pages in the sign-in front end. They are
  unreachable from the flow, and their back half is a later slice.
- A prune job for expired QR Login Transactions. The index is provisioned and the
  job is not, matching the existing precedent for account tokens.
- Branching and committing.

## Further Notes

**Reference implementation.** Two sibling folders hold earlier versions of this
product. The newer one carries a working Digital Identity integration. Both are
read-only reference, and neither is modified.

**The two codebases do not share idioms.** This one passes cross-domain work as
function values inside a dependency struct. The reference passes interfaces into
routers. A file copy does not compile. The outbound client ports almost unchanged.
The flow is rewritten.

**Order of work.** The portal is built first. It needs no third party and no
migration, and it proves the account Resource path before the Scan Verifier is
added on top.

**Already done.** The password check, its tests, and its registration in the error
mapper are written and passing. Nothing else has started.

**Found and not acted on.** The administrative create bounds its password at 255
characters, and bcrypt reads the first 72 bytes. A longer password truncates
silently. This sits outside the agreed scope and is recorded here.

**The portal defines the contract.** The front end is complete: every view is
written and every proxy route exists. The gateway is being built to match what the
portal already calls, not the other way round.
