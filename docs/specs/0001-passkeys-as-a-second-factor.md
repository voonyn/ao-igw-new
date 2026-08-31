# Passkeys as a Second Factor

Status: ready for agent. Vocabulary: `CONTEXT.md`. Decisions: `docs/adr/0012`.

## Problem Statement

A person who signs in to this gateway proves a password. When the Tenant demands more,
that person must also prove a TOTP code from an Authenticator.

TOTP costs the person real effort. The person must install an application, keep a
shared secret, read six digits under a thirty-second clock, and type them before the
clock runs out. A person who loses the phone loses the Factor.

TOTP is also the weaker Factor. An attacker who phishes a person can ask for the code
and replay it inside its window. The code proves that the person holds a secret. It
never proves which site the person is on.

Every device a person already owns can do better. A laptop, a phone, and a hardware key
all hold a key pair, unlock it with a fingerprint or a PIN, and sign a challenge that
works on one domain alone. The gateway cannot use any of them.

The database is ready and nothing else is. The Passkey table exists. The RP ID setting
exists. The administrator reset already clears Passkeys. Five comments in the code say
"no passkey backend exists", and two tests lock that state in place, so that a Passkey
row can never route a person to a screen that nothing answers.

## Solution

A person can register a Passkey and use it as a Second Factor, beside TOTP and never
instead of it.

In the Portal, a person adds a Passkey, names it, sees when each one was last used, and
removes one. In the sign-in front end, a person who holds a Passkey answers a touch or
a fingerprint instead of a typed code. A person who must enrol picks a Passkey or an
Authenticator, and never has one forced on them.

In the Console, a Tenant administrator sees the Passkeys of one person, and revokes a
single lost device. The other Factors that person holds survive the revoke.

A relying party reads `webauthn` in the `amr` claim. It can tell the two Second Factors
apart for the first time.

A person who holds both Factors is offered both at every challenge. A device left at
home never shuts that person out of a Factor that works.

## User Stories

### The person who signs in

1. As a person who holds a Passkey, I want a touch instead of a typed code, so that I finish a sign-in in one second.
2. As a person who holds a Passkey, I want the challenge to appear as soon as my password is accepted, so that I run no extra step.
3. As a person who holds a Passkey and a TOTP Enrolment, I want both offered on one screen, so that I pick the one my device supports right now.
4. As a person who holds both Factors, I want the Passkey offered first, so that the faster Factor is the default.
5. As a person whose Passkey device is at home, I want a visible link to the Authenticator challenge, so that I sign in without help.
6. As a person who cancels the browser prompt by mistake, I want to retry on the same screen, so that I lose no progress.
7. As a person whose Passkey fails, I want a message that names the reason, so that I know whether to retry or to switch Factor.
8. As a person on a browser with no passkey support, I want the control visible and disabled with a reason, so that I do not think the feature is broken.
9. As a person who signs in on a shared computer, I want no record of my Passkey left behind, so that the next person learns nothing.
10. As a person with a screen reader, I want the challenge announced and focused, so that I reach the prompt without sight.
11. As a person who uses a keyboard alone, I want to start the challenge from the keyboard, so that I need no pointer.
12. As a person on a slow connection, I want the challenge start to show progress, so that I do not press the button twice.

### The person who must enrol

13. As a person the MFA Requirement governs, I want a choice of Passkey or Authenticator, so that I pick the Factor that fits my devices.
14. As a person with a modern phone, I want the Passkey offered first at enrolment, so that I get the stronger Factor by default.
15. As a person on a managed device with no authenticator, I want the Authenticator choice always present, so that enrolment never dead-ends.
16. As a person who just registered a Passkey during sign-in, I want to continue straight to the application, so that I run no second challenge.
17. As a person who abandons Passkey enrolment, I want to fall back to the Authenticator, so that one failed attempt does not block me.
18. As a person who enrols with a Passkey alone, I want to know that an administrator is my only way back, so that I choose with open eyes.

### The person who manages their own account

19. As a person in the Portal, I want to add a Passkey, so that I stop typing codes.
20. As a person who adds a Passkey, I want to name it, so that I know which device each row is.
21. As a person who adds a Passkey, I want a sensible default name, so that I can accept it and move on.
22. As a person with several devices, I want to register a Passkey on each, so that any one of them signs me in.
23. As a person in the Portal, I want each Passkey to show when it was added and when it was last used, so that I spot the one I no longer use.
24. As a person in the Portal, I want to rename a Passkey, so that a name I chose in a hurry can be corrected.
25. As a person in the Portal, I want to remove one Passkey, so that a device I sold cannot sign in.
26. As a person who removes a Passkey, I want to prove my password first, so that a leaked access token cannot strip my Factor.
27. As a person who removes a Passkey, I want a confirmation that names the device, so that I never remove the wrong one.
28. As a person who removes my last Second Factor, I want to be told that my next sign-in will ask me to enrol again, so that the consequence is no surprise.
29. As a person who tries to register a device already registered, I want to be told so plainly, so that I do not create a duplicate.
30. As a person in the Portal, I want the Passkey list and the TOTP block on one security screen, so that I see every Factor in one place.
31. As a person who holds a Passkey and no TOTP Enrolment, I want the Portal to say that Recovery Codes cover TOTP alone, so that I am not surprised later.
32. As a person who reaches the cap of ten Passkeys, I want a clear message, so that I know to remove one first.
33. As a person who added or removed a Passkey, I want an audit record and a notification, so that a change I did not make reaches me.

### The Tenant administrator

34. As a Tenant administrator, I want to see the Passkeys of one person, so that I can answer a support call about a lost device.
35. As a Tenant administrator, I want to revoke one Passkey, so that a lost laptop stops working and the other Factors survive.
36. As a Tenant administrator, I want a confirmation that names the Passkey, so that I never revoke the wrong device.
37. As a Tenant administrator, I want the whole MFA reset to stay available, so that a person with no working Factor can start again.
38. As a Tenant administrator, I want the single flag on the user list to keep counting both Factors, so that nothing I already read changes meaning.
39. As a Tenant administrator, I want to be refused when I lack the role, so that a read-only member cannot revoke a Factor.
40. As a Tenant administrator, I want every passkey action named in the audit view, so that the Console stops hiding second-factor events it already stores.
41. As a Tenant administrator, I want no way to register a Passkey for another person, so that a Factor always belongs to the person who holds the device.
42. As a Tenant administrator, I want to be refused when I add a Tenant Domain that breaks the shared registrable domain, so that I never silently kill every Passkey.
43. As a support agent, I want the Passkey list to show a device name and a last-used date, so that I confirm which device the caller lost.

### The relying party and the operator

44. As a relying party, I want `webauthn` in the `amr` claim, so that I can tell a Passkey sign-in from a TOTP sign-in.
45. As a relying party, I want the `acr` claim unchanged, so that my existing check for two Factors keeps working.
46. As a relying party, I want the claim names fixed from the first release, so that I never rewrite my check.
47. As a Deployment operator, I want the RP ID derived from the request host, so that I configure nothing per Tenant.
48. As a Deployment operator, I want one environment override for development, so that passkeys work on a non-registrable host.
49. As a Deployment operator, I want a registration refused when the RP ID does not cover the origin, so that I never create a Passkey that no sign-in can use.
50. As a Deployment operator, I want every ceremony failure logged with the user id, so that I can troubleshoot without a credential in the log.
51. As a Deployment operator, I want no secret in any log line, so that a log file is never a credential store.

### Security

52. As a security reviewer, I want a challenge consumed once, so that a captured answer cannot be replayed.
53. As a security reviewer, I want a challenge to expire, so that an old one cannot be answered tomorrow.
54. As a security reviewer, I want a sign-in challenge start to spend the shared guessing budget and an enrolment start to spend a budget of its own, so that a flood of challenges is bounded and a cancelled prompt does not spend the budget a code sign-in reads.
55. As a security reviewer, I want a failed assertion to leave the sign-in alive, so that a hostile page cannot end a person's session for them.
56. As a security reviewer, I want a Passkey bound to its domain, so that a phishing site cannot use it.
57. As a security reviewer, I want a revoked Passkey to stop working at once, so that a revoke is not advisory.
58. As a security reviewer, I want the gateway to store no private key, so that a database leak exposes no credential.
59. As a security reviewer, I want one function to answer both the step signal and the finalize gate, so that the two can never disagree.

## Implementation Decisions

### Scope and role

- A Passkey is a Second Factor only. The person types a password first, in every case.
  Passwordless sign-in and usernameless sign-in are out of scope.
- A Passkey satisfies the MFA Requirement, exactly as a TOTP Enrolment does.
- The two Console routes run two gates. The **list** runs the read gate of the user
  domain, the one that already answered that administrator the user list and the account
  record, so an administrator of one organization reads the devices of a person in
  another and answers their lost-device call. The **revoke** runs the write gate, which
  narrows to the organization of the account. Story 39 names the revoke, and this is
  what it narrows.

### Modules

- A new `passkey` domain package holds the ceremonies. It follows the layout of the
  `totp` package: a handler, an account handler, a service, an account service, a
  repository, DTOs, and a model.
- The new package imports neither the user domain nor the login session domain. It
  receives what it needs as function values in a `Deps` struct, exactly as the `totp`
  package already does. The composition root wires them.
- The `user` domain keeps the Passkey reads it already owns, and keeps its clear
  function for the administrator reset. The new package owns the ceremony reads and
  writes.
- The pending-step resolver in the composition root gains a Passkey read. It counts
  TOTP alone today. One function keeps answering both the step signal and the finalize
  gate.

### The sign-in contract, and the gate it must not break

This is the part the code constrains hardest. Read it before anything else.

- The finalize gate reads each Pending Step **as a key in the proved Factors of the
  Login Session**. A step name and its Factor name must therefore be the same string.
  `otp` already works that way.
- The passkey challenge step is `webauthn`, matching the Factor. The enrolment step is
  `webauthn_enroll`. A step named `passkey` would be owed for ever, and every passkey
  sign-in would end in `insufficient_factors`.
- The gate demands **every** step it reads. A person who holds both Second Factors is
  offered both and proves one. **The gate must therefore change: a challenge step is
  satisfied by any proved Second Factor.** An enrolment step keeps its exact match,
  because a person who owes enrolment has proved nothing.
- Nothing regressed by that change. The step list held one entry until now, so the two
  readings could not differ.
- The password answer carries every step the person can run, most preferred first.
  `webauthn` comes before `otp`. The forced enrolment answer carries `webauthn_enroll`
  and `otp_enroll`.
- The proved Factor is recorded as `webauthn`, and it reaches the `amr` claim. See
  ADR 0012.
- The Assurance Level is unchanged. It counts Factors and never names them.

### Abuse limits

- A ceremony **start** spends a budget keyed by tenant and person. A start is the
  request that costs work, and a valid session can otherwise ask for challenges without
  end. There are two budgets, and they are separate keys. A **sign-in** challenge start
  spends the shared guessing budget, exactly as a TOTP submission does. An **enrolment**
  start spends the enrolment budget of its own, because a start answers no challenge and
  proves nothing: a person who cancels a browser prompt must not spend the budget their
  next code sign-in reads.
- A **failed assertion does not** count against the per-session wrong-answer count. A
  signature is not a guessable value, and a hostile page that could burn those five
  failures would hold a free way to end a person's sign-in.
- A cache failure at the start refuses the ceremony, as the budget already refuses a
  TOTP submission.

### The library and the ceremony

- The library is `github.com/go-webauthn/webauthn`. The stored blob is already its
  `webauthn.Credential`, marshaled verbatim.
- Attestation preference is `none`. User verification is `preferred`, because the
  password already proved knowledge, and `required` locks out a security key with no
  PIN. Resident key is `discouraged`, because a second-factor-only deployment needs no
  discoverable credential.
- Registration sends the exclude list of the Passkeys that person already holds.
- The WebAuthn user handle is the user id. It is a UUID, it is stable, it carries no
  personal data, and it fits the 64-byte cap. No column stores it, because it is
  derived.
- The sign counter lives inside the stored blob, and the gateway overwrites it after
  each successful assertion. A counter regression is logged and does not refuse the
  assertion, because a synced passkey reports zero.
- The write-back after a successful assertion — the counter, the backup state, and the
  last-used moment — rides the same transaction as the session completion and the audit
  row, as the TOTP path already does.

### The RP ID and the origins

- The RP ID derives per request from the registrable domain (eTLD+1) of the same
  verified host that already resolves the Tenant. `AO_WEBAUTHN_RP_ID` overrides it, for
  development hosts alone. Deriving a public suffix needs a new dependency.
- **The library refuses to start with an empty origin list, and no setting holds one
  today.** The origin list is built per Tenant from that Tenant's Domain rows, plus a
  Deployment setting that names the Portal and Console origins. **This is new
  configuration that nobody has specified. Confirm the shape before it is built.**
- A registration is refused when the derived RP ID does not cover the calling origin. A
  Passkey that no sign-in can answer must never be created.
- Each row stores its RP ID, as the table already provides.
- The Console already tells administrators that a new Tenant Domain must share the
  registrable domain of the existing ones. **Nothing enforces that today.** The domain
  write gains the check, using the same public-suffix call. It converts a silent
  per-credential failure into one refusal at the moment somebody makes the mistake.

### Where a ceremony lives

- The challenge and its ceremony state live in Redis alone, under a short TTL, written
  once. The key is the Login Session id for a sign-in, and the subject for a Portal
  registration, so no new identifier is minted.
- A cache failure refuses the ceremony. A ceremony that proceeds without a stored
  challenge is not a ceremony.
- A challenge is consumed once. The finish step deletes the key before it verifies.
- **This is a third exception to the stateless rule, beside the Guessing Budget and the
  enrolment budget.** CLAUDE.md and ADR 0002 both name three. Do not leave the reasoning
  in a code comment alone.

### API contracts

- Sign-in routes are siblings of the TOTP routes, under the existing second-factor
  group: a start and a finish for the Passkey challenge, and a start and a finish for
  Passkey enrolment. The existing TOTP verify route is untouched.
- Self-service routes are siblings of the TOTP account routes: a start and a finish for
  registration, a remove, and a rename. **The existing MFA status route is untouched.**
  A new route lists the person's Passkeys as one bounded whole list, following the
  memberships precedent.
- A removal demands the current password in the request body, exactly as the TOTP
  removal does, because the access token carries no session id and the bearer guard
  reads no store.
- A person may remove their last Second Factor. The enrolment gate re-forces enrolment
  at the next sign-in when the policy demands it, so a refusal buys nothing and strands
  people. The confirmation copy says so plainly.
- Administration routes join the existing admin user group: a list of one person's
  Passkeys, and a revoke of one. No route registers a Passkey for another person, at any
  privilege.
- The ceremony options and the ceremony answer pass through the Portal and login BFF as
  one opaque object. The front end never re-picks fields out of them. A comment at each
  BFF route says so, so the habit is broken on purpose and not by drift.
- Every answer uses the one response envelope. Every failure carries a distinct
  machine-readable slug. Distinct slugs are needed for at least: an expired or missing
  challenge, a credential the person does not own, an RP ID that does not cover the
  origin, a device already registered, the cap reached, and a budget that could not be
  read.

### Storage

- **No migration.** The table already holds what the library's `Credential` needs, and
  the blob absorbs new library fields without a schema change.
- One comment in migration 00032 is corrected in place. It calls `credential_id`
  "globally unique", and the primary key is `(tenant_id, credential_id)`, so the same
  credential id can exist under two Tenants.
- A Passkey keeps `deleted_at`, as ADR 0009 states plainly.
- A primary key cannot hold a functional key part. Registration of a credential id that
  already exists as a soft-deleted row therefore revives that row and clears
  `deleted_at`, following ADR 0001. Revival is correct here, because the same credential
  id is literally the same key pair.
- The cap is ten live Passkeys per person, enforced in the service.
- The person supplies the name. The column stays nullable, the service supplies a
  default, and names are not unique. Two devices named "Phone" are that person's
  business.
- No Go type parses the credential blob. The lists render the four mapped columns.

### Audit and notification

- Passkey actions get audit action names of their own. They never reuse the TOTP names.
  The trail is the only record that a Factor existed, and a trail that cannot say which
  credential was added is not that record.
- Three actions are recorded: a registration, a self-service removal, and an
  administrator revoke. The existing whole reset keeps its own name.
- An audit event carries the user id, the actor, and the credential id. It never carries
  the public key blob.
- The Console audit view names only two second-factor actions today, while the Portal
  names four. The new names are added to the Console, and the two existing gaps are
  closed in the same change.
- A registration sends the person a notification, through the existing templates for a
  second-factor change.

### Front ends

- **login-ui** gains a Passkey challenge step and a Passkey enrolment step. The step
  router reads the steps list and renders the first, and it offers the rest as another
  method. Both new steps are Client Components, because the browser call needs a real
  user gesture.
- **portal-ui** gains a Passkey block on the security view: a list with the name, the
  added date, and the last-used date, an add control, a rename, and a remove behind a
  password confirmation that names the device. It reuses the existing modal, table, and
  error components.
- **console-ui** gains a Passkey list on the user detail screen, with a revoke row action
  behind the existing destructive confirmation. The whole MFA reset stays, and the single
  `mfa_enabled` flag keeps its meaning. The Console never registers a Passkey.
- Every front end always renders the Passkey control. A browser with no support gets a
  disabled control and a short reason. Nothing is hidden.
- The browser call runs behind a feature check and an `AbortController`, so a person who
  switches Factor cancels a pending prompt cleanly.

### Sequence

The claim "no passkey backend exists" must stop being true in exactly one commit.

1. Land the account half and the Console half. The sign-in is untouched, so the five
   comments and the two tests stay true.
2. Land the sign-in half: the pending-step change, the gate change, the two new steps,
   the five comments, and both tests, together.

## Testing Decisions

### What makes a good test here

A good test drives the gateway over HTTP and asserts what a client observes: the steps
list, the response slug, the claims in the issued token, and the rows the Tenant can
read afterwards. It never reaches inside a service to assert a call.

The existing sign-in tests already work this way. They start a real authorization
request, run the identifier step and the password step, answer the challenge, finalize,
and read the issued token. That is the behaviour a person and a relying party depend on.

### The seam

There is one seam, and it exists already: the gateway integration harness in the OIDC
API package. Five second-factor flow tests already sit on it. The Passkey tests join
them, and the production code gains no new seam.

One test-only helper is new. It is a software authenticator that holds an in-memory key
pair, signs a challenge the way a browser device does, and returns the encoded answer.
It lives in the test package.

A `Verifier` interface with a fake in tests was weighed and refused. It is an interface
with one implementation, CLAUDE.md forbids exactly that, and it would test the fake
instead of the library that does the real work.

### What is tested

- The full sign-in with a Passkey, end to end, and the `webauthn` value in `amr`.
- A person who holds both Factors: the order of the steps list, and a finalize that
  passes on either proof. This is the gate change, and it is the highest-risk test here.
- A person who holds a Passkey and no TOTP Enrolment. This is the rewritten guard.
- The forced enrolment path, and both enrolment steps in the answer.
- A replayed challenge, an expired challenge, and a challenge answered by the credential
  of another person. Each one is refused with its own slug.
- A ceremony start that exhausts the shared budget, and a failed assertion that leaves
  the sign-in alive.
- A registration under an origin the RP ID does not cover.
- Registration of a device that already holds a live credential, and of one that holds a
  soft-deleted row. The second revives the row.
- The cap at ten, and the password proof on removal.
- The administrator revoke, the role check on it, and the audit event.
- A Tenant Domain that breaks the shared registrable domain.
- The repository, on the existing integration-tagged repository tests, for the revive
  path and for the tenant scope.

### The front ends

The web tree holds one test file today. This spec proposes no new front-end test
framework, because a test culture is a larger decision than this feature. The three
front ends are verified by hand against the user stories above. This is a known gap.

## Out of Scope

- Passwordless and usernameless sign-in. A Passkey never replaces the password here.
- Conditional mediation, sometimes called passkey autofill, on the identifier screen.
- Attestation, authenticator allow-lists, and any FIDO metadata service.
- Recovery Codes for a Passkey. They stay TOTP-only. A person who holds a Passkey alone
  recovers through the administrator reset.
- A Passkey registered by an administrator on behalf of another person.
- Any change to the `acr` claim or to the Assurance Level ladder.
- Per-Tenant policy that demands a Passkey and refuses TOTP.
- A front-end test framework for the three web applications.
- A prune job for expired ceremonies. Redis expires them.

## Further Notes

- The vocabulary of this spec is the project glossary. The word **Authenticator** means
  the TOTP application, and never the device that holds a Passkey.
- ADR 0012 records the `amr` value, the step name, and the gate change.
- ADR 0009 already stated that Passkeys keep `deleted_at`. This spec does not reopen it.
- ADR 0011 puts the MFA gate at the finalize step. This spec changes how that gate reads
  a challenge step, and ADR 0012 records why.
- Three items above are new work that nobody had specified: the origin list, the second
  stateless exception, and the Tenant Domain check. Each one is marked in place.
