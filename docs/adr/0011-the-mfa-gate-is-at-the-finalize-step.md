# 0011 - The MFA gate is at the finalize step

## Context

`LoginSession.Authenticated()` reports that a person proved at least one Factor.
`Resolve` refuses a session that proved none, so an unfinished sign-in never counts
as a signed-in one.

One Factor was enough while the gateway served one. TOTP breaks that. A person who
owes a Second Factor already proved one, so `Authenticated()` answers true and the
finalize step mints a token.

The login UI reads the step to take from `Methods` in the password answer. A hint
alone is not enforcement. The finalize step is reachable on its own, and a person who
never visits the challenge reaches it holding one Factor.

## Decision

The requirement is enforced in two places, and each does a different job.

`Methods` names the Factor still owed, and the login UI routes the person to the
challenge or to enrolment. This is the route forward.

The finalize step refuses a Login Session that owes a Factor. It answers a new
sentinel, mapped to the `insufficient_factors` slug. The login UI reads the slug and
routes back to the step the person skipped. This is the enforcement.

`Authenticated()` keeps its meaning. It answers whether a person proved a Factor, not
whether they met the policy.

A third place reads the requirement, added with the Passkey Second Factor. A sign-in
enrols a Second Factor only for a person who holds none. Each enrolment route of the
sign-in refuses a person the steps name a challenge for, and it answers the
`mfa_already_held` slug. Without it the enrolment is the way around the gate: the
gate reads the steps fresh, so a Factor an enrolment recorded in the middle of a
sign-in meets the challenge the account owes, and a person who holds the password
alone reaches a token.

The guard runs on the start and on the finish of each route. A pending TOTP row has
no expiry, and a passkey ceremony lives for its TTL, so a start refused on its own
leaves a leftover that carries the same bypass one call later.

The portal is exempt. A person adds a second kind of Factor there, under an access
token, and that is the supported way to hold both.

A QR Login is exempt. A Wallet presentation is a possession factor already, and the
poll answers three fixed states with no room to name a step still owed.

## Alternatives

- **The hint alone** — a direct visit to the finalize step signs a person in holding
  one Factor. That is not enforcement.
- **Teach `Authenticated()` the policy** — the challenge endpoints must read the very
  Login Session that has not met the requirement, so `Resolve` would refuse the
  session it must act on. A second read path is needed anyway, and the session status
  endpoint would report a person signed out while they answer the challenge.
- **Challenge a QR Login too** — the poll answers pending, authenticated, or expired.
  Naming a step still owed needs a fourth state, a field on the answer, and a branch
  in the login UI. It must also decide what becomes of the QR Login Transaction row
  when a failed challenge ends the Login Session.

## Consequences

- The login UI must handle `insufficient_factors` at the finalize step. Without that
  branch a refused person waits on a screen that never moves.
- Three places read the requirement, so one function must answer all three. Two
  copies of the rule drift, and a drifted authentication predicate is a security
  defect. `pendingSteps` is that function. The router builds it once and hands the
  same function value to the login session service and to the enrolment guard of
  both Second Factor modules.
- The enrolment guard reads the steps and never the two Factor tables. A person the
  steps name a challenge for is a person who holds a Factor, so a second pair of
  reads would be the drift this decision refuses.
- The challenge endpoints refuse a Login Session that has not proved a password. A
  session exists from the identifier step onward and already names a person, so
  without that guard anyone who knows an identifier could enrol a Factor on that
  account.
- A QR Login never carries `otp`. Its Assurance Level is `1fa`.
