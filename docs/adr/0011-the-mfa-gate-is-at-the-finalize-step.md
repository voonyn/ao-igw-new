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
- Two places read the requirement, so one function must answer both. Two copies of
  the rule drift, and a drifted authentication predicate is a security defect.
- The challenge endpoints refuse a Login Session that has not proved a password. A
  session exists from the identifier step onward and already names a person, so
  without that guard anyone who knows an identifier could enrol a Factor on that
  account.
- A QR Login never carries `otp`. Its Assurance Level is `1fa`.
