# 0008 - The Scan Verifier pushes its result to a callback

## Context

QR Login gives a person a code to scan with a Wallet. The person presents a
credential to the Scan Verifier, and the gateway must learn the result.

The Scan Verifier offers one way to report a result: it calls a URL that the
gateway gives it when the scan starts. The gateway does not read the result back.

The pushed body carries the identifiers of the Scan Verifier and nothing else. It
carries no Tenant, no Subject, and no Login Session id. The gateway holds a Login
Session for the scan, but that Login Session is a sealed value. SQL cannot read
inside it, so the pushed identifiers cannot find it.

## Decision

The Scan Verifier pushes the result of a scan to a callback route on the gateway.

A QR Login Transaction row exists for every scan. The row is queryable: it carries
both identifiers of the Scan Verifier as unique keys, the Tenant, the Login
Session, a digest of the nonce, the state, the resolved person, the expiry, and the
consumption time. The callback finds the row by the identifiers the push carries.

The unique keys on the two identifiers are global, not scoped to one Tenant. The
callback holds no Tenant until the row answers with one.

The browser polls the gateway for the state of the transaction. The callback writes
the result and never touches the Login Session. The poll binds the person and
records the factor, because the poll is the only party that holds a valid Login
Session token.

## Alternatives

- **Poll the Scan Verifier for the result** — the Scan Verifier serves no read for
  a result. Building the flow on a read that does not exist is not possible.
- **Keep the scan in memory and match the push against it** — an Instance must
  serve any request, and in-process state breaks that rule (ADR 0002). A push that
  arrives at a second Instance finds nothing.
- **Put the Login Session id in the callback URL** — the URL reaches a third party
  and travels back over the network. A Login Session id in a URL is a handle to a
  sign-in in flight, and a URL is logged, cached, and copied.
- **Read the Login Session by the sealed value** — the value is opaque to SQL. A
  scan cannot be found by a field that the database cannot compare.

## Consequences

- A queryable QR Login Transaction row must exist. It is the only handle that ties
  a push to a scan.
- The row is a consumed row, not an entity. It carries no soft-delete column, and a
  later prune hard deletes it.
- Replay is refused by a database constraint, not by application code, because the
  unique keys are global.
- The transaction lifetime must be longer than the window of the Scan Verifier. A
  scan that the verifier accepted must never expire here first.
- The callback is an endpoint whose success signs a person in. It must carry a
  credential, and the gateway must refuse to mount it without one.
- The poll answers three states only: pending, authenticated, and expired. Expired,
  consumed, and unknown all answer expired.
