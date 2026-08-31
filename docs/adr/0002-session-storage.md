# 0002 - Sessions in Redis with a database fallback

## Context

The gateway runs as more than one instance behind a load balancer. Any instance must
serve any request, so no session data can live in process memory.

Two stores are in use for one concern, which looks redundant to a new reader.

## Decision

The session cookie holds an opaque session id. It never holds session data.

The **database is the source of truth**. Redis is a cache in front of it.

- **Write** — write the session to the database, then set Redis with a TTL.
- **Read** — read Redis. On a miss, read the database and refill Redis.
- **Logout** — delete from the database and from Redis.

## The exceptions

Three values live in Redis and in no table. Each one is a cap or a challenge that
belongs to one moment, and a database row would outlive that moment.

- **The second-factor Guessing Budget** (`totp.Service.spendGuess`). It counts the
  guesses of one person across every sign-in they open. Every request that answers
  a challenge spends it: a TOTP submission, and a passkey sign-in challenge.
- **The passkey enrolment budget** (`passkey.Service.spendEnrolment`). It counts the
  registration starts of one person. It is a separate counter on a separate key,
  because a start answers no challenge and proves nothing. A person who cancels a
  browser prompt must not spend the budget their next code sign-in reads.
- **The passkey ceremony** (`passkey.Service.store`, `passkey.Service.consume`). It
  holds the challenge of one registration or one assertion, under a short TTL, and
  the finish step deletes it before it verifies the answer.

Each one refuses the request when the cache cannot answer. This is the opposite of
the rule above, and it is deliberate: a budget that let the request through would
leave the path unbounded, and a ceremony that ran without a stored challenge would
prove nothing.

## Alternatives

- **Redis as the primary store, database as an async backup** — a Redis restart logs
  out every user, and the sync worker becomes a component to own and debug.
- **A signed JWT in the cookie, with a revocation list in Redis** — revocation is a
  core requirement for an identity gateway. A stateless token makes immediate
  revocation the exception instead of the default.

## Consequences

- A Redis flush costs latency, not correctness. Traffic falls through to the database
  and Redis refills.
- Every session write pays two round trips. This is accepted.
- Redis must never hold data that is absent from the database, except the three values
  named above.
