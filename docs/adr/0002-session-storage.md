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
- Redis must never hold data that is absent from the database.
