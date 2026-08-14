# CLAUDE.md

Identity gateway: a Go Fiber API with three Next.js front ends.

**Use the simple method. Do not over-engineer.** No interface with one
implementation. No abstraction for a case that does not exist yet. The shortest
change that works and reads clearly is the right one.

## Detailed rules

| Skill | Use it when |
|---|---|
| `ao-go-api` | creating or changing a Go file under `internal/` or `cmd/` |
| `ao-db-migration` | creating or changing a file under `internal/platform/db/migrations` |
| `ao-nextjs-ui` | creating or changing a TypeScript or TSX file under `web/` |

Read the matching skill before you write the file, not after.

## Tech stack

**Backend** — Go 1.26, Fiber v3.4, bun 1.2 on MySQL 8, goose migrations, rueidis
(Redis), zap and timberjack (logs), viper and cobra, sonic (JSON),
go-playground/validator.

**Frontend** — Next.js 16, React 19, App Router, Tailwind v4, radix-ui, jose.

**Database** — MySQL 8.0.13 or newer. Migrations use functional key parts, so an
older version cannot run them.

## Folder structure

```
cmd/                            CLI entry points
main.go
internal/
  api/http/
    router.go                   route mounting, cross-domain only
    middlewares/                shared middleware
    response/                   response envelope and error mapper
  <domain>/                     one package per domain: tenant, user, org, oidc
  platform/                     cache, config, crypto, db, logger
  utils/
internal/platform/db/migrations/mysql/
web/login-ui/                   port 3000
web/portal-ui/                  port 3001
web/console-ui/                 port 3002
docs/adr/                       architecture decision records
```

## Rules that hold everywhere

**Soft delete.** An entity row is never hard deleted. Rows that expire or that record
a fact are the exception, and the `ao-db-migration` skill lists them.

**Never log a credential.** No password, token, secret, private key, session id, or
authorization code reaches a log line, at any level and in any environment. Log the
user id instead of the identity.

**Log enough to troubleshoot.** Middleware logs each request at `info`. Each layer
logs entry and exit at `debug`. An error is logged once, at `error`, where it stops
bubbling up.

**Validate on the backend.** Go validates every request body. Frontend validation is
a convenience for the user, never the enforcement point.

**One response envelope.** Every API answer is
`{code, status, message, data, meta?}` or `{code, status, message, errors?}`.

## Stateless design

No in-process state. Any instance must serve any request.

- The session cookie holds an opaque session id, never session data.
- The **database is the source of truth**. Redis is a cache.
- Write: write the database, then set Redis with a TTL.
- Read: read Redis. On a miss, read the database and refill Redis.
- Logout: delete from the database and from Redis.

See `docs/adr/0002-session-storage.md`.
