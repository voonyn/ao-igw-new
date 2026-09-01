# CLAUDE.md

Identity gateway: a Go Fiber API with three Next.js front ends.

**Use the simple method. Do not over-engineer.** No interface with one
implementation. No abstraction for a case that does not exist yet. The shortest
change that works and reads clearly is the right one.

## Detailed rules

Load `andrej-karpathy-skills:karpathy-guidelines` at the start of every session,
before any other work.

| Skill | Use it when |
|---|---|
| `ao-go-api` | creating or changing a Go file under `internal/` or `cmd/` |
| `ao-db-migration` | creating or changing a file under `internal/platform/db/migrations` |
| `ao-nextjs-ui` | creating or changing a TypeScript or TSX file under `web/` |

These skills are mandatory, not optional. If a task touches one of the paths
above, load the matching `ao-*` skill with the Skill tool first. Read the skill
before you write the file, not after. If a task touches more than one path, load
every matching skill.

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

**Soft delete for entities.** An entity is a row that a user creates, edits, and
expects to find again: a tenant, a user, an organization, an application. Delete it
with `deleted_at`. Every read filters on `deleted_at IS NULL`.

Do not use `deleted_at` on other rows. Pick by what the row is:

- A row that expires or is consumed once, such as a session, a token, or a code:
  hard delete it. The client cannot recover it, and a pruning job removes the rest.
- A row that stays readable after it stops working, such as a grant or a key: mark
  it with its own column, for example `revoked_at` or `disabled_at`.
- A row that records a fact, such as an audit event: never delete it.

The `ao-db-migration` skill lists the tables in each group.

**Never log a credential.** No password, token, secret, private key, or
authorization code reaches a log line, at any level and in any environment. Log the
user id instead of the identity.

A session id is not a credential here. The opaque token credentials the session, and
the id is disclosed to the client in the `/identifier` answer. Log the session id: it
is the only handle that ties the steps of one sign-in together.

**Log enough to troubleshoot.** Middleware logs each request at `info`. Each layer
logs entry and exit at `debug`. An error is logged once, at `error`, where it stops
bubbling up.

**Validate on the backend.** Go validates every request body. Frontend validation is
a convenience for the user, never the enforcement point.

**One response envelope.** Every API answer is
`{code, status, message, data, meta?}` or `{code, status, message, error, errors?}`.

`error` is a machine-readable slug, and it is on every error answer. A client
branches on the slug, never on `message`, so a reworded message never changes
behaviour. `errors` is present only when the answer names the fields that failed.

## Stateless design

No in-process state. Any instance must serve any request.

- The session cookie holds an opaque session id, never session data.
- The **database is the source of truth**. Redis is a cache.
- Write: write the database, then set Redis with a TTL.
- Read: read Redis. On a miss, read the database and refill Redis.
- Logout: delete from the database and from Redis.

Six exceptions. Each lives only in Redis, no table holds any of them, and a cache
failure refuses the request instead of letting it through.

- The Guessing Budget in `totp.Service.spendGuess`. A failure that let the guess
  through would leave second-factor guessing unbounded. The comment on that function
  carries the reasoning and the upgrade path.
- The enrolment budget in `passkey.Service.spendEnrolment`. It caps registration
  starts on a key of its own, so a cancelled browser prompt never spends the
  Guessing Budget a code sign-in reads.
- The challenge budget in `passkey.Service.spendChallenge`. It caps sign-in challenge
  starts on a key of its own, for the same reason: a start proves nothing, and the
  person who cancels it is mid sign-in.
- The connection test budget in `identityprovider.Service.spendTest`. The test is an
  outbound call into a customer network that any Console administrator of the Tenant
  drives, against a host the Tenant names. A failure that let it through would leave
  that call unmetered for as long as Redis is down.
- The bind budget in `identityprovider.Service.spendBind`. A bind is an outbound call
  into a customer network that any caller can drive, and a failure that let it through
  would turn the password step into a lever against that directory. The password step
  itself carries no budget, so there is nothing weaker to fall back to. See
  `docs/specs/0002-directory-sign-in.md`.
- The passkey ceremony in `passkey.Service.store` and `passkey.Service.consume`. A
  ceremony that proceeds without a stored challenge proves nothing, and a challenge
  a table held would outlive the one prompt it belongs to.

See `docs/adr/0002-session-storage.md`.

## Agent skills

### Issue tracker

Local markdown. Tickets live under `.scratch/<feature-slug>/issues/`, and specs live
under `docs/specs/`. See `docs/agents/issue-tracker.md`.

### Triage labels

The five default roles, each label string equal to its name. A label is the `Status:`
line of a ticket file. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` and one `docs/adr/` at the root. See
`docs/agents/domain.md`.
