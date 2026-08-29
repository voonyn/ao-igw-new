---
name: ao-go-api
description: Rules for the Go Fiber backend - domain package layout, handler to service to repository flow, DTO validation, sentinel errors, layered logging, the response envelope, and pagination. Use when creating or changing any Go file under internal/ or cmd/.
---

# Go API rules

Load `golang-code-style`, `golang-naming`, and `golang-error-handling` before you
write. By task: `golang-database` for a repository, `golang-project-layout` for a new
package, `golang-security` for auth code, `golang-testing` for tests.

## Package layout

One package per domain under `internal/<domain>/`, files by role:

```
internal/tenant/
  handler.go      bind, call the service, return a response
  dto.go          request struct, validate tags, response struct
  service.go      business logic, never touches fiber.Ctx
  repo.go         bun queries only, no business rules
  model.go        bun model
```

A domain that serves more than one concern splits by concern and keeps the role
as the suffix: `admin_handler.go`, `admin_service.go`, `admin_repo.go`,
`client_repo.go`. Every bun model of the domain still lives in `model.go`, however
many repository files read it.

No subpackages inside a domain. A domain's own layers cannot form an import cycle
that way. Bun models live in the domain that owns them, and other domains import
them.

`internal/api/http/router.go`, `middlewares/`, and `response/` stay central. They are
cross-domain.

Code still under `internal/api/http/{dto,handler}` is grandfathered. Move it into its
domain package when you next touch it, one domain at a time.

## Request flow

```
middleware -> handler -> dto -> service -> repository -> bun
```

A handler is three lines: bind, call, respond.

## Validation

`go-playground/validator` is registered as Fiber's `StructValidator` in
`internal/platform/config/validator.go`. `c.Bind().Body(&req)` validates the
`validate:` tags automatically.

Write the rules as tags on the DTO. On a bind error, return
`response.Validation(c, err)`.

Every request body is validated here, in the backend. Frontend validation is a
convenience for the user, never the enforcement point.

## Errors

Each domain declares its own sentinel errors:

```go
var (
    ErrUserNotFound      = errors.New("user not found")
    ErrDuplicateUsername = errors.New("duplicate username")
)
```

Wrap with context as the error travels up: `fmt.Errorf("find user %s: %w", id, err)`.

One mapper in `internal/api/http/response` turns a sentinel into a status code with
`errors.Is`. Handlers pass the error to the mapper and map nothing themselves.

## Logging

Use the `logger.Logger` interface. Field helpers such as `logger.String` live there,
so `zap` stays out of the import list.

| Where | Level | What |
|---|---|---|
| Middleware | `info` | one line per request and response |
| Every layer | `debug` | entry and exit, with the request id |
| A service that completed a write | `info` | one line naming what changed |
| Where the error stops bubbling | `error` | the error, logged exactly once |

Production runs at `info`, so the per-layer debug lines cost nothing until an
engineer turns them on.

The `info` line on a completed write is the exception, and it is deliberate. It is
the only record of a change that production keeps in the log, and an operator reads
it beside the request line the middleware wrote. The audit trail answers the same
question from the database, and the two are read in different places.

Every repository method writes both debug lines, the reads included. A repository
that logs nothing leaves the one layer that touched the database silent.

Log the user id, the tenant id, the session id, and the request id. Keep every
credential out of the log line: password, token, secret, private key, and
authorization code, at every level and in every environment. Mask an email as
`a***@b.com`.

A session id is not a credential. The opaque token credentials the session, and the
id is disclosed to the client.

## Response envelope

Always answer through a helper in `internal/api/http/response`.

| Helper | Status | Body |
|---|---|---|
| `OK` / `Created` / `NoContent` | 200 / 201 / 200 | `{code, status, message, data}` |
| `List(c, rows, total)` | 200 | adds `meta: {page, limit, total, totalPages}` |
| `Error(c, status, message, details)` | any | `{code, status, message, error, errors?}` |
| `ErrorSlug(c, status, slug, message)` | any | `{code, status, message, error}` |
| `Validation(c, err)` | 422 | `errors` as `{field: message}` |

`error` is a machine-readable slug, and every error answer carries one. A client
branches on the slug, never on `message`, so a reworded message never changes
behaviour. `Error` derives the slug from the status. `ErrorSlug` names it, which is
what a handler uses for a condition of its own, such as `name_conflict`.

`errors` is present only when the answer names the fields that failed.

## Pagination

Mount `middlewares.Paginate("created", "name", "state")` on a list route that pages.
It carries the defaults: page 1, limit 20, maximum limit 100. A larger limit is
clamped. Name the sort keys the console sends, such as `created` and `name`, not the
column names behind them.

A bounded list answers whole and mounts no pager. Scopes, mappers, keys, memberships
and notification templates are bounded, so those routes carry no `Paginate` and no
`meta`.

In the handler, read the page state and let the helper compute the rest:

```go
info, _ := paginate.FromContext(c)
rows, total, err := svc.List(ctx, info.Limit, info.Start())
if err != nil {
    return err
}
return response.List(c, rows, total)
```

Sorting is limited to the columns named in `middlewares.Paginate(...)`. Build the
`ORDER BY` clause from that allow-list only.

## Models and soft delete

```go
type User struct {
    bun.BaseModel `bun:"table:users"`

    ID        string    `bun:"id,pk"`
    TenantID  string    `bun:"tenant_id,pk"`
    DeletedAt time.Time `bun:",soft_delete,nullzero"`
}
```

bun then adds `WHERE deleted_at IS NULL` to every query, and `Delete()` becomes an
`UPDATE`. To read deleted rows for an audit view, opt in explicitly with
`WhereAllWithDeleted()`.

For the schema side of this — which tables carry `deleted_at` and how unique keys
work — use the `ao-db-migration` skill.
