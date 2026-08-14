# 0001 - Unique keys on soft-deleted tables

## Context

Every table uses soft delete. A deleted row keeps its data and sets `deleted_at`.

A plain unique key such as `uq_username (username, tenant_id)` then burns the
identifier forever. A tenant cannot recreate a user they deleted.

Adding `deleted_at` to the unique key does not work either. MySQL treats `NULL` as
distinct in a unique index, so two live rows with `deleted_at IS NULL` both pass the
constraint. Uniqueness breaks silently for live rows, which is the opposite of the
intent.

## Decision

`deleted_at` is `DATETIME(6) NULL`. bun uses `bun:",soft_delete,nullzero"`, which
emits `WHERE deleted_at IS NULL`.

Unique keys use a functional key part that maps `NULL` to a fixed epoch value:

```sql
UNIQUE KEY uq_username (username, tenant_id,
  (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))))
```

The `CAST` makes the expression return `DATETIME(6)` instead of a string, which keeps
the key part type stable. This requires MySQL 8.0.13 or newer.

A primary key cannot hold a functional key part. Tables whose identity is the primary
key — `tenant_members`, `organization_members`, `tenant_domains`,
`organization_domains`, `user_totp` — keep that primary key. Re-adding the same row
revives the deleted one with `ON DUPLICATE KEY UPDATE deleted_at = NULL`. No surrogate
id column is added.

Tables that expire or are append-only keep hard delete. See CLAUDE.md for the list.

## Alternatives

- **Generated marker column** — the same result, but it adds a visible column to
  every table. Rejected on readability.
- **`deleted_at NOT NULL` with an epoch default for live rows** — breaks bun's
  `soft_delete` tag, which emits `IS NULL`. It needs a custom query hook on every
  model.
- **Uniqueness enforced in the service layer** — races under concurrent writes. The
  database must own the constraint.
- **Burn the identifier** — accepted cost is too high. Support tickets follow every
  deletion.

## Consequences

- MySQL 8.0.13 is a hard floor. MySQL 5.7 cannot run these migrations.
- Every new soft-deleted table repeats this pattern. A unique key without the
  functional key part is a bug.
- The functional key part creates a hidden column inside MySQL. It never appears in
  `SELECT *`, `DESCRIBE`, or the bun model.
