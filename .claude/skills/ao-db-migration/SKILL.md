---
name: ao-db-migration
description: Rules for goose MySQL migrations - soft delete columns, unique keys that survive soft delete, which tables keep hard delete, and index conventions. Use when creating or changing a file under internal/platform/db/migrations.
---

# Migration rules

Target: MySQL 8.0.13 or newer. Functional key parts are required, so an older
version cannot run these migrations.

Every file carries `-- +goose Up` and `-- +goose Down`. The down section drops what
the up section created, in reverse order, wrapped in
`SET FOREIGN_KEY_CHECKS = 0/1`.

## Soft delete

An entity table carries:

```sql
deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
```

`DATETIME(6)`, always nullable. `NULL` means the row is live.

These tables keep **hard delete**, because a row there expires or is a fact that
never changes:

| Table | Reason |
|---|---|
| `login_sessions`, `login_session_links` | expire, pruned by `expires_at` |
| `oidc_sessions`, `oidc_grants`, `oidc_superseded_refresh_tokens` | expire |
| `account_tokens` | expire, consumed once |
| `user_totp` | holds a credential, destroyed by a reset (ADR 0009) |
| `user_totp_recovery_codes` | consumed once |
| `audit_events` | append-only |
| `system_bootstrap` | single-row marker |
| `user_humans` | 1:1 extension, follows `users` |
| `identity_provider_user_links` | nobody re-reads an unlinked account, `idp.unlinked` is the record |

## Unique keys on a soft-deleted table

MySQL treats `NULL` as distinct in a unique index. A nullable `deleted_at` placed
directly in a unique key lets two live rows share the same value, which breaks the
constraint silently.

Map `NULL` to a fixed epoch with a functional key part:

```sql
UNIQUE KEY uq_username (username, tenant_id,
  (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))))
```

The `CAST` keeps the expression typed as `DATETIME(6)` instead of a string.

Without this, a soft-deleted row holds its username forever and the tenant can never
recreate it.

## When the identity is the primary key

A primary key cannot hold a functional key part. Tables such as `tenant_members`,
`organization_members`, `tenant_domains`, and `organization_domains` keep their
natural primary key. Adding the same row again revives the deleted one:

```sql
INSERT INTO tenant_members (tenant_id, user_id, role)
VALUES (?, ?, ?)
ON DUPLICATE KEY UPDATE deleted_at = NULL, role = VALUES(role);
```

Keep the primary key as it is. A surrogate id column is not the answer here.

Background and rejected alternatives: `docs/adr/0001-soft-delete-unique-keys.md`.

## Indexes

Add an index when a query needs it, and name the query in a comment above it. A list
query index follows the shape `(tenant_id, <filter or sort column>, id)`, which
matches the keyset order the list endpoints use.
