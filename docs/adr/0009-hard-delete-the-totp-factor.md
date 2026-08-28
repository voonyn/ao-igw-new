# 0009 - The TOTP factor is hard deleted

## Context

ADR 0001 lists `user_totp` among the tables that keep a primary key and soft delete.
`ClearMFA` follows that. It marks the row with `deleted_at`, and it hard deletes the
Recovery Codes beside it.

Adding TOTP showed the cost. A soft-deleted row still holds the primary key
`(tenant_id, user_id)`, and `secret_encrypted` stays readable inside it. Enrolment
cannot write a plain `INSERT`. It must upsert and reset every column of the old
secret. Migration 00043 adds `last_step`, the replay guard, so one missed column now
carries a spent time step into the next secret and opens a replay window.

CLAUDE.md places this row in the hard-delete group. A TOTP secret is a credential the
client cannot recover, like the Recovery Codes that already hard delete beside it. It
is not an entity a person expects to find again.

## Decision

The `user_totp` row is hard deleted. Migration 00043 drops `deleted_at` from the
table. The delete moved to `totp.Repository.Clear`, which calls `ForceDelete()`
on the row as it already does on the codes. The router composes the full reset
from that call and `user.Repository.ClearPasskeys`.

`user_totp` leaves the list in ADR 0001.

Enrolment writes a guarded `UPDATE` first, and an `INSERT` only when that `UPDATE`
changes no row. The `UPDATE` names `activated_at IS NULL`, so it can replace a
pending secret and never an active one. The `INSERT` then meets one of two states.
No row at all is written. An active row gives a duplicate key, which becomes
`ErrAlreadyEnrolled`.

The two-column write is possible because the hard delete removed the third state.
A person with no live row holds no Second Factor, and that is the only state which
reads as "no second factor". With soft delete, the write had to reset `deleted_at`
as well, and a missed reset carried the spent `last_step` of the old secret into
the new one.

## Alternatives

- **Keep soft delete and upsert on enrolment** — every enrolment must reset
  `secret_encrypted`, `activated_at`, `last_step` and `deleted_at`. Four columns, and
  one missed column leaves a stale secret or a replay window. The replay guard is
  then correct only while a writer remembers all four.
- **Revive the deleted row, as ADR 0001 describes** — revival is right for a
  Membership, where the same row means the same fact. A new TOTP secret is a
  different credential. Reviving the old row asserts a continuity that does not
  exist.
- **Keep the column and never write it** — a column nothing writes is a column a
  later reader trusts.

## Consequences

- An administrator reset destroys the secret. It cannot be recovered, and that is
  what the reset is for.
- The audit trail is the only record that a factor existed. `mfa.removed` and
  `user.mfa_reset` carry it.
- `user_totp` no longer matches the ADR 0001 pattern. A reader who expects soft
  delete on every user-owned table must read this ADR.
- Passkeys keep `deleted_at`. This decision covers the TOTP row only.
