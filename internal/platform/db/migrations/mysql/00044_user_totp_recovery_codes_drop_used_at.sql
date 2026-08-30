-- +goose Up
-- used_at is dropped because nothing writes it. The comment above the table in
-- 00030 still describes the design this replaces: "used_at NULL = unused;
-- consumption flips it atomically in one guarded UPDATE". That migration is
-- applied, so it is not edited. This comment is the correction.
--
-- A Recovery Code is consumed by a guarded hard DELETE, not by an UPDATE. See
-- Repository.RedeemRecoveryCode. The row is the code: the delete matches the
-- whole primary key (tenant_id, user_id, code_hash), so InnoDB serializes two
-- challenges that submit the same code, and the first delete is the one that
-- redeems it. The second affects no row and answers ErrCodeSpent. The guard
-- never read used_at.
--
-- ADR 0009 rejects the alternative by name: "Keep the column and never write it
-- - a column nothing writes is a column a later reader trusts." A reader who
-- trusted this one would filter on `used_at IS NULL` and believe a spent code
-- is still readable. No spent code leaves a row.
-- See docs/adr/0009-hard-delete-the-totp-factor.md.
ALTER TABLE user_totp_recovery_codes DROP COLUMN used_at;

-- +goose Down
-- The column comes back unwritten, exactly as it was: DATETIME(3) NULL DEFAULT
-- NULL, after code_hash. The down migration restores the schema, never a
-- consumption history. No such history was ever recorded, because a spent code
-- was deleted rather than marked.
SET FOREIGN_KEY_CHECKS = 0;
ALTER TABLE user_totp_recovery_codes
  ADD COLUMN used_at DATETIME(3) NULL DEFAULT NULL AFTER code_hash;
SET FOREIGN_KEY_CHECKS = 1;
