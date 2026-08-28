-- +goose Up
-- last_step is the replay guard of the TOTP factor: the newest time step this
-- account has already spent. A verification claims a step with one guarded
-- UPDATE that refuses any step at or below it, so a code an observer read off
-- the screen cannot be replayed, not even one step later.
--
-- The guard reads `last_step < ?`, so the column is NOT NULL. NULL would refuse
-- every step. 0 means no step is spent yet, and no time step is ever 0.
ALTER TABLE user_totp
  ADD COLUMN last_step BIGINT NOT NULL DEFAULT 0 AFTER activated_at;

-- The TOTP row is hard deleted. It holds a credential the client cannot
-- recover, not an entity a person expects to find again. A soft-deleted row
-- keeps a readable secret and a spent step under the same primary key
-- (tenant_id, user_id), so the next enrolment must reset every column of the
-- old secret or it inherits a replay window. See
-- docs/adr/0009-hard-delete-the-totp-factor.md, which amends ADR 0001.
--
-- The recovery codes beside it already hard delete. Passkeys are not touched:
-- user_webauthn_credentials keeps its deleted_at.
ALTER TABLE user_totp DROP COLUMN deleted_at;

-- +goose Down
-- The reverse, in reverse order. A row deleted while the column was gone stays
-- gone, which is correct: the down migration restores the schema, never the
-- credentials.
SET FOREIGN_KEY_CHECKS = 0;
ALTER TABLE user_totp ADD COLUMN deleted_at DATETIME(6) NULL;
ALTER TABLE user_totp DROP COLUMN last_step;
SET FOREIGN_KEY_CHECKS = 1;
