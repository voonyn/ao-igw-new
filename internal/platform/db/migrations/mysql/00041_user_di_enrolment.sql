-- +goose Up
-- user_humans.di_user_uuid is the identifier the Scan Verifier keeps for one
-- person, written after an administrative create or invitation enrols them.
--
-- It lives on `user_humans` and not on `users`, because only a person enrols. A
-- machine account holds no user_humans row and is never mirrored.
--
-- NULL means "not mirrored". A failed enrolment leaves it NULL, so the operator
-- finds who is missing with one query, and a later retry reads the same column to
-- know whom to skip. There is no backfill: no person was enrolled before this.
--
-- No index. The column is projected on the person detail, and the operator query
-- above is a rare full scan of one tenant, not a list filter.
ALTER TABLE user_humans ADD COLUMN di_user_uuid VARCHAR(64) NULL DEFAULT NULL;

-- +goose Down
ALTER TABLE user_humans DROP COLUMN di_user_uuid;
