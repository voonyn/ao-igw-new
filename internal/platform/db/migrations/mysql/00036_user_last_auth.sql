-- +goose Up
-- users.last_auth_at records the most recent SUCCESSFUL authentication, written
-- best-effort from UserService.AuthenticateByID's success branch beside the
-- existing ResetFailedLogin (complete-session-user-metadata). Until now the only
-- last_* column on the user recorded FAILURE (user_humans.last_failed_login_at),
-- so the console's Last auth column had no source at all and rendered blank.
--
-- It lives on `users`, not `user_humans`, so it is projected by the Users list's
-- existing adminUserColumns SELECT without a join and costs the list no query.
--
-- NULL means "has never authenticated" and is rendered as an explicit "Never".
-- There is deliberately NO BACKFILL: audit_events only reaches back to whenever
-- auditing was enabled, so any backfilled value would be invented for the users
-- it could not cover. Every existing user therefore reads "Never" until their
-- next login, which is honest rather than approximately wrong.
--
-- No index: the column is projected, never filtered or sorted on (the users list
-- sort allowlist is created_at / username / state).
ALTER TABLE users ADD COLUMN last_auth_at DATETIME(3) NULL DEFAULT NULL;

-- +goose Down
ALTER TABLE users DROP COLUMN last_auth_at;
