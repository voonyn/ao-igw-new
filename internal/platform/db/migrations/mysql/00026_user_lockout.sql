-- +goose Up
-- Per-account lockout state (add-account-protection). Lives on user_humans
-- alongside the credential material (password_hash): lockout only applies to
-- human, password-authenticating users. failed_login_count is the running count
-- within the current window; last_failed_login_at anchors the window; locked_until
-- is the auto-expiring lock (NULL = not locked).
ALTER TABLE user_humans
  ADD COLUMN failed_login_count   INT         NOT NULL DEFAULT 0,
  ADD COLUMN last_failed_login_at DATETIME(3) NULL,
  ADD COLUMN locked_until         DATETIME(3) NULL;

-- +goose Down
ALTER TABLE user_humans
  DROP COLUMN failed_login_count,
  DROP COLUMN last_failed_login_at,
  DROP COLUMN locked_until;
