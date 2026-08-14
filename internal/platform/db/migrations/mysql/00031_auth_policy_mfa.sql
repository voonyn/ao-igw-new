-- +goose Up
-- Add the nullable Require-MFA knob to the two-level auth policy (add-totp-mfa). It
-- follows the exact pattern of every other auth_policy_settings column: NULL means
-- "inherit the level below" (org override → tenant default → code default = false);
-- a stored value (including 0) is an explicit setting that stops the COALESCE. Being
-- part of the tenant-scoped auth_policy_settings row, it needs no // tenantscope:allow.
ALTER TABLE auth_policy_settings
  ADD COLUMN mfa_required TINYINT(1) NULL AFTER recovery_verify_ttl_ms;

-- +goose Down
ALTER TABLE auth_policy_settings
  DROP COLUMN mfa_required;
