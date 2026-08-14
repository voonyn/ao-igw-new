-- +goose Up
-- Two-level (tenant default + per-organization override) auth policy, moved out
-- of the AO_AUTH_* process config into the database as the sole source of truth
-- (move-auth-settings-to-db). Keyed (tenant_id, org_id): the reserved sentinel
-- org_id = '' is the tenant-wide DEFAULT row; a real org id is that org's
-- OVERRIDE. Every policy column is NULLABLE — NULL in a row means "inherit the
-- level below" (org → tenant default → code default), so an org can override one
-- knob and inherit the rest. A stored value (including 0/false) is an explicit
-- setting and stops the COALESCE.
--
-- Durations are stored as *_ms integers (the notification_settings send_timeout_ms
-- precedent); the repository maps them to/from time.Duration. pw_deny_list is a
-- JSON array of strings in a TEXT column. Because even the default row carries
-- tenant_id, every query is tenant-scoped and no // tenantscope:allow is needed.
CREATE TABLE auth_policy_settings (
  tenant_id               CHAR(36)   NOT NULL,
  org_id                  CHAR(36)   NOT NULL DEFAULT '',   /* '' = tenant-wide default; real UUID = org override */

  lockout_threshold       INT        NULL,                  /* <= 0 disables lockout */
  lockout_window_ms       INT        NULL,
  lockout_cooldown_ms     INT        NULL,

  pw_min_length           INT        NULL,
  pw_min_classes          INT        NULL,
  pw_deny_list            TEXT       NULL,                  /* JSON array of strings */
  pw_check_breach         TINYINT(1) NULL,

  recovery_reset_ttl_ms   INT        NULL,
  recovery_verify_ttl_ms  INT        NULL,

  created_at              DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at              DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (tenant_id, org_id)   /* one default row per tenant; at most one override per org */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS auth_policy_settings;
SET FOREIGN_KEY_CHECKS = 1;
