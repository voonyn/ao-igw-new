-- +goose Up
-- Remembered user consent per (tenant, user, client). One row holds the
-- cumulative space-delimited set of scopes the user has approved for a client;
-- a later request whose scopes are a subset skips the consent screen, a superset
-- re-prompts and unions into `scopes` (add-oidc-consent, all-or-nothing v1).
-- Timestamps are recorded for a later revocation surface; no expiry in v1.
CREATE TABLE oidc_user_consents (
  id         CHAR(36)      NOT NULL,
  tenant_id  CHAR(36)      NOT NULL,
  user_id    CHAR(36)      NOT NULL,
  client_id  VARCHAR(191)  NOT NULL,               /* application_oidc_configs.client_id */
  scopes     TEXT          NOT NULL,               /* space-delimited consented set */
  created_at DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id),
  UNIQUE KEY  uq_user_consent (tenant_id, user_id, client_id, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
DROP TABLE IF EXISTS oidc_user_consents;
