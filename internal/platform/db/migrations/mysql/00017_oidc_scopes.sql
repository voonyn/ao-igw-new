-- +goose Up
-- Per-tenant OIDC scope registry. One row per scope string a tenant advertises.
-- Builtin scopes (openid/profile/email/offline_access) are seeded (00020), are
-- name-locked and non-deletable. Disabled scopes are neither advertised nor
-- granted. id is a single-column PK so oidc_claim_mappers.scope_id can FK it.
CREATE TABLE oidc_scopes (
  id            CHAR(36)      NOT NULL,
  tenant_id     CHAR(36)      NOT NULL,
  name          VARCHAR(191)  NOT NULL,               /* the OAuth scope string */
  display_name  VARCHAR(255)  NULL,                   /* console label */
  description   TEXT          NULL,                   /* shown on the consent screen (Change 3) */
  is_enabled    TINYINT(1)    NOT NULL DEFAULT 1,     /* disabled = not advertised/granted */
  is_default    TINYINT(1)    NOT NULL DEFAULT 0,     /* provisioning: assigned to new clients (NOT grant-time) */
  is_builtin    TINYINT(1)    NOT NULL DEFAULT 0,     /* name-locked, non-deletable */
  created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id),
  UNIQUE KEY  uq_scope (tenant_id, name, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS oidc_scopes;
SET FOREIGN_KEY_CHECKS = 1;
