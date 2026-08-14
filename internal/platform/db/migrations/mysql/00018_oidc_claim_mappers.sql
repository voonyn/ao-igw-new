-- +goose Up
-- Keycloak-style claim mappers: each row releases exactly one claim from one
-- scope. Share a claim across scopes by duplicating the row (no M:N join).
-- source_type selects where the value comes from; source_key is NEVER
-- interpolated into SQL (std attrs resolve through a Go whitelist, bag keys read
-- a parsed JSON column). Delivery flags default to UserInfo only.
CREATE TABLE oidc_claim_mappers (
  id               CHAR(36)      NOT NULL,
  tenant_id        CHAR(36)      NOT NULL,
  scope_id         CHAR(36)      NOT NULL,
  claim_name       VARCHAR(191)  NOT NULL,            /* emitted key */
  source_type      TINYINT       NOT NULL,           /* 1=std attr 2=user bag 3=membership 4=static */
  source_key       VARCHAR(191)  NULL,               /* std: attr token; bag: JSON key; membership: selector; NULL for static */
  source_value     JSON          NULL,               /* static value (source_type=4) */
  in_id_token      TINYINT(1)    NOT NULL DEFAULT 0,
  in_userinfo      TINYINT(1)    NOT NULL DEFAULT 1,
  in_access_token  TINYINT(1)    NOT NULL DEFAULT 0,  /* opt-in; PII/DoS risk */
  created_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id),
  UNIQUE KEY  uq_mapper (tenant_id, scope_id, claim_name, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6))))),
  KEY         idx_mapper_scope (scope_id),
  CONSTRAINT fk_mapper_scope FOREIGN KEY (scope_id)
    REFERENCES oidc_scopes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS oidc_claim_mappers;
SET FOREIGN_KEY_CHECKS = 1;
