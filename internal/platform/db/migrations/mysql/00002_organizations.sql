-- +goose Up
CREATE TABLE organizations (
  id              CHAR(36)  NOT NULL,
  tenant_id       CHAR(36)  NOT NULL,
  name            VARCHAR(500)  NOT NULL,
  state           TINYINT       NOT NULL DEFAULT 1,  /* 1=active 2=inactive 3=removed */
  created_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY     (id, tenant_id),
  KEY             idx_tenant (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE organization_domains (
  domain           VARCHAR(255)  NOT NULL,
  tenant_id        CHAR(36)      NOT NULL,
  org_id           CHAR(36)      NOT NULL,
  is_verified      TINYINT(1)    NOT NULL DEFAULT 0,
  is_primary       TINYINT(1)    NOT NULL DEFAULT 0,
  validation_type  TINYINT       NOT NULL DEFAULT 0,  /* 0=none 1=http 2=dns 3=smtp */
  created_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY  (domain, tenant_id),
  KEY          idx_org (org_id, tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS organization_domains;
DROP TABLE IF EXISTS organizations;
SET FOREIGN_KEY_CHECKS = 1;
