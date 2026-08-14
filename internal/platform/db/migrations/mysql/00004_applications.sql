-- +goose Up
CREATE TABLE applications (
  id          CHAR(36)  NOT NULL,
  tenant_id   CHAR(36)  NOT NULL,
  project_id  CHAR(36)  NOT NULL,
  name        VARCHAR(255)  NOT NULL,
  app_type    TINYINT       NOT NULL,            /* 1=oidc 2=saml 3=api */
  state       TINYINT       NOT NULL DEFAULT 1,  /* 1=active 2=inactive 3=removed */
  created_at  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id, tenant_id),
  KEY         idx_project (project_id, tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS applications;
SET FOREIGN_KEY_CHECKS = 1;
