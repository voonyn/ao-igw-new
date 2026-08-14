-- +goose Up
CREATE TABLE projects (
  id                        CHAR(36)  NOT NULL,
  tenant_id                 CHAR(36)  NOT NULL,
  org_id                    CHAR(36)  NOT NULL,
  name                      VARCHAR(255)  NOT NULL,
  state                     TINYINT       NOT NULL DEFAULT 1,  /* 1=active 2=inactive 3=removed */
  project_role_assertion    TINYINT(1)    NOT NULL DEFAULT 0,  /* include roles in token */
  project_role_check        TINYINT(1)    NOT NULL DEFAULT 0,  /* enforce role membership */
  has_project_check         TINYINT(1)    NOT NULL DEFAULT 0,  /* only granted users allowed */
  private_labeling_setting  TINYINT       NOT NULL DEFAULT 0,
  created_at                DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at                DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id, tenant_id),
  KEY         idx_org (org_id, tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS projects;
SET FOREIGN_KEY_CHECKS = 1;
