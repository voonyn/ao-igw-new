-- +goose Up
CREATE TABLE organization_members (
  tenant_id    CHAR(36)  NOT NULL,
  org_id       CHAR(36)  NOT NULL,
  user_id      CHAR(36)  NOT NULL,
  roles        TEXT          NOT NULL,  /* JSON: ["ORG_OWNER"] */
  created_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (tenant_id, org_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS organization_members;
SET FOREIGN_KEY_CHECKS = 1;
