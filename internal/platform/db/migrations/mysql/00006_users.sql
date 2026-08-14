-- +goose Up
CREATE TABLE users (
  id           CHAR(36)  NOT NULL,
  tenant_id    CHAR(36)  NOT NULL,
  org_id       CHAR(36)      NOT NULL,            /* users always belong to an org */
  username     VARCHAR(255)  NULL,                /* login name (unique per tenant) */
  user_type    TINYINT       NOT NULL DEFAULT 1,  /* 1=human 2=machine */
  state        TINYINT       NOT NULL DEFAULT 1,  /* 1=active 2=inactive 3=deleted 4=locked 5=initial */
  created_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY  (id, tenant_id),
  UNIQUE KEY   uq_username (username, tenant_id, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6))))),
  KEY          idx_org (org_id, tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE user_humans (
  user_id                  CHAR(36)  NOT NULL,
  tenant_id                CHAR(36)  NOT NULL,
  first_name               VARCHAR(255)  NULL,
  last_name                VARCHAR(255)  NULL,
  display_name             VARCHAR(255)  NULL,
  nick_name                VARCHAR(255)  NULL,
  preferred_language       VARCHAR(20)   NULL,                   /* BCP-47 e.g. "en", "th" */
  gender                   TINYINT       NULL,                   /* 0=unspecified 1=female 2=male 3=diverse */
  email                    VARCHAR(500)  NULL,
  is_email_verified        TINYINT(1)    NOT NULL DEFAULT 0,
  phone                    VARCHAR(50)   NULL,                   /* E.164 format */
  is_phone_verified        TINYINT(1)    NOT NULL DEFAULT 0,
  password_hash            TEXT          NULL,                   /* bcrypt hash */
  password_change_required TINYINT(1)    NOT NULL DEFAULT 0,
  password_changed_at      DATETIME(3)   NULL,
  created_at               DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at               DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  PRIMARY KEY (user_id, tenant_id),
  KEY         idx_email (email, tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS user_humans;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS = 1;
