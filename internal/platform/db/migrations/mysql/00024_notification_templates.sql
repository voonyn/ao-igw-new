-- +goose Up
-- Per-tenant message-template overrides. A row here overrides the embedded
-- default for one template key (e.g. 'password_reset') for one tenant; absent a
-- row, the embedded default renders. The DB stores overrides only — there is no
-- per-tenant seeding. subject/body_text/body_html are Go template sources.
CREATE TABLE notification_templates (
  id            CHAR(36)      NOT NULL,
  tenant_id     CHAR(36)      NOT NULL,
  template_key  VARCHAR(64)   NOT NULL,               /* e.g. password_reset */
  subject       VARCHAR(512)  NOT NULL,
  body_text     MEDIUMTEXT    NOT NULL,
  body_html     MEDIUMTEXT    NOT NULL,
  created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id),
  UNIQUE KEY  uq_tmpl (tenant_id, template_key, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS notification_templates;
SET FOREIGN_KEY_CHECKS = 1;
