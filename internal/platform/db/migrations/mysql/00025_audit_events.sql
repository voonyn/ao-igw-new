-- +goose Up
-- Append-only, tenant-scoped audit trail. Rows are written best-effort by the
-- audit recorder and are NEVER updated or deleted. metadata holds non-sensitive
-- context only -- never a password, token, or client secret. No FKs: audit must
-- survive deletion of the actor/tenant it references.
CREATE TABLE audit_events (
  id           CHAR(36)      NOT NULL,
  tenant_id    CHAR(36)      NOT NULL,
  actor_id     CHAR(36)      NULL DEFAULT NULL,   /* NULL = system / anonymous */
  action       VARCHAR(64)   NOT NULL,            /* e.g. login.succeeded, member.role_changed */
  entity_type  VARCHAR(64)   NOT NULL,
  entity_id    VARCHAR(191)  NULL DEFAULT NULL,
  result       VARCHAR(16)   NOT NULL,            /* 'success' | 'failure' */
  ip           VARCHAR(45)   NULL DEFAULT NULL,   /* INET6 max */
  user_agent   VARCHAR(512)  NULL DEFAULT NULL,
  metadata     JSON          NULL DEFAULT NULL,   /* non-secret context */
  created_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (id),
  KEY idx_audit_tenant_created (tenant_id, created_at),
  KEY idx_audit_tenant_actor   (tenant_id, actor_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
DROP TABLE IF EXISTS audit_events;
