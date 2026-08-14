-- +goose Up
-- Per-tenant outbound-mail delivery settings. One row per tenant (tenant_id is
-- the PK), overriding the instance-level AO_NOTIFICATION_* config. Absent a row,
-- the instance default applies; absent any usable transport, the log transport
-- does. smtp_password is stored encrypted (AES-256-GCM via cryptokey.Cipher) and
-- is never returned on admin reads — the console sees only a passwordSet flag.
CREATE TABLE notification_settings (
  tenant_id        CHAR(36)      NOT NULL,
  transport        VARCHAR(16)   NOT NULL DEFAULT 'log',   /* 'smtp' | 'log' */
  smtp_host        VARCHAR(255)  NULL,
  smtp_port        INT           NOT NULL DEFAULT 587,
  smtp_username    VARCHAR(255)  NULL,
  smtp_password    VARBINARY(512) NULL,                    /* encrypted at rest */
  from_address     VARCHAR(320)  NULL,                     /* RFC 5321 max localpart+domain */
  from_name        VARCHAR(255)  NULL,
  tls_mode         VARCHAR(16)   NOT NULL DEFAULT 'starttls', /* 'starttls' | 'tls' | 'none' */
  send_timeout_ms  INT           NOT NULL DEFAULT 10000,
  created_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at       DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS notification_settings;
SET FOREIGN_KEY_CHECKS = 1;
