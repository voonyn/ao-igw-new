-- +goose Up
-- qr_login_transactions holds one QR Login in flight: the code on screen, the
-- nonce it binds, and the result the Scan Verifier pushes back.
--
-- The table exists because the Scan Verifier pushes its result to a callback. The
-- push carries the identifiers of the Scan Verifier and nothing else. The Login
-- Session of the scan is a sealed blob, so SQL cannot find it by anything the
-- push carries. See docs/adr/0008-scan-verifier-push-callback.md.
--
-- The two identifiers of the Scan Verifier are VARCHAR(64) and not the CHAR(36)
-- of this deployment. The Scan Verifier mints them, and they are 32 hexadecimal
-- characters today.
--
-- Their unique keys are global, and not scoped to one tenant. The callback holds
-- no tenant until this lookup answers with one, so global uniqueness makes a
-- replay a database constraint instead of application code.
--
-- The row is consumed, not an entity. It carries no deleted_at, and a later prune
-- hard deletes it.
CREATE TABLE qr_login_transactions (
  id                    CHAR(36)    NOT NULL,
  tenant_id             CHAR(36)    NOT NULL,
  login_session_id      CHAR(36)    NOT NULL,
  verifier_session_id   VARCHAR(64) NOT NULL,  /* the Scan Verifier mints it; the wallet echoes it */
  verifier_presentation_id VARCHAR(64) NOT NULL, /* the Scan Verifier mints it; it stays server-side */
  nonce_hash            CHAR(64)    NOT NULL,  /* SHA-256 hex; the plaintext only ever goes to the verifier */
  state                 TINYINT     NOT NULL DEFAULT 1, /* 1=pending 2=verified 3=failed */
  user_id               CHAR(36)    NULL,      /* the person the push resolved to */
  expires_at            DATETIME(3) NOT NULL,
  consumed_at           DATETIME(3) NULL,
  created_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (tenant_id, id),
  UNIQUE KEY uq_qr_verifier_session      (verifier_session_id),
  UNIQUE KEY uq_qr_verifier_presentation (verifier_presentation_id),
  /* The poll reads the transaction of one login session. */
  KEY idx_qr_login_session (tenant_id, login_session_id, id),
  /* Provisioned for a prune that does not exist yet, the same way account_tokens
     (00027) provisions one. */
  KEY idx_qr_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS qr_login_transactions;
SET FOREIGN_KEY_CHECKS = 1;
