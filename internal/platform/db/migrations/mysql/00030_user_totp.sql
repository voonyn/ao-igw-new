-- +goose Up
-- TOTP (RFC 6238) second-factor credential + single-use recovery codes, per user
-- (add-totp-mfa). Both tables are tenant-scoped by construction: tenant_id is part
-- of the primary key, so every query the repo issues carries it and no
-- // tenantscope:allow is needed. TOTP is a per-user credential like the password
-- hash and the account-recovery tokens, so it lives in the user vertical slice as
-- secondary tables (mirroring account_tokens / user recovery).
--
-- user_totp holds one row per user. activated_at NULL = a PENDING enrollment (the
-- secret is generated but the user has not yet proven a code); a set activated_at
-- = an ACTIVE second factor. secret_encrypted is the cipher output of the base32
-- TOTP secret (nonce||ciphertext||tag); in development with no encryption key it is
-- the base32 secret as-is (the login_sessions / oidc storage plaintext precedent).
CREATE TABLE user_totp (
    tenant_id         CHAR(36)     NOT NULL,
    user_id           CHAR(36)     NOT NULL,

    -- ── TOTP shared secret, encrypted at rest (dev: plaintext base32) ──
    secret_encrypted  VARBINARY(255) NOT NULL,
    activated_at      DATETIME(3)  NULL     DEFAULT NULL,   /* NULL = pending; set = active */

    created_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
    PRIMARY KEY (tenant_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- user_totp_recovery_codes holds one row per single-use recovery code. code_hash
-- is a SHA-256 hex digest of the plaintext code (never the code itself); the codes
-- are high-entropy, so a fast digest is correct — this is not a password. used_at
-- NULL = unused; consumption flips it atomically in one guarded UPDATE so a code is
-- spent at most once even under concurrent challenges.
CREATE TABLE user_totp_recovery_codes (
    tenant_id   CHAR(36)     NOT NULL,
    user_id     CHAR(36)     NOT NULL,
    code_hash   CHAR(64)     NOT NULL,                    /* SHA-256 hex of the plaintext code */

    used_at     DATETIME(3)  NULL     DEFAULT NULL,       /* NULL = unused */
    created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (tenant_id, user_id, code_hash),
    KEY idx_user_totp_recovery_user (tenant_id, user_id)  /* list/delete a user's codes */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS user_totp_recovery_codes;
DROP TABLE IF EXISTS user_totp;
SET FOREIGN_KEY_CHECKS = 1;
