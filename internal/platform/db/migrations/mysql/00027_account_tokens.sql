-- +goose Up
-- Single-use, time-limited account tokens for self-service recovery
-- (add-account-recovery): password reset and email verification. One table, a
-- purpose discriminator — both flows share an identical mint → email →
-- single-use consume → expire/prune lifecycle.
--
-- token_hash holds a SHA-256 digest of the raw token, never the token itself
-- (pattern: login_sessions.token_hash / oidc_grants.auth_code_hash); the
-- plaintext is disclosed once, only inside the emailed link. Unlike
-- login_sessions the lookup is tenant-scoped (the confirm request arrives on the
-- tenant's domain, so the tenant is resolved before consume), so the digest is
-- unique WITHIN a tenant, not globally.
--
-- used_at NULL = unconsumed; the consume path flips it atomically in one UPDATE
-- guarded by (used_at IS NULL AND expires_at > now), so a token is spent at most
-- once even under concurrent confirms.
CREATE TABLE account_tokens (
    id           CHAR(36)     NOT NULL,
    tenant_id    CHAR(36)     NOT NULL,
    user_id      CHAR(36)     NOT NULL,
    purpose      TINYINT      NOT NULL,                /* 1=password_reset 2=email_verify */

    -- ── Credential digest (SHA-256 hex; never the raw token) ──
    token_hash   CHAR(64)     NOT NULL,

    expires_at   DATETIME(3)  NOT NULL,
    used_at      DATETIME(3)  NULL     DEFAULT NULL,   /* NULL = unconsumed */
    created_at   DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (tenant_id, id),
    UNIQUE KEY uq_account_tokens_token (tenant_id, token_hash),   /* consume lookup */
    KEY idx_account_tokens_user        (tenant_id, user_id, purpose), /* invalidate-for-user */
    KEY idx_account_tokens_expires_at  (expires_at)               /* background pruning */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS account_tokens;
SET FOREIGN_KEY_CHECKS = 1;
