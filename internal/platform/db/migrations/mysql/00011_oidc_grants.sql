-- +goose Up
-- Persisted goidc Grants (github.com/luikyv/go-oidc). A Grant is the access an
-- entity (user or client) gave to a client; goidc creates one per authorization
-- code / refresh-token / client-credentials issuance and resolves it by id, by
-- authorization code, and by refresh token.
--
-- Secrets at rest:
--   * data is the full goidc.Grant, AES-256-GCM encrypted at the app layer
--     (internal/utils/cryptokey.Cipher, keyed by DATABASE_ENCRYPTION_KEY). It
--     carries the plaintext refresh token, so it must be reversible. When no
--     key is configured (dev) it is stored as raw JSON.
--   * auth_code_hash / refresh_token_hash hold a SHA-256 digest of the code /
--     token, never the value itself. goidc looks grants up by the plaintext
--     handle, which the adapter digests before matching.
--
-- Accessed via internal/repository/oidc (data) under internal/service's
-- OIDCStorageService, which implements goidc's GrantManager + RefreshTokenManager.
CREATE TABLE oidc_grants (
    -- ── Identity & lifecycle ──────────────────────────────────
    id                  CHAR(36)     NOT NULL,                /* goidc Grant.ID (UUID by default) */
    tenant_id           CHAR(36)     NOT NULL,                /* owning OP instance, see oidc_provider_configs */
    client_id           CHAR(36)     NOT NULL,                /* extracted: relying party */
    subject             VARCHAR(255) NULL     DEFAULT NULL,   /* extracted: resource owner (NULL for client_credentials) */

    -- ── Lookup digests (SHA-256 hex of the secret; never the secret) ──
    auth_code_hash      CHAR(64)     NULL     DEFAULT NULL,   /* SHA-256 of Random(30) code; kept after redemption for reuse detection */
    refresh_token_hash  CHAR(64)     NULL     DEFAULT NULL,   /* SHA-256 of Random(100) token; replaced in place on rotation */

    -- ── Authoritative state (encrypted; see header) ───────────
    data                MEDIUMBLOB   NOT NULL,                /* AES-256-GCM(serialized goidc.Grant), or raw JSON when unkeyed */

    -- ── Housekeeping ──────────────────────────────────────────
    expires_at          DATETIME(3)  NULL     DEFAULT NULL,   /* refresh-token expiry (0/unset = NULL) */
    created_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at          DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    PRIMARY KEY (tenant_id, id),
    -- Token-endpoint resolves grants by these digests on every redemption.
    KEY idx_oidc_grants_auth_code     (tenant_id, auth_code_hash),
    KEY idx_oidc_grants_refresh_token (tenant_id, refresh_token_hash),
    -- Supports "revoke every grant for this subject".
    KEY idx_oidc_grants_subject       (tenant_id, subject),
    -- Supports background pruning of expired grants.
    KEY idx_oidc_grants_expires_at    (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS oidc_grants;
SET FOREIGN_KEY_CHECKS = 1;
