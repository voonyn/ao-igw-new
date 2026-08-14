-- +goose Up
-- Short-lived goidc authorization sessions (AuthnSession, github.com/luikyv/
-- go-oidc). A session holds the in-flight state of an authorization request
-- between the /authorize redirect and the user finishing authentication;
-- goidc resolves it by id.
--
-- data is the full goidc.AuthnSession, AES-256-GCM encrypted at the app layer
-- (internal/utils/cryptokey.Cipher, keyed by DATABASE_ENCRYPTION_KEY), or raw
-- JSON when no key is configured (dev). The flat columns are extracted for
-- operability only.
--
-- Accessed via internal/repository/oidc (data) under internal/service's
-- OIDCStorageService, which implements goidc's AuthManager seam (the
-- grant-by-auth-code lookup it also requires reads oidc_grants).
CREATE TABLE oidc_sessions (
    -- ── Identity & lifecycle ──────────────────────────────────
    id          CHAR(36)     NOT NULL,                /* goidc AuthnSession.ID (UUID) */
    tenant_id   CHAR(36)     NOT NULL,                /* owning OP instance, see oidc_provider_configs */
    client_id   CHAR(36)     NULL     DEFAULT NULL,   /* extracted: relying party */
    subject     VARCHAR(255) NULL     DEFAULT NULL,   /* extracted: set once the user authenticates */

    -- ── Authoritative state (encrypted; see header) ───────────
    data        MEDIUMBLOB   NOT NULL,                /* AES-256-GCM(serialized goidc.AuthnSession), or raw JSON when unkeyed */

    -- ── Housekeeping ──────────────────────────────────────────
    expires_at  DATETIME(3)  NULL     DEFAULT NULL,   /* AuthnSession.ExpiresAt (0/unset = NULL) */
    created_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    PRIMARY KEY (tenant_id, id),
    -- Supports background pruning of expired sessions.
    KEY idx_oidc_sessions_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS oidc_sessions;
SET FOREIGN_KEY_CHECKS = 1;
