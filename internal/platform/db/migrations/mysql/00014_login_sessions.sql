-- +goose Up
-- Durable SSO login session (Zitadel "session" analogue): a protocol-agnostic
-- container of verified authentication factors, owned by the first-party login
-- app and credentialed by an opaque, rotating session token. One login session
-- fans out to N protocol flows (see login_session_links) = single sign-on.
--
-- data is the full LoginSession struct (AMR-keyed factor map with per-factor
-- auth_time, user agent, IP, absolute-cap timestamp, metadata), AES-256-GCM
-- encrypted at the app layer (internal/utils/cryptokey.Cipher, keyed by
-- DATABASE_ENCRYPTION_KEY), or raw JSON when no key is configured (dev),
-- mirroring oidc_sessions. The flat columns are extracted for operability only.
--
-- token_hash holds a SHA-256 digest of the session token, never the token
-- itself (pattern: oidc_grants.auth_code_hash); the plaintext is returned once
-- per mint/rotation. It is globally UNIQUE because bearer lookup happens before
-- the tenant is resolved.
CREATE TABLE login_sessions (
    -- ── Identity & lifecycle ──────────────────────────────────
    id              CHAR(36)     NOT NULL,                /* public session id; the `sid` claim */
    tenant_id       CHAR(36)     NOT NULL,
    user_id         CHAR(36)     NULL     DEFAULT NULL,   /* extracted: NULL until user check passes */
    state           TINYINT      NOT NULL DEFAULT 1,      /* 1=active 2=terminated; expired is derived */

    -- ── Credential digest (SHA-256 hex; never the token) ──────
    token_hash      CHAR(64)     NOT NULL,                /* rotated per factor upgrade */

    -- ── Authoritative state (encrypted; see header) ───────────
    data            MEDIUMBLOB   NOT NULL,                /* AES-256-GCM(serialized LoginSession), or raw JSON when unkeyed */

    -- ── Housekeeping ──────────────────────────────────────────
    expires_at      DATETIME(3)  NOT NULL,                /* effective expiry: slid on activity, capped */
    terminated_at   DATETIME(3)  NULL     DEFAULT NULL,
    created_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at      DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    PRIMARY KEY (tenant_id, id),
    UNIQUE KEY uq_login_sessions_token (token_hash),       /* bearer lookup precedes tenant resolution */
    KEY idx_login_sessions_user       (tenant_id, user_id),
    KEY idx_login_sessions_expires_at (expires_at)          /* background pruning */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS login_sessions;
SET FOREIGN_KEY_CHECKS = 1;
