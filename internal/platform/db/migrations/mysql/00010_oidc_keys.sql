-- +goose Up
-- Asymmetric key pairs for the instance OpenID Provider. Public halves are
-- published at the JWKS endpoint (jwks_uri in oidc_provider_configs); private
-- halves are ENCRYPTED at the app layer (reversible, NOT hashed) before insert.
-- Material is produced by internal/platform/crypto.Generate: both halves are
-- JWK JSON (RFC 7517 / RFC 7518), so a row needs no decoding to reach a
-- goidc.JSONWebKey. algorithm duplicates the JWK `alg` value
-- (RS256/RS384/RS512, ES256/ES384/ES512, PS256/PS384/PS512) so the signer can
-- be selected without parsing the key. The row id doubles as the JWKS `kid`.
CREATE TABLE oidc_keys (
    -- ── Identity & lifecycle ──────────────────────────────────
    id            CHAR(36)     NOT NULL,                /* also published as the JWKS `kid` */
    tenant_id     CHAR(36)     NOT NULL,
    key_use       TINYINT      NOT NULL DEFAULT 1,      /* JWK use: 1=sig 2=enc */
    algorithm     VARCHAR(20)  NOT NULL,                /* JOSE alg: RS256/ES256/... */
    state         TINYINT      NOT NULL DEFAULT 1,      /* 1=active 2=inactive 3=retired */

    -- ── Key material ──────────────────────────────────────────
    public_key    JSON         NOT NULL,                /* public JWK — served via JWKS */
    private_key   BLOB         NOT NULL,                /* private JWK — ENCRYPTED at app layer */

    -- ── Rotation window ───────────────────────────────────────
    active_at     DATETIME(3)  NULL DEFAULT NULL,       /* when the key starts signing */
    expires_at    DATETIME(3)  NULL DEFAULT NULL,       /* rotation / retirement time */
    created_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
    PRIMARY KEY (id, tenant_id),
    -- Covers JWKS publishing & signer selection: "active keys for this tenant".
    KEY         idx_oidc_keys_lookup (tenant_id, state, key_use, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS oidc_keys;
SET FOREIGN_KEY_CHECKS = 1;
