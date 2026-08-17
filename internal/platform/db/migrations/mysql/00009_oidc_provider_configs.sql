-- +goose Up
-- One OpenID Provider configuration per instance. Drives the document
-- served at /.well-known/openid-configuration (OIDC Discovery 1.0 +
-- RFC 8414 OAuth 2.0 Authorization Server Metadata) and the runtime
-- defaults the authorization server enforces.
CREATE TABLE oidc_provider_configs (
    -- ── Identity & lifecycle ──────────────────────────────────
    tenant_id     CHAR(36)      NOT NULL,
    issuer        VARCHAR(255)  NOT NULL,                 /* base issuer URL, e.g. https://auth.acme.com */
    state         TINYINT       NOT NULL DEFAULT 1,       /* 1=active 2=inactive */
    created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    require_pkce            TINYINT       NOT NULL DEFAULT 1,       /* 1=require S256 PKCE 0=optional for a confidential client, still required of a public one */
    refresh_token_rotation  TINYINT       NOT NULL DEFAULT 1,       /* 1=rotate refresh token on use 0=reuse */

    -- ── Token defaults (kept flat: server reads these on every issue) ──
    authorization_code_lifetime_secs  INT UNSIGNED  NOT NULL DEFAULT 600,
    access_token_type                 TINYINT       NOT NULL DEFAULT 1,     /* 1=jwt 2=opaque */
    access_token_lifetime_secs        INT UNSIGNED  NOT NULL DEFAULT 3600,
    id_token_lifetime_secs            INT UNSIGNED  NOT NULL DEFAULT 3600,
    refresh_token_lifetime_secs       INT UNSIGNED  NULL     DEFAULT NULL,  /* NULL = the shipped default, see migration 00037 */
   
    -- ── Grouped metadata blobs (each read/written together) ──────────

    -- Signing & encryption algorithms advertised per artifact.
    -- Fields: id_token_{sig, key_enc, content_enc}_alg_values,
    --         userinfo_{sig, key_enc, content_enc}_alg_values,
    --         request_object_{sig, key_enc, content_enc}_alg_values,
    --         token_endpoint_auth_sig_alg_values,
    --         introspection_{sig, encryption}_alg_values,
    --         dpop_signing_alg_values
    signing_alg_config   JSON  NULL DEFAULT NULL,

    deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
    PRIMARY KEY (tenant_id),
    UNIQUE KEY  uq_oidc_issuer (issuer, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS oidc_provider_configs;
SET FOREIGN_KEY_CHECKS = 1;
