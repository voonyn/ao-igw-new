-- +goose Up
CREATE TABLE application_oidc_configs (
    -- ── Identity & lifecycle ──────────────────────────────────
    app_id                      CHAR(36)  NOT NULL,
    tenant_id                   CHAR(36)  NOT NULL,
    client_id                   VARCHAR(36)     NOT NULL,
    created_at                  DATETIME(3)     NOT NULL,
    expires_at                  DATETIME(3)     NULL        DEFAULT NULL,

    -- ── Secrets ──────────────────────────────────────────────
    -- secret holds a bcrypt hash, never the secret itself. The gateway shows the
    -- secret once, at creation, and verifies it with crypto.VerifyPassword.
    secret                      TEXT            NULL        DEFAULT NULL,
    secret_expires_at           DATETIME(3)     NULL        DEFAULT NULL,
    registration_token          TEXT            NULL        DEFAULT NULL,
 
    -- ── Core auth behaviour (kept flat: app checks these directly) ──
    -- token_authn_method is kept flat so the app can quickly
    -- determine IsPublic() without deserializing any JSON.
    token_authn_method          VARCHAR(50)     NOT NULL    DEFAULT 'client_secret_basic',
    -- scopes the client can request, as space-separated names. It is the
    -- allow-list goidc validates an authorization request against.
    scopes                      TEXT            NULL        DEFAULT NULL,
    subject_type                VARCHAR(20)     NULL        DEFAULT NULL,
    sector_identifier_uri       TEXT            NULL        DEFAULT NULL,
    default_max_age_secs        INT UNSIGNED    NULL        DEFAULT NULL,
    default_acr_values          TEXT            NULL        DEFAULT NULL,
    par_is_required             TINYINT(1)      NOT NULL    DEFAULT 0,
 
    -- ── URIs & grants (arrays, validated by app not DB) ──────
    redirect_uris               JSON            NOT NULL,
    grant_types                 JSON            NOT NULL,
    response_types              JSON            NOT NULL,
    request_uris                JSON            NULL        DEFAULT NULL,
    post_logout_redirect_uris   JSON          NULL        DEFAULT NULL,
    auth_detail_types           JSON            NULL        DEFAULT NULL,
 
    -- ── JWKS (public keys, read as unit) ─────────────────────
    jwks_uri                    TEXT            NULL        DEFAULT NULL,
    signed_jwks_uri             TEXT            NULL        DEFAULT NULL,
    jwks                        JSON            NULL        DEFAULT NULL,
 
    -- ── Feature config blobs (each group always read/written together) ──
 
    -- Signing & encryption for ID token, UserInfo, JAR, JARM
    -- Fields: id_token_{sig_alg, key_enc_alg, content_enc_alg},
    --         userinfo_{sig_alg, key_enc_alg, content_enc_alg},
    --         jar_{is_required, sig_alg, key_enc_alg, content_enc_alg},
    --         jarm_{sig_alg, key_enc_alg, content_enc_alg}
    crypto_config           JSON            NULL        DEFAULT NULL,
 
    -- Per-endpoint authn methods & sig algs (token, introspect, revoke)
    -- Fields: token_authn_sig_alg,
    --         introspection_{authn_method, authn_sig_alg},
    --         revocation_{authn_method, authn_sig_alg}
    authn_config            JSON            NULL        DEFAULT NULL,
 
    -- DPoP + mTLS binding settings
    -- Fields: dpop_binding_required, tls_binding_required,
    --         tls_subject_dn, tls_san_dns, tls_san_ip
    token_binding_config    JSON            NULL        DEFAULT NULL,
 
    -- CIBA backchannel settings (NULL when CIBA not used)
    -- Fields: ciba_delivery_mode, ciba_notification_endpoint,
    --         ciba_jar_sig_alg, ciba_user_code_enabled
    ciba_config             JSON            NULL        DEFAULT NULL,
 
    -- OpenID Federation settings (NULL when federation not used)
    -- Fields: fed_trust_anchor, fed_trust_marks,
    --         client_registration_types
    federation_config       JSON            NULL        DEFAULT NULL,
 
    -- Informational / display metadata (never queried individually)
    -- Fields: client_name, application_type, logo_uri, policy_uri,
    --         tos_uri, contacts, keywords, description, display_name,
    --         organization_name, organization_uri, information_uri,
    --         credential_offer_endpoint
    meta                    JSON            NULL        DEFAULT NULL,
 
    -- Extra DCR attributes not covered by standard fields
    custom_attributes       JSON            NULL        DEFAULT NULL,
 
    deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
    PRIMARY KEY (app_id, tenant_id),
    UNIQUE KEY  uq_oidc_client (tenant_id, client_id, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6))))),
    KEY         idx_oidc_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS application_oidc_configs;
SET FOREIGN_KEY_CHECKS = 1;
