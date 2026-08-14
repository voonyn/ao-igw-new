-- +goose Up
-- Generic protocol -> session attachment, one row per successful finalize.
-- Outlives the protocol artifact (oidc_sessions rows are short-lived and
-- pruned) so it can drive logout fan-out and SSO audit, and stays protocol-free
-- on the session side so SAML attaches later without a migration.
--
-- protocol is an enum (1=oidc, 2=saml reserved); protocol_ref is the protocol's
-- request identifier (the goidc AuthnSession.ID for OIDC). The primary key
-- enforces that a single protocol flow is satisfied by exactly one session.
CREATE TABLE login_session_links (
    tenant_id         CHAR(36)     NOT NULL,
    login_session_id  CHAR(36)     NOT NULL,
    protocol          TINYINT      NOT NULL,              /* 1=oidc 2=saml (reserved) */
    protocol_ref      VARCHAR(255) NOT NULL,              /* oidc: goidc AuthnSession.ID */
    client_id         CHAR(36)     NULL     DEFAULT NULL, /* extracted RP, logout fan-out */
    created_at        DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (tenant_id, protocol, protocol_ref),       /* a flow is satisfied by exactly one session */
    KEY idx_login_session_links_session (tenant_id, login_session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS login_session_links;
SET FOREIGN_KEY_CHECKS = 1;
