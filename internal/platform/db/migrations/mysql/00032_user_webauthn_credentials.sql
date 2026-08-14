-- +goose Up
-- WebAuthn/passkey second-factor credentials, per user (add-webauthn-passkeys).
-- A passkey is a per-user credential like the TOTP secret (00030), so it lives in
-- the user vertical slice as a secondary table. Unlike TOTP there is no secret at
-- rest: the stored blob is a PUBLIC key + metadata, so no cipher is involved.
--
-- The table is tenant-scoped by construction: tenant_id is part of the primary
-- key, so every query the repo issues carries it and no // tenantscope:allow is
-- needed. One row per registered credential (a user MAY have several passkeys).
--
-- credential is the JSON-marshaled webauthn.Credential owned by the go-webauthn
-- library (id, public key, attestation, flags, authenticator{aaguid, sign count,
-- clone warning}). We persist it verbatim and overwrite it on each successful
-- assertion (updated sign count) rather than mapping field-by-field, so the schema
-- never drifts as the library's struct evolves. credential_id is duplicated out of
-- the blob as a queryable BINARY column for the PK/lookup and the browser exclude
-- list. rp_id is the domain the passkey was registered under (per-domain binding):
-- an assertion under a different host fails by construction.
CREATE TABLE user_webauthn_credentials (
    tenant_id      CHAR(36)       NOT NULL,
    credential_id  VARBINARY(255) NOT NULL,                   /* raw credential id, globally unique */

    user_id        CHAR(36)       NOT NULL,
    rp_id          VARCHAR(255)   NOT NULL,                   /* domain registered under (RP ID) */
    credential     JSON           NOT NULL,                   /* marshaled webauthn.Credential (public key, no secret) */
    name           VARCHAR(255)   NULL     DEFAULT NULL,      /* optional friendly label */

    created_at     DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_used_at   DATETIME(3)    NULL     DEFAULT NULL,      /* set on each successful assertion */

    deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
    PRIMARY KEY (tenant_id, credential_id),
    KEY idx_user_webauthn_user (tenant_id, user_id)           /* list/challenge/delete a user's passkeys */
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
DROP TABLE IF EXISTS user_webauthn_credentials;
