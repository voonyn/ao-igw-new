-- +goose Up
-- Extracted login_session_id column on oidc_grants, following the house pattern
-- (SaveGrant already extracts client_id/subject from the grant). Grant.Store
-- inherits the sid at grant creation but Store lives in the encrypted blob; the
-- adapter lifts it into this indexed column so logout fan-out is one query.
-- Additive and nullable: existing rows are unaffected, and NULL means
-- "pre-feature or client_credentials grant".
ALTER TABLE oidc_grants
    ADD COLUMN login_session_id CHAR(36) NULL DEFAULT NULL AFTER subject,
    ADD KEY idx_oidc_grants_login_session (tenant_id, login_session_id);

-- +goose Down
ALTER TABLE oidc_grants
    DROP KEY idx_oidc_grants_login_session,
    DROP COLUMN login_session_id;
