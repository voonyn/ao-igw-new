-- +goose Up
-- RFC 8707 resource indicators. The tenant declares which resource identifiers
-- its clients can ask for at /authorize. The authorization server puts the
-- requested value in the access token `aud`, and the resource server checks it.
-- NULL or an empty list disables the indicator for the tenant.
ALTER TABLE oidc_provider_configs
    ADD COLUMN resource_indicators JSON NULL DEFAULT NULL AFTER signing_alg_config;

-- Existing tenants keep the two identifiers the front ends already send:
-- console-ui sends urn:alphaomega:admin-api, portal-ui sends
-- urn:alphaomega:account-api.
UPDATE oidc_provider_configs
   SET resource_indicators = JSON_ARRAY('urn:alphaomega:admin-api', 'urn:alphaomega:account-api')
 WHERE resource_indicators IS NULL;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
ALTER TABLE oidc_provider_configs DROP COLUMN resource_indicators;
SET FOREIGN_KEY_CHECKS = 1;
