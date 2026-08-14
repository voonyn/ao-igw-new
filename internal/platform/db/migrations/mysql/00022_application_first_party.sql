-- +goose Up
-- First-party flag on an OIDC client. A first-party client (the tenant's own
-- apps, e.g. console-ui / portal-ui) skips the consent screen entirely, still
-- bounded by its scope_ids allow-list (add-oidc-consent). Default 0: a new or
-- pre-existing client is third-party until explicitly marked. Seeded 1 for the
-- bootstrap apps by `bootstrap`; not editable until application editing goes
-- writable (a later change).
ALTER TABLE application_oidc_configs
  ADD COLUMN is_first_party TINYINT(1) NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE application_oidc_configs
  DROP COLUMN is_first_party;
