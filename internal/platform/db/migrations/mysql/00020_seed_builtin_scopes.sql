-- +goose Up
-- Backfill builtin scopes + standard claim mappers for every EXISTING tenant.
-- This gates the WithScopes switch (5.1): once WithScopes is DB-driven an
-- unseeded tenant would advertise only `openid` and break existing clients with
-- invalid_scope. New tenants are seeded equivalently by `bootstrap`. Idempotent:
-- INSERT IGNORE leans on UNIQUE(tenant_id,name) / UNIQUE(tenant_id,scope_id,
-- claim_name), so a re-run inserts nothing.

-- Builtin scopes for each tenant. openid/profile/email are default-provisioned
-- to new clients; offline_access is opt-in.
INSERT IGNORE INTO oidc_scopes
  (id, tenant_id, name, display_name, description, is_enabled, is_default, is_builtin)
SELECT UUID(), t.id, s.name, s.display_name, s.description, 1, s.is_default, 1
  FROM tenants t
  CROSS JOIN (
    SELECT 'openid'         AS name, 'OpenID'         AS display_name, 'Subject identifier (required for OIDC).'        AS description, 1 AS is_default
    UNION ALL SELECT 'profile',        'Profile',        'Basic profile: name, username, locale.',           1
    UNION ALL SELECT 'email',          'Email',          'Email address and its verification status.',       1
    UNION ALL SELECT 'offline_access', 'Offline access', 'Issue a refresh token for offline access.',        0
  ) s;

-- Standard `profile` claim mappers (source_type=1 std attr, UserInfo only) —
-- the Change-1 mapping, now data.
INSERT IGNORE INTO oidc_claim_mappers
  (id, tenant_id, scope_id, claim_name, source_type, source_key, in_id_token, in_userinfo, in_access_token)
SELECT UUID(), sc.tenant_id, sc.id, m.claim_name, 1, m.source_key, 0, 1, 0
  FROM oidc_scopes sc
  CROSS JOIN (
    SELECT 'name'               AS claim_name, 'name'               AS source_key
    UNION ALL SELECT 'given_name',         'given_name'
    UNION ALL SELECT 'family_name',        'family_name'
    UNION ALL SELECT 'preferred_username', 'preferred_username'
    UNION ALL SELECT 'locale',             'locale'
    UNION ALL SELECT 'updated_at',         'updated_at'
  ) m
 WHERE sc.name = 'profile' AND sc.is_builtin = 1;

-- Standard `email` claim mappers. email_verified is a trust claim, released only
-- through this locked builtin mapper.
INSERT IGNORE INTO oidc_claim_mappers
  (id, tenant_id, scope_id, claim_name, source_type, source_key, in_id_token, in_userinfo, in_access_token)
SELECT UUID(), sc.tenant_id, sc.id, m.claim_name, 1, m.source_key, 0, 1, 0
  FROM oidc_scopes sc
  CROSS JOIN (
    SELECT 'email'          AS claim_name, 'email'          AS source_key
    UNION ALL SELECT 'email_verified', 'email_verified'
  ) m
 WHERE sc.name = 'email' AND sc.is_builtin = 1;

-- +goose Down
-- Remove only the seeded builtin scopes; their mappers cascade via the FK.
DELETE FROM oidc_scopes WHERE is_builtin = 1;
