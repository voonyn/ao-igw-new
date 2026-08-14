-- +goose Up
-- Keyset pagination (paginate-admin-list-api) windows every growth-bearing admin
-- list over (created_at, id) within a tenant. Without a covering index the tuple
-- comparison degrades to a scan, so the change that bounds the read would make
-- it slower. The audit feed already had idx_audit_tenant_created; these are the
-- seven tables that did not.
--
-- Column order matches the predicate: tenant_id equality first, then the ordered
-- keyset pair. The org-narrowed reads reach their org through a join or an IN
-- list on an already-indexed column, so no separate (tenant_id, org_id, …) index
-- is added until a measurement asks for one.

ALTER TABLE organizations        ADD KEY idx_orgs_tenant_page      (tenant_id, created_at, id);
ALTER TABLE projects             ADD KEY idx_projects_tenant_page  (tenant_id, created_at, id);
ALTER TABLE applications         ADD KEY idx_apps_tenant_page      (tenant_id, created_at, id);
ALTER TABLE users                ADD KEY idx_users_tenant_page     (tenant_id, created_at, id);
ALTER TABLE organization_members ADD KEY idx_org_members_page      (tenant_id, created_at, org_id, user_id);
ALTER TABLE login_sessions       ADD KEY idx_sessions_tenant_page  (tenant_id, created_at, id);
ALTER TABLE oidc_grants          ADD KEY idx_grants_tenant_page    (tenant_id, created_at, id);

-- +goose Down
ALTER TABLE oidc_grants          DROP KEY idx_grants_tenant_page;
ALTER TABLE login_sessions       DROP KEY idx_sessions_tenant_page;
ALTER TABLE organization_members DROP KEY idx_org_members_page;
ALTER TABLE users                DROP KEY idx_users_tenant_page;
ALTER TABLE applications         DROP KEY idx_apps_tenant_page;
ALTER TABLE projects             DROP KEY idx_projects_tenant_page;
ALTER TABLE organizations        DROP KEY idx_orgs_tenant_page;
