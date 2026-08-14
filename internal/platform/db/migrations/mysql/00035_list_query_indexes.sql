-- +goose Up
-- The list-query contract (add-admin-list-query-contract) lets a caller order and
-- narrow a collection instead of receiving it in one fixed order. 00033 indexed
-- exactly one ordering per table — (tenant_id, created_at, id) — so every sort
-- key beyond `created` would filesort the tenant, which is the regression 00033
-- was written to prevent. These are that change's other orderings.
--
-- THE RULE THIS FILE ENFORCES: a sort key is offered only where an index covers
-- it, and the index ships in the same change as the key. Adding a key to a
-- repository's allowlist without adding its index here is how the allowlist
-- quietly becomes a table scan.
--
-- Column order matches the predicate the keyset builds: tenant_id equality
-- first, then the ordered pair (<sort column>, id). The trailing id is the
-- tiebreak that keeps an ordering on a NON-UNIQUE column (a name, a state)
-- stable across pages — without it, rows sharing a value can repeat or vanish at
-- a page boundary.
--
-- The `name` indexes serve double duty: `q` is a PREFIX match (LIKE 'term%'),
-- which uses the same index a sort on that column does. That is why search is a
-- prefix and not a substring — '%term%' could use none of these.

-- organizations / projects / applications: allowlist keys `name`, `state`.
-- (`created` is 00033's idx_*_tenant_page.)
ALTER TABLE organizations  ADD KEY idx_orgs_tenant_name      (tenant_id, name, id);
ALTER TABLE organizations  ADD KEY idx_orgs_tenant_state     (tenant_id, state, id);
ALTER TABLE projects       ADD KEY idx_projects_tenant_name  (tenant_id, name, id);
ALTER TABLE projects       ADD KEY idx_projects_tenant_state (tenant_id, state, id);
ALTER TABLE applications   ADD KEY idx_apps_tenant_name      (tenant_id, name, id);
ALTER TABLE applications   ADD KEY idx_apps_tenant_state     (tenant_id, state, id);

-- users: allowlist keys `username`, `state`. `username` is also the ONLY field
-- `q` searches on this list — display name and email live on user_humans, which
-- no index on users can cover, so sorting and searching them is deferred with
-- its own measurement rather than shipped as a join filesort.
ALTER TABLE users          ADD KEY idx_users_tenant_username (tenant_id, username, id);
ALTER TABLE users          ADD KEY idx_users_tenant_state    (tenant_id, state, id);

-- login_sessions: allowlist keys `expires`, `state`.
ALTER TABLE login_sessions ADD KEY idx_sessions_tenant_expires (tenant_id, expires_at, id);
ALTER TABLE login_sessions ADD KEY idx_sessions_tenant_state   (tenant_id, state, id);

-- oidc_grants: allowlist key `expires`.
ALTER TABLE oidc_grants    ADD KEY idx_grants_tenant_expires (tenant_id, expires_at, id);

-- The per-user reads. A user's detail view asks for that user's sessions, and
-- 00033 added only the tenant-wide page index — so narrowing by user_id scanned
-- the tenant's sessions and then ordered them. This is the same keyset shape
-- with the subject in front of it.
ALTER TABLE login_sessions ADD KEY idx_sessions_tenant_user_page (tenant_id, user_id, created_at, id);

-- oidc_grants.subject is the grants half of the same read.
ALTER TABLE oidc_grants    ADD KEY idx_grants_tenant_subject_page (tenant_id, subject, created_at, id);

-- tenant_members had NO page index, because when 00033 was written the tenant
-- roster was not paged — it was returned whole inside /members' composite
-- envelope. Splitting that envelope (design decision 7) made the roster a keyset
-- read ordered by (created_at, user_id), and PRIMARY (tenant_id, user_id) cannot
-- serve that ordering, so every page filesorted the roster. Verified: without
-- this key the plan is `PRIMARY … Using filesort`; with it, `Backward index scan`.
ALTER TABLE tenant_members ADD KEY idx_tenant_members_page (tenant_id, created_at, user_id);

-- audit_events already indexes (tenant_id, created_at) and (tenant_id, actor_id),
-- so "events this user PERFORMED" is covered and "events performed ON this user"
-- scans within the tenant. The Audit tab offers both as separate reads, because
-- the audit filter conjoins its predicates — this is the index the second one
-- needs.
ALTER TABLE audit_events   ADD KEY idx_audit_tenant_entity (tenant_id, entity_id, created_at);

-- +goose Down
ALTER TABLE tenant_members DROP KEY idx_tenant_members_page;
ALTER TABLE audit_events   DROP KEY idx_audit_tenant_entity;
ALTER TABLE oidc_grants    DROP KEY idx_grants_tenant_subject_page;
ALTER TABLE login_sessions DROP KEY idx_sessions_tenant_user_page;
ALTER TABLE oidc_grants    DROP KEY idx_grants_tenant_expires;
ALTER TABLE login_sessions DROP KEY idx_sessions_tenant_state;
ALTER TABLE login_sessions DROP KEY idx_sessions_tenant_expires;
ALTER TABLE users          DROP KEY idx_users_tenant_state;
ALTER TABLE users          DROP KEY idx_users_tenant_username;
ALTER TABLE applications   DROP KEY idx_apps_tenant_state;
ALTER TABLE applications   DROP KEY idx_apps_tenant_name;
ALTER TABLE projects       DROP KEY idx_projects_tenant_state;
ALTER TABLE projects       DROP KEY idx_projects_tenant_name;
ALTER TABLE organizations  DROP KEY idx_orgs_tenant_state;
ALTER TABLE organizations  DROP KEY idx_orgs_tenant_name;
