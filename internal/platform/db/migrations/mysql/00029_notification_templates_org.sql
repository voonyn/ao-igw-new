-- +goose Up
-- Add the organization tier to message-template overrides. org_id = '' is the
-- tenant-wide row (existing rows default to it, preserving today's behavior); a
-- real org id is that org's override. Resolution at render time is most-specific
-- row wins: (tenant, org, key) → (tenant, '', key) → embedded default.
ALTER TABLE notification_templates
  ADD COLUMN org_id CHAR(36) NOT NULL DEFAULT '' AFTER tenant_id;
ALTER TABLE notification_templates
  DROP KEY uq_tmpl,
  ADD UNIQUE KEY uq_tmpl (tenant_id, org_id, template_key, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))));

-- +goose Down
ALTER TABLE notification_templates
  DROP KEY uq_tmpl;
ALTER TABLE notification_templates
  DROP COLUMN org_id;
ALTER TABLE notification_templates
  ADD UNIQUE KEY uq_tmpl (tenant_id, template_key, (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6)))));
