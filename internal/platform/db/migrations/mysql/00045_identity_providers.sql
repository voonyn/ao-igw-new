-- +goose Up
-- Identity Provider records, one row per provider (directory-sign-in). One table
-- with a `type` column and every per-type field inline and nullable: type 1 is
-- LDAP, and a second type adds nullable columns to this table and migrates no
-- existing row. The stated ceiling is the third type, where a detail table or a
-- payload column earns its place. See docs/adr/0013.
--
-- The provider is an ENTITY: an administrator creates it, edits it, and expects to
-- find it again, so it carries deleted_at and every read filters
-- `deleted_at IS NULL`. state sits beside deleted_at, which is the `applications`
-- shape (00004): an inactive provider and a soft-deleted provider both refuse every
-- sign-in of the people tied to them.
--
-- org_id carries the level: '' is the Tenant-wide row and a UUID is that
-- Organization's own row. The row that resolution names wins WHOLE, and no field is
-- ever merged from a second row, because half a bind DN from the Tenant and half from
-- an Organization is nonsense. Resolution never walks the levels: it keys on the
-- claimed domain, on the Identity Link, or on the count of live active rows of the
-- Tenant, which spans both levels. org_id decides the Organization a bind creates
-- people in, and it scopes the admin list.
--
-- bind_password is VARBINARY, sealed by crypto.Cipher, and never TEXT. The
-- repository seals on write and opens on read (the notification_settings pattern,
-- 00023), so no layer above ever holds the ciphertext.
CREATE TABLE identity_providers (
  id              CHAR(36)      NOT NULL,
  tenant_id       CHAR(36)      NOT NULL,
  org_id          CHAR(36)      NOT NULL DEFAULT '',  /* '' = tenant-wide, UUID = that org's own */
  name            VARCHAR(255)  NOT NULL,
  type            TINYINT       NOT NULL DEFAULT 1,   /* 1=ldap */
  state           TINYINT       NOT NULL DEFAULT 1,   /* 1=active 2=inactive */
  /* Org a bind creates people in when org_id = ''. users.org_id is mandatory (00006),
     so a Tenant-wide row without it creates nobody: the service refuses to save one. */
  default_org_id  CHAR(36)      NULL,

  -- ── Transport (per-type: LDAP) ──
  mode            TINYINT        NULL DEFAULT 3,      /* 1=plain 2=starttls 3=ldaps */
  servers         JSON           NULL,                /* ["ldaps://dc1.corp.example:636", ...] */
  root_ca         TEXT           NULL,                /* optional PEM for a private authority */
  timeout_ms      INT            NULL DEFAULT 5000,   /* dial and bind deadline, never NULL for an outbound call */

  -- ── Search (per-type: LDAP) ──
  bind_dn             VARCHAR(512)   NULL,            /* service account that runs the search */
  bind_password       VARBINARY(512) NULL,            /* sealed by crypto.Cipher; never TEXT */
  base_dn             VARCHAR(512)   NULL,
  user_object_classes JSON           NULL,            /* ["inetOrgPerson", ...] */
  user_filters        JSON           NULL,            /* ["uid", "sAMAccountName", ...] */
  user_base           VARCHAR(512)   NULL,

  -- ── Attribute mapping (per-type: LDAP). Six attributes, and no more: every other
  --    attribute Zitadel maps writes a column that no token can carry. ──
  attr_id             VARCHAR(255)  NULL,             /* stable directory id, objectGUID in AD */
  attr_username       VARCHAR(255)  NULL,
  attr_email          VARCHAR(255)  NULL,
  attr_first_name     VARCHAR(255)  NULL,
  attr_last_name      VARCHAR(255)  NULL,
  attr_display_name   VARCHAR(255)  NULL,

  created_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id, tenant_id),
  -- Name is unique per tenant, and the functional key part maps a NULL deleted_at to
  -- a fixed epoch so a soft-deleted row does not hold its name for ever (uq_username,
  -- 00006; docs/adr/0001).
  UNIQUE KEY uq_identity_providers_name (name, tenant_id,
    (IFNULL(deleted_at, CAST('1970-01-01 00:00:01' AS DATETIME(6))))),
  -- Admin list, and resolution case 4: "count the live active providers of this tenant".
  KEY idx_identity_providers_tenant (tenant_id, state, id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Domains a provider claims. Resolution case 1 reads this table: an identifier that
-- carries a claimed domain resolves to that provider.
--
-- The claim is a row, not a JSON list in a TEXT column, because only a row carries a
-- unique key. (tenant_id, domain) is the primary key, so one domain belongs to at
-- most one provider of a Tenant and the DATABASE refuses the second claim. A JSON
-- list would move the rule into application code, which loses the race between two
-- administrators who save at the same moment.
--
-- The claim is an ENTITY, so it carries deleted_at. The identity IS the primary key,
-- so a functional key part is impossible here (docs/adr/0001). Re-claiming a domain
-- revives the deleted row, which is the organization_domains pattern (00002). The
-- revive must keep the owner of a LIVE row, or the second claim silently steals the
-- domain from the first provider instead of being refused:
--   INSERT ... ON DUPLICATE KEY UPDATE
--     idp_id     = IF(deleted_at IS NULL, idp_id, VALUES(idp_id)),
--     deleted_at = NULL
-- A live row of another provider therefore keeps its owner and changes nothing. The
-- repository reads the row back and answers domain_already_claimed when it names a
-- provider other than the one that asked.
CREATE TABLE identity_provider_domains (
  tenant_id    CHAR(36)      NOT NULL,
  domain       VARCHAR(255)  NOT NULL,            /* bare host, stored lowercased */
  idp_id       CHAR(36)      NOT NULL,

  created_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (tenant_id, domain),
  -- "every domain of this provider": the admin read, and the cascade on provider delete.
  KEY idx_identity_provider_domains_idp (tenant_id, idp_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The Identity Link: one directory account tied to one person.
--
-- This is NOT an entity. It carries no deleted_at and it is HARD deleted, because
-- nobody re-reads an unlinked account: the audit row (idp.unlinked) is the record.
-- See CLAUDE.md.
--
-- The primary key (tenant_id, idp_id, external_id) means one directory account maps
-- to one person. The second unique key (tenant_id, idp_id, user_id) means one person
-- holds at most one account per provider. One person can still hold several links,
-- one per provider, which is what a redirect provider will need.
--
-- external_id is the STABLE id of the directory, objectGUID in Active Directory, and
-- never the username. A username changed in the directory therefore never orphans
-- the person.
CREATE TABLE identity_provider_user_links (
  tenant_id    CHAR(36)      NOT NULL,
  idp_id       CHAR(36)      NOT NULL,
  external_id  VARCHAR(255)  NOT NULL,           /* stable directory id (attr_id), never the username */
  user_id      CHAR(36)      NOT NULL,

  created_at   DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

  PRIMARY KEY (tenant_id, idp_id, external_id),
  -- One person holds at most one account per provider.
  UNIQUE KEY uq_identity_provider_user_links_user (tenant_id, idp_id, user_id),
  -- "every link of this person": resolution case 2, the admin link list, and the
  -- last-link guard rail.
  KEY idx_identity_provider_user_links_user (tenant_id, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS identity_provider_user_links;
DROP TABLE IF EXISTS identity_provider_domains;
DROP TABLE IF EXISTS identity_providers;
SET FOREIGN_KEY_CHECKS = 1;
