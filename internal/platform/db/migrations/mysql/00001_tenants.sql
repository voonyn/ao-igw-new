-- +goose Up
CREATE TABLE tenants (
  id               CHAR(36)      NOT NULL,
  name             VARCHAR(200)  NOT NULL,
  state            TINYINT       NOT NULL DEFAULT 1        /* 1=active 2=inactive -- 3=removed */,
  default_org_id   CHAR(36)      NULL                      /* default org for self-reg */,
  created_at       DATETIME(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at       DATETIME(3)      NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  
  deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
  PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE tenant_domains (
    -- Bare host, stored lowercased, optionally with a port for non-standard
    -- listeners (e.g. "auth.acme.com", "localhost:8080"). Globally unique, so a
    -- domain maps to exactly one tenant.
    domain        VARCHAR(255)  NOT NULL,
    tenant_id     CHAR(36)      NOT NULL,

    is_primary    TINYINT       NOT NULL DEFAULT 0,       /* the tenant's canonical domain */
    is_verified   TINYINT       NOT NULL DEFAULT 1,       /* custom domains may require verification */
    state         TINYINT       NOT NULL DEFAULT 1,       /* 1=active 2=inactive */

    created_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),

    deleted_at   DATETIME(6)   NULL,               /* soft delete: NULL = live */
    PRIMARY KEY (domain),
    -- Reverse lookup: "all domains for this tenant".
    KEY idx_tenant_domains_tenant (tenant_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS tenant_domains;
DROP TABLE IF EXISTS tenants;
SET FOREIGN_KEY_CHECKS = 1;
