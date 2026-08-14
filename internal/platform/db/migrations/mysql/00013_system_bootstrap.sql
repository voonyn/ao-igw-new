-- +goose Up
-- One-time, instance-wide bootstrap marker. The `bootstrap` command inserts the
-- single row (id = 1) inside the same transaction that creates the AlphaOmega
-- default tenant, organization, project, admin user, applications, OIDC provider
-- config and signing keys. A second `bootstrap` invocation hits this primary-key
-- (and CHECK) constraint and is refused atomically — that is what makes the
-- initialization run exactly once across the entire IAM lifecycle.
CREATE TABLE system_bootstrap (
    id          TINYINT      NOT NULL DEFAULT 1,                 /* singleton: always 1 */
    tenant_id   CHAR(36)     NOT NULL,                           /* the AO default tenant created at bootstrap */
    version     VARCHAR(20)  NOT NULL,                           /* bootstrap routine version, for future re-runs/migration */
    applied_at  DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    -- Enforced on MySQL 8.0.16+; harmlessly parsed-and-ignored on older engines,
    -- where the PRIMARY KEY alone still guarantees the single-row invariant.
    CONSTRAINT chk_system_bootstrap_singleton CHECK (id = 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;
DROP TABLE IF EXISTS system_bootstrap;
SET FOREIGN_KEY_CHECKS = 1;
