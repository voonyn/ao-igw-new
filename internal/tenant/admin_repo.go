package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ListAllDomains reads every hostname of one tenant, the primary one first and
// the removed ones included.
//
// It differs from ListDomains on purpose. That read answers which hosts serve
// requests, and this one answers which hosts the tenant holds: the console
// renders a removed host as removed, and an operator who cannot see it cannot
// take it back.
func (r *Repository) ListAllDomains(ctx context.Context, tenantID string) ([]Domain, error) {
	r.log.Debug("read every tenant domain", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var rows []Domain
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID).
		Order("is_primary DESC", "domain ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read every domain of tenant %s: %w", tenantID, err)
	}
	return rows, nil
}

// FindDomain reads one hostname, whatever tenant holds it and whatever state it
// is in. The host is the primary key of the table and is globally unique, so the
// read takes no tenant id: a write has to see a claim another tenant already
// holds.
//
// A soft-deleted row comes back too. The row still occupies the key, so an
// insert on that host would fail, and the caller needs to know the host is
// spoken for.
func (r *Repository) FindDomain(ctx context.Context, domain string) (Domain, error) {
	r.log.Debug("read one tenant domain", logger.String("domain", domain), logger.RequestID(ctx))

	var row Domain
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("domain = ?", domain).
		WhereAllWithDeleted().
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, fmt.Errorf("%w: %s", ErrDomainNotFound, domain)
	}
	if err != nil {
		return Domain{}, fmt.Errorf("read tenant domain %s: %w", domain, err)
	}
	return row, nil
}

// InsertDomain maps one new host to a tenant. It runs on the caller's
// transaction.
func (r *Repository) InsertDomain(ctx context.Context, row Domain) error {
	r.log.Debug("write tenant domain",
		logger.String("tenant_id", row.TenantID), logger.String("domain", row.Domain),
		logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("map domain %s to tenant %s: %w", row.Domain, row.TenantID, err)
	}
	r.log.Debug("wrote tenant domain",
		logger.String("tenant_id", row.TenantID), logger.String("domain", row.Domain),
		logger.RequestID(ctx))
	return nil
}

// RestoreDomain puts one removed host of a tenant back to work. It runs on the
// caller's transaction.
//
// It clears the soft-delete mark as well as the state, so a row marked either
// way comes back. The tenant id is in the clause, so one tenant can never
// restore the host of another.
func (r *Repository) RestoreDomain(ctx context.Context, tenantID, domain string) error {
	r.log.Debug("restore tenant domain",
		logger.String("tenant_id", tenantID), logger.String("domain", domain),
		logger.RequestID(ctx))

	_, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Domain)(nil)).
		Set("state = ?", DomainStateActive).
		Set("deleted_at = NULL").
		Where("tenant_id = ?", tenantID).
		Where("domain = ?", domain).
		WhereAllWithDeleted().
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("restore domain %s of tenant %s: %w", domain, tenantID, err)
	}
	r.log.Debug("restored tenant domain",
		logger.String("tenant_id", tenantID), logger.String("domain", domain),
		logger.RequestID(ctx))
	return nil
}

// DeactivateDomain stops one host of a tenant resolving. It runs on the caller's
// transaction.
//
// The row stays. tenant_domains.domain is globally unique, so a delete would
// free the host for another tenant to claim, and the removal could not be
// undone.
func (r *Repository) DeactivateDomain(ctx context.Context, tenantID, domain string) error {
	r.log.Debug("deactivate tenant domain",
		logger.String("tenant_id", tenantID), logger.String("domain", domain),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Domain)(nil)).
		Set("state = ?", DomainStateInactive).
		Where("tenant_id = ?", tenantID).
		Where("domain = ?", domain).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("remove domain %s of tenant %s: %w", domain, tenantID, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("remove domain %s of tenant %s: %w", domain, tenantID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrDomainNotFound, domain)
	}
	r.log.Debug("deactivated tenant domain",
		logger.String("tenant_id", tenantID), logger.String("domain", domain),
		logger.RequestID(ctx))
	return nil
}

// ReadBootstrap reads the singleton bootstrap record. A deployment whose schema
// was migrated but never bootstrapped returns ErrNoBootstrapRecord.
func (r *Repository) ReadBootstrap(ctx context.Context) (Bootstrap, error) {
	r.log.Debug("read the bootstrap record", logger.RequestID(ctx))

	var row Bootstrap
	err := db.Conn(ctx, r.db).NewSelect().Model(&row).Limit(1).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Bootstrap{}, ErrNoBootstrapRecord
	}
	if err != nil {
		return Bootstrap{}, fmt.Errorf("read the bootstrap record: %w", err)
	}
	return row, nil
}
