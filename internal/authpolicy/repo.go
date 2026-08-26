package authpolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNotFound reports that the level holds no row. It never reaches the client:
// a level that stores nothing inherits the level below, and a reset of an
// override that is not there has already reached the state it asks for.
var ErrNotFound = errors.New("auth policy row not found")

// policyColumns names every knob of the table, in the order the migrations
// added them. The insert lists them so no write touches created_at or
// updated_at, and the upsert repeats them so a write replaces the whole row.
var policyColumns = []string{
	"lockout_threshold", "lockout_window_ms", "lockout_cooldown_ms",
	"pw_min_length", "pw_min_classes", "pw_deny_list", "pw_check_breach",
	"recovery_reset_ttl_ms", "recovery_verify_ttl_ms", "mfa_required",
}

// Repository reads and writes the two-level auth policy of one tenant.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// Find reads the live row of one level. An empty orgID reads the tenant
// default. A level that stores nothing answers ErrNotFound, which the service
// reads as "inherit everything".
func (r *Repository) Find(ctx context.Context, tenantID, orgID string) (Row, error) {
	r.log.Debug("read the auth policy of one level",
		logger.String("tenant_id", tenantID), logger.String("org_id", orgID), logger.RequestID(ctx))

	var row Row
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("ap.tenant_id = ?", tenantID).
		Where("ap.org_id = ?", orgID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, fmt.Errorf("%w: tenant %s, org %q", ErrNotFound, tenantID, orgID)
	}
	if err != nil {
		return Row{}, fmt.Errorf("read the auth policy of tenant %s, org %q: %w", tenantID, orgID, err)
	}
	return row, nil
}

// Upsert writes the whole row of one level. It runs on the caller's
// transaction.
//
// Every knob is written, the NULL ones included, so a field the write left out
// goes back to inheriting the level below. deleted_at is cleared with it: the
// primary key is (tenant_id, org_id), so a level that was reset once must be
// writable again.
func (r *Repository) Upsert(ctx context.Context, row Row) error {
	r.log.Debug("write auth policy",
		logger.String("tenant_id", row.TenantID), logger.String("org_id", row.OrgID),
		logger.RequestID(ctx))

	q := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column(append([]string{"tenant_id", "org_id"}, policyColumns...)...).
		On("DUPLICATE KEY UPDATE")
	for _, col := range policyColumns {
		q = q.Set(col + " = VALUES(" + col + ")")
	}

	if _, err := q.Set("deleted_at = NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the auth policy of tenant %s, org %q: %w",
			row.TenantID, row.OrgID, err)
	}
	r.log.Debug("wrote auth policy",
		logger.String("tenant_id", row.TenantID), logger.String("org_id", row.OrgID),
		logger.RequestID(ctx))
	return nil
}

// Remove marks the override of one organization deleted. It runs on the
// caller's transaction.
//
// The row is soft deleted, not dropped: an operator wrote it, and the trail of
// what an organization once enforced answers a question a dropped row cannot.
func (r *Repository) Remove(ctx context.Context, tenantID, orgID string) error {
	r.log.Debug("delete auth policy",
		logger.String("tenant_id", tenantID), logger.String("org_id", orgID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Row)(nil)).
		Where("ap.tenant_id = ?", tenantID).
		Where("ap.org_id = ?", orgID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("remove the auth policy of tenant %s, org %s: %w", tenantID, orgID, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count the written rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: tenant %s, org %s", ErrNotFound, tenantID, orgID)
	}
	r.log.Debug("deleted auth policy",
		logger.String("tenant_id", tenantID), logger.String("org_id", orgID),
		logger.RequestID(ctx))
	return nil
}
