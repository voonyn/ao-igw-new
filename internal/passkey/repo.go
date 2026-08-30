package passkey

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// Repository holds the Passkeys of every tenant. It runs the SQL and nothing
// else: no ceremony, no verification, and no policy rule.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// List reads the live Passkeys of one person, oldest first.
//
// The row carries deleted_at, so bun narrows the read to the live rows on its
// own. A person who holds none reads an empty list, which is the normal state of
// an account that never registered a device.
func (r *Repository) List(ctx context.Context, tenantID, userID string) ([]Credential, error) {
	r.log.Debug("list the passkeys",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

	rows := make([]Credential, 0)
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Order("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the passkeys of user %s of tenant %s: %w",
			userID, tenantID, err)
	}

	r.log.Debug("listed the passkeys",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Int("count", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// Insert writes one registered Passkey. It runs on the caller's transaction, so
// the row and the audit event land together.
func (r *Repository) Insert(ctx context.Context, row Credential) error {
	r.log.Debug("insert a passkey",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("insert the passkey of user %s of tenant %s: %w",
			row.UserID, row.TenantID, err)
	}

	r.log.Debug("inserted a passkey",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))
	return nil
}
