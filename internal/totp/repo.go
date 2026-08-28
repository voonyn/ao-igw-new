package totp

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// Repository holds the TOTP factor of every tenant. It runs the SQL and nothing
// else: no code verification, no secret generation, and no policy rule.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// Clear destroys the TOTP factor of one person: the shared secret and every
// Recovery Code behind it. It runs on the caller's transaction.
//
// Both deletes are hard. The secret is a credential the client cannot recover,
// and a marked row would keep it readable under the same primary key. This is
// what makes an administrator reset final: a returned device cannot sign in
// with the old Authenticator. See docs/adr/0009-hard-delete-the-totp-factor.md.
//
// A person who holds no factor is the normal outcome, so no row is not an
// error.
//
// ForceDelete is the belt beside the braces. Neither model carries deleted_at
// today, so bun already emits a DELETE. The call keeps the delete hard on the
// day somebody adds the column back to a model.
func (r *Repository) Clear(ctx context.Context, tenantID, userID string) error {
	r.log.Debug("clear the totp factor",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

	conn := db.Conn(ctx, r.db)

	if _, err := conn.NewDelete().
		Model((*Enrolment)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		ForceDelete().
		Exec(ctx); err != nil {
		return fmt.Errorf("clear the totp factor of user %s of tenant %s: %w", userID, tenantID, err)
	}

	if _, err := conn.NewDelete().
		Model((*RecoveryCode)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		ForceDelete().
		Exec(ctx); err != nil {
		return fmt.Errorf("clear the recovery codes of user %s of tenant %s: %w", userID, tenantID, err)
	}

	r.log.Debug("cleared the totp factor",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))
	return nil
}
