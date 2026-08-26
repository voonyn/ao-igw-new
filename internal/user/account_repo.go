package user

import (
	"context"
	"fmt"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// UpdateProfile writes the four identity columns of one person. It runs on the
// caller's transaction.
//
// It writes fewer columns than UpdateHuman. The phone number is a contact
// field, and the self-service form does not carry it, so a write of it here
// would clear a number the console set.
//
// The write reaches a live account only. The bearer guard reads no store, so a
// token stays valid until it expires, even after the tenant deleted or
// deactivated the account behind it. The predicate on users is what stops such a
// token from still writing a profile.
//
// An account nobody holds, and one that can no longer sign in, both answer
// ErrNoSuchUser.
func (r *Repository) UpdateProfile(ctx context.Context, row Human) error {
	r.log.Debug("update own profile",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("first_name", "last_name", "display_name", "preferred_language").
		Where("tenant_id = ?", row.TenantID).
		Where("user_id = ?", row.UserID).
		Where("EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.tenant_id = ? "+
			"AND u.state = ? AND u.deleted_at IS NULL)", row.UserID, row.TenantID, stateActive).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("update the profile of user %s of tenant %s: %w", row.UserID, row.TenantID, err)
	}
	r.log.Debug("updated own profile",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))
	return oneRow(res, row.TenantID, row.UserID, "update the profile of")
}
