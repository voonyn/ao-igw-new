package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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

// FindCredential reads the organization of one live person and the bcrypt hash
// of their stored password, in one query.
//
// It is the one read that verifies a password, and both callers take it. The
// sign-in reads the hash, and a password change reads the hash to prove that the
// caller holds the current password, and the organization to name the level
// whose policy the new password is checked against. One predicate serves both:
// two copies of it would drift, and a drifted authentication predicate is a
// security defect.
//
// An inactive account, a locked account, a soft-deleted account, and a machine
// account all answer ErrNotFound. A disabled person therefore cannot sign in
// with a session the identifier step opened before, and a token that outlived
// the account it names changes no password.
//
// The hash is a credential. It never reaches a log line and never leaves this
// package in a response.
func (r *Repository) FindCredential(ctx context.Context, tenantID, userID string) (User, error) {
	r.log.Debug("read credential",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	var row User
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		ColumnExpr("u.id, u.tenant_id, u.org_id").
		ColumnExpr("h.password_hash AS password_hash").
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.tenant_id = ?", tenantID).
		Where("u.id = ?", userID).
		Where("u.state = ?", stateActive).
		Where("u.user_type = ?", typeHuman).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, fmt.Errorf("%w: tenant %s, user %s", ErrNotFound, tenantID, userID)
	}
	if err != nil {
		return User{}, fmt.Errorf("read the credential of user %s of tenant %s: %w", userID, tenantID, err)
	}

	r.log.Debug("read the credential",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))
	return row, nil
}

// HasPassword reports whether one live person of a tenant holds a stored
// password. It answers a boolean and never the hash, so no caller of it handles
// a credential.
//
// It filters neither the state nor the lock, because the question is what the
// row holds and not who can sign in. The administrative guard that reads it
// refuses the removal of the last Identity Link of a person whose password_hash
// is NULL, and a deactivated person of that shape is locked out for ever by the
// same removal.
//
// A machine account and an account the tenant does not hold both answer false.
// Neither holds a user_humans row, so neither holds a password.
func (r *Repository) HasPassword(ctx context.Context, tenantID, userID string) (bool, error) {
	r.log.Debug("read whether the person holds a password",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	held, err := db.Conn(ctx, r.db).NewSelect().
		Model((*User)(nil)).
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.tenant_id = ?", tenantID).
		Where("u.id = ?", userID).
		Where("h.password_hash IS NOT NULL").
		Where("h.password_hash <> ''").
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether user %s of tenant %s holds a password: %w",
			userID, tenantID, err)
	}

	r.log.Debug("read whether the person holds a password",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Bool("held", held), logger.RequestID(ctx))
	return held, nil
}

// SetPassword writes the new bcrypt hash of one person, stamps the change, and
// clears the flag that forces a change at the next sign-in. It runs on the
// caller's transaction.
//
// The predicate on users is the one UpdateProfile carries, for the same reason:
// the bearer guard reads no store, so a token stays valid until it expires, and
// the query is what refuses an account that can no longer sign in.
//
// The hash is written and never read back. The password itself never reaches
// this layer.
func (r *Repository) SetPassword(ctx context.Context, tenantID, userID, hash string) error {
	r.log.Debug("set password",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Human)(nil)).
		Set("password_hash = ?", hash).
		Set("password_changed_at = ?", time.Now().UTC()).
		Set("password_change_required = ?", false).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.tenant_id = ? "+
			"AND u.state = ? AND u.deleted_at IS NULL)", userID, tenantID, stateActive).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("set the password of user %s of tenant %s: %w", userID, tenantID, err)
	}
	r.log.Debug("set the password",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))
	return oneRow(res, tenantID, userID, "set the password of")
}
