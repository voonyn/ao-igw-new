package passkey

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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

// HasAny reports whether one person holds at least one live Passkey.
//
// The password step reads it to name the Pending Steps, so it counts and reads
// no blob. List answers the same question, and it would carry every stored
// public key across the wire on every sign-in to do it.
//
// The row carries deleted_at, so bun narrows the read to the live rows on its
// own. A revoked Passkey therefore stops routing a person to the challenge at
// once.
func (r *Repository) HasAny(ctx context.Context, tenantID, userID string) (bool, error) {
	r.log.Debug("count the passkeys",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

	held, err := db.Conn(ctx, r.db).NewSelect().
		Model((*Credential)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("count the passkeys of user %s of tenant %s: %w",
			userID, tenantID, err)
	}

	r.log.Debug("counted the passkeys",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Bool("held", held), logger.RequestID(ctx))
	return held, nil
}

// Insert writes one registered Passkey. It runs on the caller's transaction, so
// the row and the audit event land together.
//
// The primary key is (tenant_id, credential_id), so two registrations of one id
// that race cannot both land. Both reads find no row, both are told to insert,
// and the loser meets the key. That is a refusal and not a fault, so it answers
// ErrDuplicateDevice, which is what the revive path answers the same race. Every
// other write error travels up wrapped.
func (r *Repository) Insert(ctx context.Context, row Credential) error {
	r.log.Debug("insert a passkey",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		if db.IsUniqueViolation(err) {
			return ErrDuplicateDevice
		}
		return fmt.Errorf("insert the passkey of user %s of tenant %s: %w",
			row.UserID, row.TenantID, err)
	}

	r.log.Debug("inserted a passkey",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))
	return nil
}

// FindByCredential reads one row by its credential id, removed rows included.
//
// The read is not narrowed to a person, and it is not narrowed to the live
// rows. Both are deliberate. The primary key is (tenant_id, credential_id), so
// a row of another person and a row somebody removed each block an insert of
// the same id, and the caller decides which of the two happened.
//
// A row nobody registered answers ErrNotFound, which is the normal answer for a
// device this tenant never saw.
func (r *Repository) FindByCredential(
	ctx context.Context, tenantID string, credID []byte,
) (Credential, error) {
	r.log.Debug("find a passkey by its credential id",
		logger.String("tenant_id", tenantID),
		logger.String("credential_id", credentialID(credID)), logger.RequestID(ctx))

	var row Credential
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		WhereAllWithDeleted().
		Where("tenant_id = ?", tenantID).
		Where("credential_id = ?", credID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrNotFound
	}
	if err != nil {
		return Credential{}, fmt.Errorf("find the passkey of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("found a passkey by its credential id",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", row.UserID), logger.RequestID(ctx))
	return row, nil
}

// Revive rewrites a removed row as a fresh registration and clears the delete
// mark. It runs on the caller's transaction.
//
// The primary key is (tenant_id, credential_id), so the row a person removed
// still holds the id of the device. A person who registers that device again
// takes the row back, with the new public key, the new name, and no memory of
// the last use.
//
// The write demands a delete mark. It is the guard on the read the caller made
// before the transaction opened: two registrations of one id that race meet the
// primary key on the insert path, and they meet this predicate here. A write
// that touches no row answers ErrDuplicateDevice, because the only way a removed
// row is no longer removed is that another registration took it first.
func (r *Repository) Revive(ctx context.Context, row Credential) error {
	r.log.Debug("revive a passkey",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("user_id", "rp_id", "credential", "name", "created_at").
		Set("last_used_at = NULL").
		Set("deleted_at = NULL").
		WhereAllWithDeleted().
		Where("tenant_id = ?", row.TenantID).
		Where("credential_id = ?", row.CredentialID).
		Where("deleted_at IS NOT NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("revive the passkey of user %s of tenant %s: %w",
			row.UserID, row.TenantID, err)
	}
	if touched, err := res.RowsAffected(); err == nil && touched == 0 {
		return ErrDuplicateDevice
	}

	r.log.Debug("revived a passkey",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.UserID),
		logger.RequestID(ctx))
	return nil
}

// Touch writes back what one successful assertion changed: the stored blob,
// which carries the new sign counter and the new backup state, and the moment
// the Passkey was last used. It runs on the caller's transaction, so the
// write-back and the session completion land together.
//
// The write is narrowed to the tenant, to the person, and to the live rows. A
// Passkey somebody removed while the ceremony ran signs nobody in, so a write
// that touches no row answers ErrNotFound and the sign-in is refused.
func (r *Repository) Touch(
	ctx context.Context, tenantID, userID string, credID []byte, record string,
) error {
	r.log.Debug("touch a passkey",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.String("credential_id", credentialID(credID)), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Credential)(nil)).
		Set("credential = ?", record).
		Set("last_used_at = ?", time.Now().UTC()).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("credential_id = ?", credID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("touch the passkey of user %s of tenant %s: %w", userID, tenantID, err)
	}
	if touched, err := res.RowsAffected(); err == nil && touched == 0 {
		return ErrNotFound
	}

	r.log.Debug("touched a passkey",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))
	return nil
}

// Rename writes the new name of one live Passkey of one person.
//
// The write is narrowed to the tenant and to the person, so nobody renames a
// device of another account. A write that touches no row answers ErrNotFound.
func (r *Repository) Rename(
	ctx context.Context, tenantID, userID string, credID []byte, name string,
) error {
	r.log.Debug("rename a passkey",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.String("credential_id", credentialID(credID)), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Credential)(nil)).
		Set("name = ?", name).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("credential_id = ?", credID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("rename the passkey of user %s of tenant %s: %w", userID, tenantID, err)
	}
	if touched, err := res.RowsAffected(); err == nil && touched == 0 {
		return ErrNotFound
	}

	r.log.Debug("renamed a passkey",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))
	return nil
}

// Delete marks one live Passkey of one person as removed. It runs on the
// caller's transaction, so the row and the audit event land together.
//
// The row carries deleted_at, so bun turns this into an update. The row stays,
// which is what lets the same device register again later.
//
// The write is narrowed to the tenant and to the person. A write that touches no
// row answers ErrNotFound.
func (r *Repository) Delete(
	ctx context.Context, tenantID, userID string, credID []byte,
) error {
	r.log.Debug("delete a passkey",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.String("credential_id", credentialID(credID)), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Credential)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("credential_id = ?", credID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete the passkey of user %s of tenant %s: %w", userID, tenantID, err)
	}
	if touched, err := res.RowsAffected(); err == nil && touched == 0 {
		return ErrNotFound
	}

	r.log.Debug("deleted a passkey",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))
	return nil
}
