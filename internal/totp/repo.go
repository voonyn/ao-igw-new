package totp

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

// ErrNoEnrolment reports a person who holds no row in user_totp: neither an
// active Second Factor nor a pending enrolment.
var ErrNoEnrolment = errors.New("no totp enrolment")

// Find reads the TOTP row of one person. It returns ErrNoEnrolment on a miss,
// which is the normal state of an account that holds no Second Factor.
func (r *Repository) Find(ctx context.Context, tenantID, userID string) (Enrolment, error) {
	r.log.Debug("read the totp enrolment",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

	var row Enrolment
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Enrolment{}, ErrNoEnrolment
	}
	if err != nil {
		return Enrolment{}, fmt.Errorf("read the totp enrolment of user %s of tenant %s: %w",
			userID, tenantID, err)
	}

	r.log.Debug("read the totp enrolment",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Bool("active", row.Active()), logger.RequestID(ctx))
	return row, nil
}

// HasActiveFactor reports whether one person holds an active TOTP Enrolment.
//
// It counts TOTP and nothing else. The derived column on the user list also
// counts passkeys, and no passkey backend exists, so a read of that column would
// send a person to a challenge nothing can answer.
func (r *Repository) HasActiveFactor(ctx context.Context, tenantID, userID string) (bool, error) {
	r.log.Debug("count the active totp factor",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

	held, err := db.Conn(ctx, r.db).NewSelect().
		Model((*Enrolment)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("activated_at IS NOT NULL").
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("count the active totp factor of user %s of tenant %s: %w",
			userID, tenantID, err)
	}

	r.log.Debug("counted the active totp factor",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Bool("active", held), logger.RequestID(ctx))
	return held, nil
}

// SavePending writes the pending enrolment of one person: a fresh secret, no
// activation, and no spent step.
//
// A person who abandoned a setup starts again over the same primary key, so an
// update comes first. It names activated_at IS NULL, so it can only ever replace
// a pending secret.
//
// No pending row matched means one of two things, and the insert tells them
// apart. No row at all is inserted. An active row gives a duplicate key, and
// that gives ErrAlreadyEnrolled: a person removes the factor they hold before
// they enrol another, and a start that answered a secret the database never
// stored would hand out a dead enrolment.
//
// The secret is a credential. Only the user id reaches a log line.
func (r *Repository) SavePending(ctx context.Context, tenantID, userID string, secret []byte) error {
	r.log.Debug("write the pending totp enrolment",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

	conn := db.Conn(ctx, r.db)

	res, err := conn.NewUpdate().
		Model((*Enrolment)(nil)).
		Set("secret_encrypted = ?", secret).
		Set("last_step = 0").
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("activated_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("replace the pending totp enrolment of user %s of tenant %s: %w",
			userID, tenantID, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("replace the pending totp enrolment of user %s of tenant %s: %w",
			userID, tenantID, err)
	}

	if rows == 0 {
		row := Enrolment{TenantID: tenantID, UserID: userID, SecretEncrypted: secret}
		_, err := conn.NewInsert().
			Model(&row).
			Column("tenant_id", "user_id", "secret_encrypted").
			Exec(ctx)
		if db.IsUniqueViolation(err) {
			return ErrAlreadyEnrolled
		}
		if err != nil {
			return fmt.Errorf("write the pending totp enrolment of user %s of tenant %s: %w",
				userID, tenantID, err)
		}
	}

	r.log.Debug("wrote the pending totp enrolment",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))
	return nil
}

// Activate turns the pending enrolment of one person into an active Second
// Factor, and spends the time step the code proved. It runs on the caller's
// transaction.
//
// The update names the secret the caller verified, so only the secret a code
// proved is ever activated. Without it, a start that landed between the read and
// this write would make a secret nobody proved the active factor, and the person
// would be locked out of their own account.
//
// The update also names activated_at IS NULL, so an enrolment that another
// request already activated is not activated twice. No row updated gives
// ErrNoEnrolment.
func (r *Repository) Activate(
	ctx context.Context, tenantID, userID string, secret []byte, step int64,
) error {
	r.log.Debug("activate the totp enrolment",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Enrolment)(nil)).
		Set("activated_at = ?", time.Now().UTC()).
		Set("last_step = ?", step).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("activated_at IS NULL").
		Where("secret_encrypted = ?", secret).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("activate the totp enrolment of user %s of tenant %s: %w",
			userID, tenantID, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("activate the totp enrolment of user %s of tenant %s: %w",
			userID, tenantID, err)
	}
	if rows == 0 {
		return ErrNoEnrolment
	}

	r.log.Debug("activated the totp enrolment",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.RequestID(ctx))
	return nil
}

// ReplaceRecoveryCodes voids every Recovery Code of one person and stores the
// new set. It runs on the caller's transaction.
//
// The rows hold digests, never the codes. The delete is hard: a spent or voided
// code must leave no row that a later read could match.
func (r *Repository) ReplaceRecoveryCodes(
	ctx context.Context, tenantID, userID string, digests []string,
) error {
	r.log.Debug("replace the recovery codes",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Int("codes", len(digests)), logger.RequestID(ctx))

	conn := db.Conn(ctx, r.db)

	if _, err := conn.NewDelete().
		Model((*RecoveryCode)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		ForceDelete().
		Exec(ctx); err != nil {
		return fmt.Errorf("void the recovery codes of user %s of tenant %s: %w", userID, tenantID, err)
	}

	rows := make([]RecoveryCode, 0, len(digests))
	for _, digest := range digests {
		rows = append(rows, RecoveryCode{TenantID: tenantID, UserID: userID, CodeHash: digest})
	}
	if len(rows) == 0 {
		return nil
	}

	if _, err := conn.NewInsert().
		Model(&rows).
		Column("tenant_id", "user_id", "code_hash").
		Exec(ctx); err != nil {
		return fmt.Errorf("store the recovery codes of user %s of tenant %s: %w", userID, tenantID, err)
	}

	r.log.Debug("replaced the recovery codes",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Int("codes", len(rows)), logger.RequestID(ctx))
	return nil
}
