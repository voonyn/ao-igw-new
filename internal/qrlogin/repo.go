package qrlogin

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

// Repository holds the QR Login transactions of every tenant. It runs the SQL and
// nothing else: no call to the Scan Verifier, no nonce digest, and no state rule.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// Insert writes one started transaction.
//
// The insert is strict. A duplicate identifier of the Scan Verifier is an error
// and never an upsert, because that unique violation is the replay defence.
func (r *Repository) Insert(ctx context.Context, row Transaction) error {
	r.log.Debug("write qr login transaction",
		logger.String("tenant_id", row.TenantID), logger.RequestID(ctx))

	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column("id", "tenant_id", "login_session_id", "verifier_session_id",
			"verifier_presentation_id", "nonce_hash", "state", "expires_at").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write qr login transaction %s of tenant %s: %w", row.ID, row.TenantID, err)
	}

	r.log.Debug("wrote qr login transaction",
		logger.String("tenant_id", row.TenantID), logger.String("session_id", row.LoginSessionID),
		logger.RequestID(ctx))
	return nil
}

// FindByVerifierRef reads the transaction the push callback names.
//
// It is the one read of this deployment that names no tenant. The push arrives at
// one fixed address with no host to resolve a tenant from, so this read is what
// supplies the tenant every later call is scoped by. Both identifiers are
// globally unique, which is what makes that safe.
//
// A push that carries both is matched on both. Preferring one silently loses the
// row whenever that half turns out to be an identifier of the verifier's own
// rather than the one this deployment stored.
func (r *Repository) FindByVerifierRef(ctx context.Context, sessionID, presentationID string) (Transaction, error) {
	r.log.Debug("read qr login transaction by verifier reference", logger.RequestID(ctx))

	if sessionID == "" && presentationID == "" {
		return Transaction{}, ErrNotFound
	}

	var row Transaction
	q := db.Conn(ctx, r.db).NewSelect().Model(&row)
	switch {
	case sessionID != "" && presentationID != "":
		q = q.Where("verifier_session_id = ? OR verifier_presentation_id = ?", sessionID, presentationID)
	case sessionID != "":
		q = q.Where("verifier_session_id = ?", sessionID)
	default:
		q = q.Where("verifier_presentation_id = ?", presentationID)
	}
	err := q.Limit(1).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Transaction{}, ErrNotFound
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("read qr login transaction by verifier reference: %w", err)
	}

	r.log.Debug("read qr login transaction by verifier reference",
		logger.String("tenant_id", row.TenantID), logger.RequestID(ctx))
	return row, nil
}

// FindByLoginSession reads the newest transaction of one login session. The poll
// reads it.
func (r *Repository) FindByLoginSession(ctx context.Context, tenantID, loginSessionID string) (Transaction, error) {
	r.log.Debug("read qr login transaction",
		logger.String("tenant_id", tenantID), logger.String("session_id", loginSessionID),
		logger.RequestID(ctx))

	var row Transaction
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("login_session_id = ?", loginSessionID).
		Order("id DESC").
		Limit(1).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Transaction{}, ErrNotFound
	}
	if err != nil {
		return Transaction{}, fmt.Errorf("read qr login transaction of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("read qr login transaction",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))
	return row, nil
}

// Consume claims one pending, unexpired, unconsumed transaction in one guarded
// update. A second push, and a retry of the same push, change nothing.
//
// It returns ErrNotFound when the guard matches no row. Unknown, expired, and
// already consumed collapse into that one answer.
func (r *Repository) Consume(ctx context.Context, tenantID, id string, now time.Time) error {
	r.log.Debug("claim qr login transaction",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Transaction)(nil)).
		Set("consumed_at = ?", now).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", id).
		Where("consumed_at IS NULL").
		Where("state = ?", StatePending).
		Where("expires_at > ?", now).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("claim qr login transaction %s of tenant %s: %w", id, tenantID, err)
	}
	claimed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("claim qr login transaction %s of tenant %s: %w", id, tenantID, err)
	}
	if claimed == 0 {
		return ErrNotFound
	}

	r.log.Debug("claimed qr login transaction",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))
	return nil
}

// SetResult records the outcome on a claimed transaction. userID is written only
// for a verified one.
func (r *Repository) SetResult(ctx context.Context, tenantID, id string, state int, userID string) error {
	r.log.Debug("record qr login result",
		logger.String("tenant_id", tenantID), logger.Int("state", state), logger.RequestID(ctx))

	q := db.Conn(ctx, r.db).NewUpdate().
		Model((*Transaction)(nil)).
		Set("state = ?", state).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", id)
	if userID != "" {
		q = q.Set("user_id = ?", userID)
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("record qr login result of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("recorded qr login result",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))
	return nil
}
