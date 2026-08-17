package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrLoginSessionNotFound reports that no live session of the tenant carries the
// token digest. An expired session and a terminated one answer alike.
var ErrLoginSessionNotFound = errors.New("login session not found")

// Row is one row of login_sessions. Data holds the sealed LoginSession, which
// is the authority. The other columns are extracted copies, so the database can
// find the row and an operator can read it.
//
// TokenHash holds a SHA-256 digest, never the token. A leaked row cannot
// credential a request.
//
// The table records the fact of a login, so a row is terminated, never soft
// deleted. See the ao-db-migration skill.
type Row struct {
	bun.BaseModel `bun:"table:login_sessions"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	UserID   string `bun:"user_id,nullzero"`
	State    int    `bun:"state"`

	TokenHash string `bun:"token_hash"`
	Data      []byte `bun:"data"`

	ExpiresAt    time.Time `bun:"expires_at"`
	TerminatedAt time.Time `bun:"terminated_at,nullzero"`
}

// Repository holds the login sessions of every tenant. The cipher seals the
// session at rest. A nil cipher matches the development bootstrap, which stores
// the session as plain JSON.
type Repository struct {
	db     *bun.DB
	cipher *aocrypto.Cipher
	log    logger.Logger
}

func NewRepository(bdb *bun.DB, cipher *aocrypto.Cipher, log logger.Logger) *Repository {
	return &Repository{db: bdb, cipher: cipher, log: log}
}

// Save writes one login session under one token digest. Every factor upgrade
// rotates the token and saves the same session id again, so the write is an
// upsert.
//
// prevTokenHash is not used here. The upsert replaces token_hash on the same
// row, so the old digest stops matching by itself. Only the cache needs to be
// told, and CachingSaver does that.
func (r *Repository) Save(ctx context.Context, live LoginSession, tokenHash, _ string) error {
	r.log.Debug("save login session",
		logger.String("tenant_id", live.TenantID), logger.String("session_id", live.ID))

	// The service logs this failure where it stops bubbling, so the repository
	// only wraps it.
	row, err := seal(live, tokenHash, r.cipher)
	if err != nil {
		return err
	}
	_, err = db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		On("DUPLICATE KEY UPDATE").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("save login session %s of tenant %s: %w", live.ID, live.TenantID, err)
	}

	r.log.Debug("saved login session",
		logger.String("tenant_id", live.TenantID), logger.String("session_id", live.ID))
	return nil
}

// FindByTokenHash reads the live session one token digest credentials. A
// terminated session and an expired one are misses, so a dead token never
// resolves.
func (r *Repository) FindByTokenHash(ctx context.Context, tenantID, tokenHash string) (LoginSession, error) {
	r.log.Debug("read login session", logger.String("tenant_id", tenantID))

	var row Row
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("token_hash = ?", tokenHash).
		Where("state = ?", StateActive).
		Where("expires_at > ?", time.Now().UTC()).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginSession{}, fmt.Errorf("%w: tenant %s", ErrLoginSessionNotFound, tenantID)
	}
	if err != nil {
		return LoginSession{}, fmt.Errorf("read login session of tenant %s: %w", tenantID, err)
	}

	// The service logs this failure where it stops bubbling, so the repository
	// only wraps it.
	live, err := open(row, r.cipher)
	if err != nil {
		return LoginSession{}, err
	}

	r.log.Debug("read login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", row.ID))
	return live, nil
}

// Terminate ends one live login session and answers with the token digest the
// row held. The caller drops the cache entry of that digest, which is the only
// place the digest is known after the row is terminated.
//
// The row records the fact of a login, so it is terminated and never deleted.
// A session that is already terminated, and one that expired, are both misses:
// there is nothing left to end.
func (r *Repository) Terminate(ctx context.Context, tenantID, sessionID string) (string, error) {
	r.log.Debug("terminate login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", sessionID))

	var row Row
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("id = ?", sessionID).
		Where("tenant_id = ?", tenantID).
		Where("state = ?", StateActive).
		Where("expires_at > ?", time.Now().UTC()).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: tenant %s, session %s", ErrLoginSessionNotFound, tenantID, sessionID)
	}
	if err != nil {
		return "", fmt.Errorf("read login session %s of tenant %s: %w", sessionID, tenantID, err)
	}

	if _, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Row)(nil)).
		Set("state = ?", StateTerminated).
		Set("terminated_at = ?", time.Now().UTC()).
		Where("id = ?", sessionID).
		Where("tenant_id = ?", tenantID).
		Exec(ctx); err != nil {
		return "", fmt.Errorf("terminate login session %s of tenant %s: %w", sessionID, tenantID, err)
	}

	r.log.Debug("terminated login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", sessionID))
	return row.TokenHash, nil
}

// seal turns one login session into the row that holds it. The row carries the
// sealed session plus the columns the lookups and an operator need.
func seal(live LoginSession, tokenHash string, cipher *aocrypto.Cipher) (Row, error) {
	data, err := aocrypto.SealJSON(cipher, live)
	if err != nil {
		return Row{}, fmt.Errorf("seal login session %s: %w", live.ID, err)
	}
	return Row{
		ID:        live.ID,
		TenantID:  live.TenantID,
		UserID:    live.UserID,
		State:     StateActive,
		TokenHash: tokenHash,
		Data:      data,
		ExpiresAt: live.ExpiresAt,
	}, nil
}

// open reads the sealed login session back. The row columns are copies, so the
// sealed value alone answers the caller.
func open(row Row, cipher *aocrypto.Cipher) (LoginSession, error) {
	var live LoginSession
	if err := aocrypto.OpenJSON(cipher, row.Data, &live); err != nil {
		return LoginSession{}, fmt.Errorf("open login session %s: %w", row.ID, err)
	}
	return live, nil
}
