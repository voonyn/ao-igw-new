package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/uptrace/bun"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrGrantNotFound reports that no grant of the tenant carries the id, the
// authorization code, or the refresh token. The protocol engine turns it into
// goidc.ErrNotFound.
var ErrGrantNotFound = errors.New("grant not found")

// ErrSessionNotFound reports that no authn session of the tenant carries the
// id. The protocol engine turns it into goidc.ErrNotFound.
var ErrSessionNotFound = errors.New("authn session not found")

// ErrRefreshTokenReused reports a refresh token that was already rotated away.
// A caller matches it with errors.Is, and reads the grant it belongs to from
// the ReuseError below.
var ErrRefreshTokenReused = errors.New("refresh token was already used")

// ReuseError reports one replay, and names the grant the replayed token
// belonged to. The token itself is never carried, because the token is the
// credential: the caller records the grant instead.
type ReuseError struct {
	GrantID  string
	ClientID string
	Subject  string
}

func (e *ReuseError) Error() string {
	return fmt.Sprintf("%s: grant %s", ErrRefreshTokenReused, e.GrantID)
}

// Is matches the sentinel, so a caller that only needs the class of the failure
// does not name the type.
func (e *ReuseError) Is(target error) bool { return target == ErrRefreshTokenReused }

// ClaimSessionID names the login session a grant came from. It is the key the
// grant store holds it under, and the name of the ID token claim that publishes
// it. OpenID Connect Session Management defines the claim.
const ClaimSessionID = "sid"

// supersededFallbackLifetime bounds a superseded digest whose grant carried no
// refresh token deadline. It repeats the 30-day default migration 00037
// shipped, because a row with no bound would be retained forever.
const supersededFallbackLifetime = 30 * 24 * time.Hour

// supersededPruneBatch bounds one sweep of expired records. Every rotation
// sweeps, so a small batch drains faster than the traffic fills it, and no
// single request pays for a large delete.
const supersededPruneBatch = 200

// StorageRepository holds the protocol state of one tenant: its grants and its
// authn sessions. The cipher seals the state at rest. A nil cipher matches the
// development bootstrap, which stores the state as plain JSON.
type StorageRepository struct {
	db     *bun.DB
	cipher *aocrypto.Cipher
	log    logger.Logger
}

func NewStorageRepository(bdb *bun.DB, cipher *aocrypto.Cipher, log logger.Logger) *StorageRepository {
	return &StorageRepository{db: bdb, cipher: cipher, log: log}
}

// SaveGrant writes one grant of one tenant. The engine saves the same grant
// again on every rotation and on code redemption, so the write is an upsert.
func (r *StorageRepository) SaveGrant(ctx context.Context, tenantID string, grant *goidc.Grant) error {
	r.log.Debug("save grant",
		logger.String("tenant_id", tenantID), logger.String("grant_id", grant.ID), logger.RequestID(ctx))

	row, err := sealGrant(tenantID, grant, r.cipher)
	if err != nil {
		r.log.Error("seal grant",
			logger.String("tenant_id", tenantID),
			logger.String("grant_id", grant.ID),
			logger.Err(err))
		return err
	}

	if err := r.retainSuperseded(ctx, tenantID, grant); err != nil {
		return err
	}

	_, err = db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		On("DUPLICATE KEY UPDATE").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("save grant %s of tenant %s: %w", grant.ID, tenantID, err)
	}

	r.log.Debug("saved grant",
		logger.String("tenant_id", tenantID), logger.String("grant_id", grant.ID), logger.RequestID(ctx))
	return nil
}

// retainSuperseded records the refresh token this save replaces, and sweeps a
// bounded batch of the tenant's expired records. Insertion and deletion run on
// the same traffic, so the table cannot grow faster than it is drained.
//
// A save that finds no stored grant is the first save of that grant, and a save
// that replaces nothing is not a rotation. Both retain nothing.
func (r *StorageRepository) retainSuperseded(ctx context.Context, tenantID string, grant *goidc.Grant) error {
	prev, err := r.findGrant(ctx, tenantID, "id", grant.ID)
	if errors.Is(err, ErrGrantNotFound) {
		return nil
	}
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	row, ok := supersede(tenantID, prev, grant, now)
	if !ok {
		return nil
	}

	if _, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		On("DUPLICATE KEY UPDATE").
		Exec(ctx); err != nil {
		return fmt.Errorf("retain superseded refresh token of grant %s of tenant %s: %w", grant.ID, tenantID, err)
	}
	r.log.Debug("retained superseded refresh token",
		logger.String("tenant_id", tenantID), logger.String("grant_id", grant.ID), logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*SupersededRefreshToken)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("expires_at < ?", now).
		Limit(supersededPruneBatch).
		Exec(ctx); err != nil {
		return fmt.Errorf("prune superseded refresh tokens of tenant %s: %w", tenantID, err)
	}
	return nil
}

// FindGrant reads one grant of one tenant by its id.
func (r *StorageRepository) FindGrant(ctx context.Context, tenantID, id string) (*goidc.Grant, error) {
	return r.findGrant(ctx, tenantID, "id", id)
}

// FindGrantByAuthCode reads the grant the authorization code belongs to. The
// code itself never reaches the database, only its digest.
func (r *StorageRepository) FindGrantByAuthCode(ctx context.Context, tenantID, code string) (*goidc.Grant, error) {
	return r.findGrant(ctx, tenantID, "auth_code_hash", aocrypto.Digest(code))
}

// FindGrantByRefreshToken reads the grant the refresh token belongs to. The
// token itself never reaches the database, only its digest.
//
// The superseded records are read first. A token that a rotation replaced can
// only be presented by whoever kept a copy, so the whole grant is revoked and
// the read fails with a ReuseError. The successor token dies with it.
func (r *StorageRepository) FindGrantByRefreshToken(ctx context.Context, tenantID, token string) (*goidc.Grant, error) {
	digest := aocrypto.Digest(token)

	var reused SupersededRefreshToken
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&reused).
		Where("tenant_id = ?", tenantID).
		Where("token_hash = ?", digest).
		Scan(ctx)
	if err == nil {
		return nil, r.revokeGrant(ctx, tenantID, reused.GrantID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("read superseded refresh token of tenant %s: %w", tenantID, err)
	}

	return r.findGrant(ctx, tenantID, "refresh_token_hash", digest)
}

// FindGrantsByLoginSession reads every grant one sign-in produced. A logout
// ends them all, so the answer holds the revoked ones too, and the caller skips
// what is already revoked.
//
// An empty session id answers nothing. Such an id names no sign-in, and
// matching on it would read every grant the tenant holds.
func (r *StorageRepository) FindGrantsByLoginSession(
	ctx context.Context, tenantID, sessionID string,
) ([]*goidc.Grant, error) {
	r.log.Debug("read grants of login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", sessionID), logger.RequestID(ctx))

	if sessionID == "" {
		return nil, nil
	}

	var rows []Grant
	if err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID).
		Where("login_session_id = ?", sessionID).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read grants of login session %s of tenant %s: %w",
			sessionID, tenantID, err)
	}

	grants := make([]*goidc.Grant, 0, len(rows))
	for _, row := range rows {
		grant, err := openGrant(row, r.cipher)
		if err != nil {
			r.log.Error("open grant",
				logger.String("tenant_id", tenantID),
				logger.String("grant_id", row.ID),
				logger.Err(err))
			return nil, err
		}
		grants = append(grants, grant)
	}

	r.log.Debug("read grants of login session",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", sessionID),
		logger.Int("grants", len(grants)), logger.RequestID(ctx))
	return grants, nil
}

// revokeGrant ends one grant after a replay, and drops the history of that
// grant: a revoked grant has nothing left to detect. It always answers with a
// ReuseError, which names the grant and never the token.
func (r *StorageRepository) revokeGrant(ctx context.Context, tenantID, grantID string) error {
	r.log.Debug("revoke grant",
		logger.String("tenant_id", tenantID), logger.String("grant_id", grantID),
		logger.RequestID(ctx))

	reuse := &ReuseError{GrantID: grantID}

	grant, err := r.findGrant(ctx, tenantID, "id", grantID)
	if errors.Is(err, ErrGrantNotFound) {
		return reuse
	}
	if err != nil {
		return err
	}
	reuse.ClientID = grant.ClientID
	reuse.Subject = grant.Subject

	if grant.RevokedAt == 0 {
		grant.RevokedAt = int(time.Now().UTC().Unix())
		row, err := sealGrant(tenantID, grant, r.cipher)
		if err != nil {
			return err
		}
		if _, err := db.Conn(ctx, r.db).NewInsert().
			Model(&row).
			On("DUPLICATE KEY UPDATE").
			Exec(ctx); err != nil {
			return fmt.Errorf("revoke grant %s of tenant %s: %w", grantID, tenantID, err)
		}
	}

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*SupersededRefreshToken)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("grant_id = ?", grantID).
		Exec(ctx); err != nil {
		return fmt.Errorf("drop superseded refresh tokens of grant %s of tenant %s: %w", grantID, tenantID, err)
	}

	r.log.Debug("revoked grant",
		logger.String("tenant_id", tenantID), logger.String("grant_id", grantID),
		logger.RequestID(ctx))
	return reuse
}

// findGrant reads one grant by an indexed column. The value is an id or a
// digest, so it is safe to log the column name but never the value.
func (r *StorageRepository) findGrant(ctx context.Context, tenantID, column, value string) (*goidc.Grant, error) {
	r.log.Debug("read grant",
		logger.String("tenant_id", tenantID), logger.String("by", column), logger.RequestID(ctx))

	var row Grant
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("? = ?", bun.Ident(column), value).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: tenant %s, by %s", ErrGrantNotFound, tenantID, column)
	}
	if err != nil {
		return nil, fmt.Errorf("read grant of tenant %s by %s: %w", tenantID, column, err)
	}

	grant, err := openGrant(row, r.cipher)
	if err != nil {
		r.log.Error("open grant",
			logger.String("tenant_id", tenantID),
			logger.String("grant_id", row.ID),
			logger.Err(err))
		return nil, err
	}

	r.log.Debug("read grant",
		logger.String("tenant_id", tenantID), logger.String("grant_id", row.ID), logger.RequestID(ctx))
	return grant, nil
}

// SaveSession writes one authn session of one tenant. The engine saves the same
// session again at each step of the login, so the write is an upsert.
func (r *StorageRepository) SaveSession(ctx context.Context, tenantID string, session *goidc.AuthnSession) error {
	r.log.Debug("save authn session",
		logger.String("tenant_id", tenantID), logger.String("session_id", session.ID), logger.RequestID(ctx))

	row, err := sealSession(tenantID, session, r.cipher)
	if err != nil {
		r.log.Error("seal authn session",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", session.ID),
			logger.Err(err))
		return err
	}
	_, err = db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		On("DUPLICATE KEY UPDATE").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("save authn session %s of tenant %s: %w", session.ID, tenantID, err)
	}

	r.log.Debug("saved authn session",
		logger.String("tenant_id", tenantID), logger.String("session_id", session.ID), logger.RequestID(ctx))
	return nil
}

// FindSession reads one authn session of one tenant by its id.
func (r *StorageRepository) FindSession(ctx context.Context, tenantID, id string) (*goidc.AuthnSession, error) {
	r.log.Debug("read authn session",
		logger.String("tenant_id", tenantID), logger.String("session_id", id), logger.RequestID(ctx))

	var row Session
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", id).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: tenant %s, session %s", ErrSessionNotFound, tenantID, id)
	}
	if err != nil {
		return nil, fmt.Errorf("read authn session %s of tenant %s: %w", id, tenantID, err)
	}

	session, err := openSession(row, r.cipher)
	if err != nil {
		r.log.Error("open authn session",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", id),
			logger.Err(err))
		return nil, err
	}

	r.log.Debug("read authn session",
		logger.String("tenant_id", tenantID), logger.String("session_id", id), logger.RequestID(ctx))
	return session, nil
}

// sealGrant turns one grant into the row that holds it. The row carries the
// sealed grant plus the columns the lookups need.
func sealGrant(tenantID string, grant *goidc.Grant, cipher *aocrypto.Cipher) (Grant, error) {
	data, err := aocrypto.SealJSON(cipher, grant)
	if err != nil {
		return Grant{}, fmt.Errorf("seal grant %s: %w", grant.ID, err)
	}
	sessionID, _ := grant.Store[ClaimSessionID].(string)
	return Grant{
		ID:               grant.ID,
		TenantID:         tenantID,
		ClientID:         grant.ClientID,
		Subject:          grant.Subject,
		LoginSessionID:   sessionID,
		AuthCodeHash:     digestOrEmpty(grant.AuthCode),
		RefreshTokenHash: digestOrEmpty(grant.RefreshToken),
		Data:             data,
		ExpiresAt:        unixTime(later(grant.RefreshTokenExpiresAt, grant.AuthCodeExpiresAt)),
	}, nil
}

// supersede answers what one save retains. The engine rotates in place: it
// replaces the refresh token of the grant it just read, and saves the same
// grant id again. The token that was there before is therefore only knowable
// here, by comparing the stored grant against the incoming one.
//
// It answers false when the save is not a rotation: an unchanged token is
// still live, and a grant that carried no token supersedes nothing.
func supersede(tenantID string, prev, next *goidc.Grant, now time.Time) (SupersededRefreshToken, bool) {
	if prev.RefreshToken == "" || prev.RefreshToken == next.RefreshToken {
		return SupersededRefreshToken{}, false
	}

	expiresAt := unixTime(prev.RefreshTokenExpiresAt)
	if expiresAt.IsZero() {
		expiresAt = now.Add(supersededFallbackLifetime)
	}
	return SupersededRefreshToken{
		TenantID:  tenantID,
		TokenHash: aocrypto.Digest(prev.RefreshToken),
		GrantID:   prev.ID,
		ExpiresAt: expiresAt,
	}, true
}

// openGrant reads the sealed grant back. The row columns are copies, so the
// sealed value alone answers the engine.
func openGrant(row Grant, cipher *aocrypto.Cipher) (*goidc.Grant, error) {
	var grant goidc.Grant
	if err := aocrypto.OpenJSON(cipher, row.Data, &grant); err != nil {
		return nil, fmt.Errorf("open grant %s: %w", row.ID, err)
	}
	return &grant, nil
}

// sealSession turns one authn session into the row that holds it.
func sealSession(tenantID string, session *goidc.AuthnSession, cipher *aocrypto.Cipher) (Session, error) {
	data, err := aocrypto.SealJSON(cipher, session)
	if err != nil {
		return Session{}, fmt.Errorf("seal authn session %s: %w", session.ID, err)
	}
	return Session{
		ID:        session.ID,
		TenantID:  tenantID,
		ClientID:  session.ClientID,
		Subject:   session.Subject,
		Data:      data,
		ExpiresAt: unixTime(session.ExpiresAt),
	}, nil
}

// openSession reads the sealed authn session back.
func openSession(row Session, cipher *aocrypto.Cipher) (*goidc.AuthnSession, error) {
	var session goidc.AuthnSession
	if err := aocrypto.OpenJSON(cipher, row.Data, &session); err != nil {
		return nil, fmt.Errorf("open authn session %s: %w", row.ID, err)
	}
	return &session, nil
}

// digestOrEmpty digests a code or a token. An absent value stays empty, so the
// column stays NULL and never matches a lookup.
func digestOrEmpty(value string) string {
	if value == "" {
		return ""
	}
	return aocrypto.Digest(value)
}

// later returns the deadline that pruning must respect: a grant lives until its
// refresh token expires, or until its authorization code expires when it has no
// refresh token.
func later(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// unixTime turns the seconds count goidc stores into a time. A zero count means
// no deadline, which the column holds as NULL.
func unixTime(secs int) time.Time {
	if secs == 0 {
		return time.Time{}
	}
	return time.Unix(int64(secs), 0).UTC()
}
