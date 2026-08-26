package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/utils"
)

// ErrConsentNotFound reports that the person gave no live consent to the client
// the request names. A consent of somebody else answers the same way, so the
// refusal never says which applications another person connected.
var ErrConsentNotFound = errors.New("consent not found")

// ConsentRepository reads and writes the remembered consent of one tenant.
type ConsentRepository struct {
	db  *bun.DB
	log logger.Logger
}

func NewConsentRepository(bdb *bun.DB, log logger.Logger) *ConsentRepository {
	return &ConsentRepository{db: bdb, log: log}
}

// Find reads what the database knows about one person and one client: whether
// the tenant owns the client, and the scopes the person approved before now.
//
// The two facts come from one query, because the consent gate needs both and
// neither is useful alone. A client with no consent row is the normal first
// visit, so the row is optional and its absence is no error.
func (r *ConsentRepository) Find(
	ctx context.Context, tenantID, userID, clientID string,
) (ConsentState, error) {
	r.log.Debug("read consent",
		logger.String("tenant_id", tenantID), logger.String("client_id", clientID), logger.RequestID(ctx))

	var row struct {
		IsFirstParty bool   `bun:"is_first_party"`
		Scopes       string `bun:"scopes"`
	}
	err := db.Conn(ctx, r.db).NewSelect().
		TableExpr("application_oidc_configs AS c").
		ColumnExpr("c.is_first_party").
		ColumnExpr("COALESCE(uc.scopes, '') AS scopes").
		Join("LEFT JOIN oidc_user_consents AS uc").
		JoinOn("uc.tenant_id = c.tenant_id AND uc.client_id = c.client_id").
		JoinOn("uc.user_id = ? AND uc.deleted_at IS NULL", userID).
		Where("c.tenant_id = ?", tenantID).
		Where("c.client_id = ?", clientID).
		Where("c.deleted_at IS NULL").
		Scan(ctx, &row)
	if errors.Is(err, sql.ErrNoRows) {
		return ConsentState{}, fmt.Errorf("%w: tenant %s, client %s", ErrClientNotFound, tenantID, clientID)
	}
	if err != nil {
		return ConsentState{}, fmt.Errorf("read consent of client %s in tenant %s: %w", clientID, tenantID, err)
	}

	return ConsentState{FirstParty: row.IsFirstParty, Scopes: strings.Fields(row.Scopes)}, nil
}

// Save writes the scopes one person allows one client. The unique key holds one
// live row per person and client, so a second answer updates the first.
func (r *ConsentRepository) Save(
	ctx context.Context, tenantID, userID, clientID string, scopes []string,
) error {
	r.log.Debug("write consent",
		logger.String("tenant_id", tenantID), logger.String("client_id", clientID), logger.RequestID(ctx))

	row := &UserConsent{
		ID:       utils.NewUUIDv7(),
		TenantID: tenantID,
		UserID:   userID,
		ClientID: clientID,
		Scopes:   strings.Join(scopes, " "),
	}
	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(row).
		On("DUPLICATE KEY UPDATE").
		Set("scopes = VALUES(scopes)").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write consent of client %s in tenant %s: %w", clientID, tenantID, err)
	}
	return nil
}

// consentClientJoin reads the client one consent names. It is a LEFT JOIN: a
// consent whose client is gone must still be listed, so the person can take it
// back.
const consentClientJoin = `LEFT JOIN application_oidc_configs AS c
	ON c.tenant_id = uc.tenant_id AND c.client_id = uc.client_id AND c.deleted_at IS NULL`

// liveGrantExists reports a grant of the same person and the same client that
// has not expired. It is a correlated subquery, so the read stays one round trip
// and answers one boolean per row.
//
// A NULL expiry counts as live. The column holds the refresh token expiry, and
// it is NULL when the grant carries no refresh token, so a NULL says that no
// deadline passed and not that one did. The self-service session read applies
// the same rule to a session with no deadline.
const liveGrantExists = `EXISTS (
	SELECT 1 FROM oidc_grants AS g
	 WHERE g.tenant_id = uc.tenant_id
	   AND g.client_id = uc.client_id
	   AND g.subject = uc.user_id
	   AND (g.expires_at IS NULL OR g.expires_at > NOW(3))
) AS has_grant`

// ListBySubject reads the live consents of one person, newest first.
//
// The list is bounded by how many applications one person connected, so it pages
// nothing and answers whole.
//
// An empty subject reads nothing. The bearer guard verified the subject, so this
// cannot happen. It costs one comparison to make sure that a missing subject
// never reads the consents of every person in the tenant.
func (r *ConsentRepository) ListBySubject(
	ctx context.Context, tenantID, userID string,
) ([]ConnectionRecord, error) {
	r.log.Debug("list own consents",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if userID == "" {
		r.log.Debug("listed own consents",
			logger.String("tenant_id", tenantID), logger.Int("rows", 0), logger.RequestID(ctx))
		return nil, nil
	}

	var rows []ConnectionRecord
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("uc.client_id, uc.scopes, uc.created_at, uc.updated_at").
		ColumnExpr("COALESCE(a.name, '') AS app_name").
		ColumnExpr(liveGrantExists).
		Join(consentClientJoin).
		Join(grantAppJoin).
		Where("uc.tenant_id = ?", tenantID).
		Where("uc.user_id = ?", userID).
		Order("uc.created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the consents of user %s in tenant %s: %w", userID, tenantID, err)
	}

	r.log.Debug("listed own consents",
		logger.String("tenant_id", tenantID), logger.Int("rows", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// DeleteForSubject withdraws the consent one person gave one client.
//
// The write is a soft delete, and the unique key of the table is functional over
// deleted_at. A withdrawn row therefore keeps its own key value, and the same
// person consenting to the same client again inserts a new live row instead of
// colliding with the old one.
//
// The three predicates are the ownership rule. A consent of another person is
// not reachable, whatever the request carries, and a pair with no live consent
// answers ErrConsentNotFound.
func (r *ConsentRepository) DeleteForSubject(
	ctx context.Context, tenantID, userID, clientID string,
) error {
	r.log.Debug("withdraw own consent",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID),
		logger.String("client_id", clientID), logger.RequestID(ctx))

	if userID == "" || clientID == "" {
		return fmt.Errorf("%w: tenant %s, client %s", ErrConsentNotFound, tenantID, clientID)
	}

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*UserConsent)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Where("client_id = ?", clientID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("withdraw the consent of user %s for client %s: %w", userID, clientID, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("withdraw the consent of user %s for client %s: %w", userID, clientID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: tenant %s, client %s", ErrConsentNotFound, tenantID, clientID)
	}

	r.log.Debug("withdrew own consent",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID),
		logger.String("client_id", clientID), logger.RequestID(ctx))
	return nil
}
