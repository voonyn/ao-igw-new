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
