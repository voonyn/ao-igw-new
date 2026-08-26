package oidc

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

// ErrClientNotFound reports that no live client of the tenant carries the client
// id. The protocol engine turns it into goidc.ErrNotFound.
var ErrClientNotFound = errors.New("client not found")

// appStateActive is applications.state for an application that serves requests.
const appStateActive = 1

// appTypeOIDC is applications.app_type for an OIDC application. Only an OIDC
// application has a client.
const appTypeOIDC = 1

// clientColumns names every column the Client model holds. The table carries
// more columns than the model does, and a select of them all fails to scan, so
// the list is written out here.
const clientColumns = `c.app_id, c.tenant_id, c.client_id, c.created_at, c.expires_at,
	c.secret, c.secret_expires_at, c.token_authn_method, c.subject_type, c.scopes,
	c.is_first_party, c.redirect_uris, c.grant_types, c.response_types,
	c.post_logout_redirect_uris, c.deleted_at`

// ClientRepository reads the clients of one tenant.
type ClientRepository struct {
	db  *bun.DB
	log logger.Logger
}

func NewClientRepository(bdb *bun.DB, log logger.Logger) *ClientRepository {
	return &ClientRepository{db: bdb, log: log}
}

// FindByClientID reads one client of one tenant. An inactive application, an
// expired row, and a soft-deleted row never come back. A miss returns
// ErrClientNotFound.
func (r *ClientRepository) FindByClientID(ctx context.Context, tenantID, clientID string) (Client, error) {
	r.log.Debug("read client",
		logger.String("tenant_id", tenantID), logger.String("client_id", clientID), logger.RequestID(ctx))

	var row Client
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		ColumnExpr(clientColumns).
		ColumnExpr("a.name AS name").
		Join("JOIN applications AS a ON a.id = c.app_id AND a.tenant_id = c.tenant_id").
		Where("c.tenant_id = ?", tenantID).
		Where("c.client_id = ?", clientID).
		Where("c.expires_at IS NULL OR c.expires_at > ?", time.Now()).
		Where("a.deleted_at IS NULL").
		Where("a.state = ?", appStateActive).
		Where("a.app_type = ?", appTypeOIDC).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, fmt.Errorf("%w: tenant %s, client %s", ErrClientNotFound, tenantID, clientID)
	}
	if err != nil {
		return Client{}, fmt.Errorf("read client %s of tenant %s: %w", clientID, tenantID, err)
	}

	r.log.Debug("read client",
		logger.String("tenant_id", tenantID), logger.String("client_id", clientID), logger.RequestID(ctx))
	return row, nil
}
