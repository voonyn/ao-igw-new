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

// Client is one row of application_oidc_configs joined to its application: the
// protocol identity of one application. Name comes from the application, because
// the application is the thing an administrator names.
//
// Secret holds a bcrypt hash, not the secret itself. VerifyClientSecret is the
// only reader of it.
type Client struct {
	bun.BaseModel `bun:"table:application_oidc_configs,alias:c"`

	AppID    string `bun:"app_id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	ClientID string `bun:"client_id"`
	Name     string `bun:"name,scanonly"`

	CreatedAt       time.Time `bun:"created_at,nullzero"`
	ExpiresAt       time.Time `bun:"expires_at,nullzero"`
	Secret          string    `bun:"secret,nullzero"`
	SecretExpiresAt time.Time `bun:"secret_expires_at,nullzero"`

	TokenAuthnMethod string `bun:"token_authn_method"`
	SubjectType      string `bun:"subject_type,nullzero"`
	Scopes           string `bun:"scopes,nullzero"`
	IsFirstParty     bool   `bun:"is_first_party"`

	RedirectURIs           []string `bun:"redirect_uris"`
	GrantTypes             []string `bun:"grant_types"`
	ResponseTypes          []string `bun:"response_types"`
	PostLogoutRedirectURIs []string `bun:"post_logout_redirect_uris,nullzero"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

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
		logger.String("tenant_id", tenantID), logger.String("client_id", clientID))

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
		logger.String("tenant_id", tenantID), logger.String("client_id", clientID))
	return row, nil
}
