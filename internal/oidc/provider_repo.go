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

// ErrProviderConfigNotFound reports that a tenant has no live provider config.
// The tenant is not an OpenID Provider yet, so the request stops there.
var ErrProviderConfigNotFound = errors.New("provider config not found")

// providerStateActive is oidc_provider_configs.state for a config that serves.
const providerStateActive = 1

// Resource identifiers (RFC 8707). ResourceAdminAPI names the admin management
// API that console-ui calls, ResourceAccountAPI the self-service API that
// portal-ui calls. Both front ends send these exact values at /authorize.
const (
	ResourceAdminAPI   = "urn:alphaomega:admin-api"
	ResourceAccountAPI = "urn:alphaomega:account-api"
)

// SeedResourceIndicators is the resource identifier list a new tenant starts
// with. bootstrap writes it into oidc_provider_configs.resource_indicators.
var SeedResourceIndicators = []string{ResourceAdminAPI, ResourceAccountAPI}

// Access token types, as stored in oidc_provider_configs.access_token_type.
// Only a JWT access token is in scope. The provider build refuses type 2.
const (
	AccessTokenTypeJWT    = 1
	AccessTokenTypeOpaque = 2
)

// ProviderConfig is one row of oidc_provider_configs: the protocol settings of
// one tenant. Every OIDC knob comes from here, never from the environment.
// RefreshTokenLifetimeSecs is nil when the tenant disables the refresh grant.
type ProviderConfig struct {
	bun.BaseModel `bun:"table:oidc_provider_configs"`

	TenantID string `bun:"tenant_id,pk"`
	Issuer   string `bun:"issuer"`
	State    int    `bun:"state"`

	RequirePKCE          bool `bun:"require_pkce"`
	RefreshTokenRotation bool `bun:"refresh_token_rotation"`

	AuthorizationCodeLifetimeSecs int  `bun:"authorization_code_lifetime_secs"`
	AccessTokenType               int  `bun:"access_token_type"`
	AccessTokenLifetimeSecs       int  `bun:"access_token_lifetime_secs"`
	IDTokenLifetimeSecs           int  `bun:"id_token_lifetime_secs"`
	RefreshTokenLifetimeSecs      *int `bun:"refresh_token_lifetime_secs"`

	// ResourceIndicators lists the RFC 8707 resource identifiers a client of this
	// tenant can ask for. Empty means the tenant runs without the indicator.
	ResourceIndicators []string `bun:"resource_indicators,nullzero"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// ProviderRepository reads the provider config of one tenant.
type ProviderRepository struct {
	db  *bun.DB
	log logger.Logger
}

func NewProviderRepository(bdb *bun.DB, log logger.Logger) *ProviderRepository {
	return &ProviderRepository{db: bdb, log: log}
}

// FindByTenant reads the active provider config of one tenant. A miss returns
// ErrProviderConfigNotFound.
func (r *ProviderRepository) FindByTenant(ctx context.Context, tenantID string) (ProviderConfig, error) {
	r.log.Debug("read provider config", logger.String("tenant_id", tenantID))

	var cfg ProviderConfig
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&cfg).
		Where("tenant_id = ?", tenantID).
		Where("state = ?", providerStateActive).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return ProviderConfig{}, fmt.Errorf("%w: tenant %s", ErrProviderConfigNotFound, tenantID)
	}
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("read provider config of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("read provider config",
		logger.String("tenant_id", tenantID), logger.String("issuer", cfg.Issuer))
	return cfg, nil
}

// ReadByTenant reads the provider config of one tenant whatever state it is in.
//
// The administrative screen renders the state as a read-only field, so a tenant
// whose provider is switched off must still read the row. A soft-deleted row
// never comes back, because that tenant has no provider config at all.
func (r *ProviderRepository) ReadByTenant(ctx context.Context, tenantID string) (ProviderConfig, error) {
	r.log.Debug("read provider config", logger.String("tenant_id", tenantID))

	var cfg ProviderConfig
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&cfg).
		Where("tenant_id = ?", tenantID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return ProviderConfig{}, fmt.Errorf("%w: tenant %s", ErrProviderConfigNotFound, tenantID)
	}
	if err != nil {
		return ProviderConfig{}, fmt.Errorf("read provider config of tenant %s: %w", tenantID, err)
	}
	return cfg, nil
}

// Update writes the settings the body names, and only those. It runs on the
// caller's transaction.
//
// The seven columns below are the whole writable surface of the table. The
// issuer, the state, the advertised signing algorithms, and the resource
// identifiers are never named here, so no request can reach them.
//
// A body that names nothing writes nothing and is not an error: the console
// sends what changed, and nothing changed.
func (r *ProviderRepository) Update(
	ctx context.Context, tenantID string, body ProviderConfigBody,
) error {
	q := db.Conn(ctx, r.db).NewUpdate().
		Model((*ProviderConfig)(nil)).
		Where("tenant_id = ?", tenantID)

	set := 0
	setInt := func(column string, value *int) {
		if value != nil {
			q, set = q.Set(column+" = ?", *value), set+1
		}
	}
	setInt("authorization_code_lifetime_secs", body.AuthCodeLifetime)
	setInt("access_token_lifetime_secs", body.AccessTokenLifetime)
	setInt("id_token_lifetime_secs", body.IDTokenLifetime)
	setInt("refresh_token_lifetime_secs", body.RefreshTokenLifetime)

	if body.RequirePKCE != nil {
		q, set = q.Set("require_pkce = ?", *body.RequirePKCE), set+1
	}
	if body.RefreshRotation != nil {
		q, set = q.Set("refresh_token_rotation = ?", *body.RefreshRotation), set+1
	}
	if body.AccessTokenType != nil {
		q, set = q.Set("access_token_type = ?", accessTokenType(*body.AccessTokenType)), set+1
	}

	if set == 0 {
		return nil
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("write the provider config of tenant %s: %w", tenantID, err)
	}
	return nil
}

// accessTokenType is the number the column stores for the name the console
// sends.
func accessTokenType(name string) int {
	if name == AccessTokenNameOpaque {
		return AccessTokenTypeOpaque
	}
	return AccessTokenTypeJWT
}
