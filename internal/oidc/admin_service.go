package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// ErrOpaqueAccessToken reports a write that would make the tenant issue opaque
// access tokens.
//
// The protocol engine refuses to build a provider that issues them, so the
// tenant would answer nothing at all: no sign-in, no token, and no way to mint
// the admin token that would put the setting back. Recovery would be a SQL
// statement. The value is refused here instead.
var ErrOpaqueAccessToken = errors.New("an opaque access token is not served")

// AdminActor is the person behind one administrative provider request. The IP
// and the agent travel to the audit trail, so the trail names where the change
// came from.
type AdminActor struct {
	TenantID  string
	UserID    string
	IP        string
	UserAgent string
}

// The reads and writes the administrative service composes its answers from.
// Each one is a function value, so the logic is testable without a database.
type (
	// ProviderFinder reads the provider config of one tenant, whatever state it
	// is in. A tenant that is not an OpenID Provider yet returns
	// ErrProviderConfigNotFound.
	ProviderFinder func(ctx context.Context, tenantID string) (ProviderConfig, error)

	// ProviderUpdater writes the fields the body names, and only those.
	ProviderUpdater func(ctx context.Context, tenantID string, body ProviderConfigBody) error

	// KeyLister reads every live key of one tenant, the retired ones included.
	KeyLister func(ctx context.Context, tenantID string) ([]Key, error)
)

// AdminDeps is the database side of the administrative provider service.
type AdminDeps struct {
	Provider ProviderFinder
	Update   ProviderUpdater
	Keys     KeyLister

	TenantRoles TenantRoleFinder

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AdminService serves the protocol settings and the signing keys of a tenant to
// the console.
//
// Key rotation is not here. A key is created and retired by the bootstrap
// command and by a scheduled routine, so this service reads the set and writes
// nothing to it.
type AdminService struct {
	deps AdminDeps
	log  logger.Logger
}

func NewAdminService(deps AdminDeps) *AdminService {
	return &AdminService{deps: deps, log: deps.Log}
}

// ReadProvider answers the protocol settings of the tenant.
func (s *AdminService) ReadProvider(ctx context.Context, a AdminActor) (ProviderView, error) {
	s.log.Debug("read the provider config",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorize(ctx, a, false, "read the provider config"); err != nil {
		return ProviderView{}, err
	}

	cfg, err := s.deps.Provider(ctx, a.TenantID)
	if err != nil {
		if errors.Is(err, ErrProviderConfigNotFound) {
			return ProviderView{}, err
		}
		return ProviderView{}, s.fail(a, "read the provider config", err)
	}
	return providerView(cfg), nil
}

// UpdateProvider writes the settings the body names and answers the row as it
// then stands.
//
// A field the body omits is left alone. The read that follows the write runs on
// the same transaction, so the answer is the row that was committed and the
// console renders the saved state without a second request.
func (s *AdminService) UpdateProvider(
	ctx context.Context, a AdminActor, body ProviderConfigBody,
) (ProviderView, error) {
	s.log.Debug("write the provider config",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorize(ctx, a, true, "write the provider config"); err != nil {
		return ProviderView{}, err
	}
	if body.AccessTokenType != nil && *body.AccessTokenType != AccessTokenNameJWT {
		s.log.Warn("refused an opaque access token",
			logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
		return ProviderView{}, fmt.Errorf("%w: tenant %s", ErrOpaqueAccessToken, a.TenantID)
	}

	var out ProviderView
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Update(ctx, a.TenantID, body); err != nil {
			return err
		}
		cfg, err := s.deps.Provider(ctx, a.TenantID)
		if err != nil {
			return err
		}
		out = providerView(cfg)

		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionProviderUpdated,
			EntityType: audit.EntityProviderConfig,
			EntityID:   a.TenantID,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
		})
	})
	if err != nil {
		if errors.Is(err, ErrProviderConfigNotFound) {
			return ProviderView{}, err
		}
		return ProviderView{}, s.fail(a, "write the provider config", err)
	}

	s.log.Info("wrote the provider config",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
	return out, nil
}

// ListKeys answers the key set of the tenant. The list is bounded by the
// rotation routine, so it is not paged.
func (s *AdminService) ListKeys(ctx context.Context, a AdminActor) ([]KeyView, error) {
	s.log.Debug("list the signing keys",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorize(ctx, a, false, "list the signing keys"); err != nil {
		return nil, err
	}

	rows, err := s.deps.Keys(ctx, a.TenantID)
	if err != nil {
		return nil, s.fail(a, "list the signing keys", err)
	}

	views := make([]KeyView, 0, len(rows))
	for _, row := range rows {
		views = append(views, keyView(row))
	}
	return views, nil
}

// authorize is the gate of every route of this service.
//
// A read needs a tenant manager: the settings and the key set describe the whole
// tenant and no organization holds a part of them. A write needs the owner,
// because the settings decide how every token of the tenant is issued.
func (s *AdminService) authorize(ctx context.Context, a AdminActor, write bool, what string) error {
	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}

	if slices.Contains(roles, tenant.RoleIAMOwner) ||
		(!write && slices.Contains(roles, tenant.RoleIAMAdmin)) {
		return nil
	}

	s.log.Warn("refused a person who does not hold the role",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *AdminService) fail(a AdminActor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}

func providerView(cfg ProviderConfig) ProviderView {
	// The console iterates the list without a guard, so it is a list and never
	// null. A tenant with no identifier runs without the resource indicator.
	indicators := cfg.ResourceIndicators
	if indicators == nil {
		indicators = []string{}
	}

	return ProviderView{
		Issuer:               cfg.Issuer,
		State:                cfg.State,
		RequirePKCE:          cfg.RequirePKCE,
		RefreshRotation:      cfg.RefreshTokenRotation,
		AuthCodeLifetime:     cfg.AuthorizationCodeLifetimeSecs,
		AccessTokenType:      accessTokenName(cfg.AccessTokenType),
		AccessTokenLifetime:  cfg.AccessTokenLifetimeSecs,
		IDTokenLifetime:      cfg.IDTokenLifetimeSecs,
		RefreshTokenLifetime: cfg.RefreshTokenLifetimeSecs,
		ResourceIndicators:   indicators,
	}
}

// accessTokenName is the name the console prints for the stored number.
func accessTokenName(t int) string {
	if t == AccessTokenTypeOpaque {
		return AccessTokenNameOpaque
	}
	return AccessTokenNameJWT
}

func keyView(row Key) KeyView {
	return KeyView{
		ID:        row.ID,
		TenantID:  row.TenantID,
		Use:       row.KeyUse,
		Alg:       row.Algorithm,
		State:     row.State,
		ActiveAt:  moment(row.ActiveAt),
		ExpiresAt: moment(row.ExpiresAt),
		Created:   row.CreatedAt,
		Updated:   row.UpdatedAt,
	}
}

// moment answers null for a column the row does not carry. A zero date would
// render as the year one, which the console reads as a real rotation window.
func moment(at time.Time) *time.Time {
	if at.IsZero() {
		return nil
	}
	return &at
}
