package oidc

import (
	"context"

	"alphaomega/identitygateway/internal/platform/logger"
)

// Scope is one scope the tenant offers. DisplayName and Description are the
// words the consent screen renders, and both are optional columns.
type Scope struct {
	Name        string
	DisplayName string
	Description string
}

// ScopeLister reads the enabled scopes of one tenant. A disabled scope is not
// advertised, so the read filters it out.
type ScopeLister func(ctx context.Context, tenantID string) ([]Scope, error)

// ScopeDeps is the database side of the scope service.
type ScopeDeps struct {
	List ScopeLister
	Log  logger.Logger
}

// ScopeService answers what the tenant offers, for discovery and for the
// consent screen.
type ScopeService struct {
	deps ScopeDeps
	log  logger.Logger
}

func NewScopeService(deps ScopeDeps) *ScopeService {
	return &ScopeService{deps: deps, log: deps.Log}
}

// Advertised names the scopes the discovery document holds. openid comes
// first and is always present, because a tenant that disables the row still
// runs OpenID Connect.
func (s *ScopeService) Advertised(ctx context.Context, tenantID string) ([]string, error) {
	s.log.Debug("read advertised scopes", logger.String("tenant_id", tenantID))

	scopes, err := s.deps.List(ctx, tenantID)
	if err != nil {
		s.log.Error("read scopes",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return nil, err
	}

	names := []string{"openid"}
	for _, scope := range scopes {
		if scope.Name != "openid" {
			names = append(names, scope.Name)
		}
	}

	s.log.Debug("advertised scopes", logger.String("tenant_id", tenantID))
	return names, nil
}

// Describe reads the words the consent screen renders for the scopes it asks
// about. The answer follows the requested order, and holds one entry per
// requested name.
//
// A scope with no display name, and a scope the tenant does not offer, both
// fall back to the bare scope name. The screen always has something to render.
func (s *ScopeService) Describe(
	ctx context.Context, tenantID string, names []string,
) ([]Scope, error) {
	s.log.Debug("describe scopes", logger.String("tenant_id", tenantID))

	scopes, err := s.deps.List(ctx, tenantID)
	if err != nil {
		s.log.Error("read scopes",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return nil, err
	}

	known := make(map[string]Scope, len(scopes))
	for _, scope := range scopes {
		known[scope.Name] = scope
	}

	out := make([]Scope, 0, len(names))
	for _, name := range names {
		scope := known[name]
		scope.Name = name
		if scope.DisplayName == "" {
			scope.DisplayName = name
		}
		out = append(out, scope)
	}

	s.log.Debug("described scopes", logger.String("tenant_id", tenantID))
	return out, nil
}
