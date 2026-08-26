package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// ErrForbidden reports that the person does not administer this tenant. A grant
// reaches every organization, so only a tenant manager reads one.
var ErrForbidden = errors.New("only a tenant manager reads a grant")

// GrantActor is the person behind one administrative grant read.
type GrantActor struct {
	TenantID string
	UserID   string
}

// The reads the grant service composes its answer from. Each one is a function
// value, so the logic is testable without a database.
type (
	// GrantLister reads one page of the grants of one tenant.
	GrantLister func(ctx context.Context, tenantID string, q GrantQuery) ([]GrantRecord, int64, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// membership holds no role, which is not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)
)

// GrantDeps is the database side of the grant service.
type GrantDeps struct {
	List        GrantLister
	TenantRoles TenantRoleFinder
	Log         logger.Logger
}

// GrantService serves the grants of a tenant to the console.
//
// The list is a read and nothing more. A grant is revoked through the login
// session it came from, or through the force-logout of the person who holds it,
// because a revoke that left the session alive would be undone by the next
// refresh.
type GrantService struct {
	deps GrantDeps
	log  logger.Logger
}

func NewGrantService(deps GrantDeps) *GrantService {
	return &GrantService{deps: deps, log: deps.Log}
}

// List reads one page of the grants of the tenant.
func (s *GrantService) List(
	ctx context.Context, a GrantActor, q GrantQuery,
) ([]GrantView, int64, error) {
	s.log.Debug("list grants",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		s.log.Error("read tenant roles",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.Err(err))
		return nil, 0, err
	}
	if !slices.Contains(roles, tenant.RoleIAMOwner) && !slices.Contains(roles, tenant.RoleIAMAdmin) {
		s.log.Warn("refused a person who does not administer the tenant",
			logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
		return nil, 0, fmt.Errorf("%w: tenant %s, user %s", ErrForbidden, a.TenantID, a.UserID)
	}

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		s.log.Error("list grants",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.Err(err))
		return nil, 0, err
	}

	views := make([]GrantView, 0, len(rows))
	for _, row := range rows {
		views = append(views, GrantView{
			ID:             row.ID,
			TenantID:       row.TenantID,
			AppID:          row.ClientID,
			AppName:        row.AppName,
			Subject:        row.Subject,
			SubjectName:    row.SubjectName,
			LoginSessionID: row.LoginSessionID,
			Kind:           row.Kind(),
			Created:        row.CreatedAt,
			Expires:        row.ExpiresAt,
		})
	}
	return views, total, nil
}
