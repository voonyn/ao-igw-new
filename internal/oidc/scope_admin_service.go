package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
	"alphaomega/identitygateway/internal/utils"
)

// ErrScopeNotFound reports that the tenant holds no live scope with that id.
var ErrScopeNotFound = errors.New("scope not found")

// ErrScopeNameTaken reports a name another scope of the tenant already holds.
// Two scopes with one name would make an authorization request ambiguous.
var ErrScopeNameTaken = errors.New("the tenant already holds a scope with that name")

// ErrBuiltinScope reports a delete of a scope the migration seeded. The
// protocol and the seeded claim mappers name it, so it stays. It can still be
// disabled, which stops it being advertised or granted.
var ErrBuiltinScope = errors.New("a builtin scope cannot be deleted")

// ErrScopeInUse reports a delete of a scope that is still on the allow-list of
// a client. Removing it would refuse an authorization request the client makes
// today, and the client would report an invalid scope with nothing to point at.
var ErrScopeInUse = errors.New("a client still holds this scope")

// The reads and writes the scope service composes its answers from. Each one is
// a function value, so the logic is testable without a database.
type (
	// ScopeRowLister reads every live scope of one tenant, the disabled ones
	// included, with the number of claims each releases.
	ScopeRowLister func(ctx context.Context, tenantID string) ([]ScopeRow, error)

	// ScopeFinder reads one live scope of a tenant by its id.
	ScopeFinder func(ctx context.Context, tenantID, id string) (ScopeRow, error)

	// ScopeNameFinder reads one live scope of a tenant by its name. A name
	// nobody holds returns ErrScopeNotFound.
	ScopeNameFinder func(ctx context.Context, tenantID, name string) (ScopeRow, error)

	// ScopeInserter writes one new scope.
	ScopeInserter func(ctx context.Context, row ScopeRow) error

	// ScopeUpdater writes the five writable fields of one scope.
	ScopeUpdater func(ctx context.Context, row ScopeRow) error

	// ScopeDeleter marks one scope of a tenant deleted.
	ScopeDeleter func(ctx context.Context, tenantID, id string) error

	// ClientScopeCounter counts the live clients of a tenant that still name one
	// scope on their allow-list.
	ClientScopeCounter func(ctx context.Context, tenantID, name string) (int, error)
)

// ScopeAdminDeps is the database side of the scope service.
type ScopeAdminDeps struct {
	ListScopes      ScopeRowLister
	FindScope       ScopeFinder
	FindScopeByName ScopeNameFinder

	InsertScope ScopeInserter
	UpdateScope ScopeUpdater
	DeleteScope ScopeDeleter

	CountClientsWithScope ClientScopeCounter

	ListMappers  MapperRowLister
	FindMapper   MapperFinderByID
	CountMappers MapperCounter

	InsertMapper MapperInserter
	UpdateMapper MapperUpdater
	DeleteMapper MapperDeleter

	TenantRoles TenantRoleFinder

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// ScopeAdminService serves the scope registry and the claim mappers of a tenant
// to the console.
type ScopeAdminService struct {
	deps ScopeAdminDeps
	log  logger.Logger
}

func NewScopeAdminService(deps ScopeAdminDeps) *ScopeAdminService {
	return &ScopeAdminService{deps: deps, log: deps.Log}
}

// ListScopes answers every scope the tenant holds, the disabled ones included.
// The registry is bounded by what an operator writes, so it is not paged.
func (s *ScopeAdminService) ListScopes(ctx context.Context, a AdminActor) ([]ScopeView, error) {
	s.log.Debug("list the scopes",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorize(ctx, a, "list the scopes"); err != nil {
		return nil, err
	}

	rows, err := s.deps.ListScopes(ctx, a.TenantID)
	if err != nil {
		return nil, s.fail(a, "list the scopes", err)
	}

	views := make([]ScopeView, 0, len(rows))
	for _, row := range rows {
		views = append(views, scopeView(row))
	}
	return views, nil
}

// CreateScope writes one new scope of the tenant.
//
// The scope is never builtin. Only the migration writes that mark, and it is
// what makes the seeded names permanent, so an operator cannot mint a scope that
// nobody can delete.
func (s *ScopeAdminService) CreateScope(
	ctx context.Context, a AdminActor, body ScopeBody,
) (ScopeView, error) {
	s.log.Debug("create a scope",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorize(ctx, a, "create a scope"); err != nil {
		return ScopeView{}, err
	}

	row := ScopeRow{
		ID:          utils.NewUUIDv7(),
		TenantID:    a.TenantID,
		Name:        body.Name,
		DisplayName: body.DisplayName,
		Description: body.Description,
		IsEnabled:   body.IsEnabled,
		IsDefault:   body.IsDefault,
	}
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.freeName(ctx, a.TenantID, body.Name, ""); err != nil {
			return err
		}
		if err := s.deps.InsertScope(ctx, row); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionScopeCreated,
			EntityType: audit.EntityScope,
			EntityID:   row.ID,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
			Metadata:   map[string]any{"scope_name": row.Name},
		})
	})
	if err != nil {
		if errors.Is(err, ErrScopeNameTaken) {
			return ScopeView{}, err
		}
		return ScopeView{}, s.fail(a, "create a scope", err)
	}

	s.log.Info("created a scope",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", row.ID))
	return scopeView(row), nil
}

// UpdateScope writes the words and the two switches of one scope, and answers
// the row as it then stands.
//
// The name of a builtin scope is left alone. The seeded names are the names the
// protocol and the clients already use, so a rename would stop a request
// resolving with nothing to point at.
func (s *ScopeAdminService) UpdateScope(
	ctx context.Context, a AdminActor, id string, body ScopeBody,
) (ScopeView, error) {
	s.log.Debug("write a scope",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", id))

	if err := s.authorize(ctx, a, "write a scope"); err != nil {
		return ScopeView{}, err
	}

	var out ScopeRow
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		row, err := s.deps.FindScope(ctx, a.TenantID, id)
		if err != nil {
			return err
		}

		if !row.IsBuiltin && body.Name != row.Name {
			if err := s.freeName(ctx, a.TenantID, body.Name, row.ID); err != nil {
				return err
			}
			row.Name = body.Name
		}
		row.DisplayName = body.DisplayName
		row.Description = body.Description
		row.IsEnabled = body.IsEnabled
		row.IsDefault = body.IsDefault

		if err := s.deps.UpdateScope(ctx, row); err != nil {
			return err
		}
		out = row

		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionScopeUpdated,
			EntityType: audit.EntityScope,
			EntityID:   row.ID,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
			Metadata:   map[string]any{"scope_name": row.Name},
		})
	})
	if err != nil {
		if errors.Is(err, ErrScopeNotFound) || errors.Is(err, ErrScopeNameTaken) {
			return ScopeView{}, err
		}
		return ScopeView{}, s.fail(a, "write a scope", err)
	}

	s.log.Info("wrote a scope",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", id))
	return scopeView(out), nil
}

// DeleteScope marks one scope of the tenant deleted, with its claim mappers.
//
// Two scopes are refused. A builtin scope stays, because the protocol and the
// seeded mappers name it. A scope a client still holds stays, because removing
// it would refuse an authorization request that client makes today. Both can be
// disabled instead, which stops the scope being advertised or granted.
func (s *ScopeAdminService) DeleteScope(ctx context.Context, a AdminActor, id string) error {
	s.log.Debug("delete a scope",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", id))

	if err := s.authorize(ctx, a, "delete a scope"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		row, err := s.deps.FindScope(ctx, a.TenantID, id)
		if err != nil {
			return err
		}
		if row.IsBuiltin {
			return fmt.Errorf("%w: %s", ErrBuiltinScope, row.Name)
		}

		clients, err := s.deps.CountClientsWithScope(ctx, a.TenantID, row.Name)
		if err != nil {
			return err
		}
		if clients > 0 {
			return fmt.Errorf("%w: %s", ErrScopeInUse, row.Name)
		}

		if err := s.deps.DeleteScope(ctx, a.TenantID, id); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionScopeDeleted,
			EntityType: audit.EntityScope,
			EntityID:   row.ID,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
			Metadata:   map[string]any{"scope_name": row.Name},
		})
	})
	if err != nil {
		if errors.Is(err, ErrScopeNotFound) || errors.Is(err, ErrBuiltinScope) ||
			errors.Is(err, ErrScopeInUse) {
			return err
		}
		return s.fail(a, "delete a scope", err)
	}

	s.log.Info("deleted a scope",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("scope_id", id))
	return nil
}

// freeName reports whether the tenant can take the name. keep names the scope
// that is allowed to hold it already, so a write that does not rename passes.
func (s *ScopeAdminService) freeName(ctx context.Context, tenantID, name, keep string) error {
	existing, err := s.deps.FindScopeByName(ctx, tenantID, name)
	switch {
	case errors.Is(err, ErrScopeNotFound):
		return nil
	case err != nil:
		return err
	case existing.ID == keep:
		return nil
	default:
		return fmt.Errorf("%w: %s", ErrScopeNameTaken, name)
	}
}

// authorize is the gate of every route of this service.
//
// Every route needs the owner of the tenant, the reads included. A scope decides
// which claims every client of the tenant can ask for, and a claim mapper
// decides what a token releases about a person, so the registry is not a
// read-only view an administrator browses.
func (s *ScopeAdminService) authorize(ctx context.Context, a AdminActor, what string) error {
	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}
	if slices.Contains(roles, tenant.RoleIAMOwner) {
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
func (s *ScopeAdminService) fail(a AdminActor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}
