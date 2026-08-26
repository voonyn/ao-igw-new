package authpolicy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"alphaomega/identitygateway/internal/actor"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// ErrForbidden reports a person who does not administer the level they named. A
// person who administers nothing and a person who administers another
// organization read the same refusal, so no answer reports what somebody else
// administers.
var ErrForbidden = errors.New("cannot administer this auth policy")

// ErrTenantScope reports a reset of the tenant default. The default is the
// bottom of the two levels, so removing it would leave nothing to inherit.
var ErrTenantScope = errors.New("the tenant default has nothing to inherit")

// Actor is the person behind one administrative request. The IP and the user
// agent reach the audit trail, and nothing else here reads them.
type Actor actor.Actor

// The reads and writes the service composes its answers from. Each one is a
// function value, so the logic is testable without a database.
type (
	// Finder reads the stored row of one level. A level that stores nothing
	// answers ErrNotFound, which the service reads as "inherit everything".
	Finder func(ctx context.Context, tenantID, orgID string) (Row, error)

	// Upserter writes the whole row of one level.
	Upserter func(ctx context.Context, row Row) error

	// Remover marks the override of one organization deleted.
	Remover func(ctx context.Context, tenantID, orgID string) error

	// OrgFinder reads one organization. It returns organization.ErrNotFound on
	// a miss, so no org id can name a policy for an organization the tenant
	// does not hold.
	OrgFinder func(ctx context.Context, tenantID, orgID string) (organization.Organization, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// role gets an empty answer, not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// MembershipLister reads the organization memberships of one person.
	MembershipLister func(ctx context.Context, tenantID, userID string) ([]organization.Membership, error)
)

// Deps is the database side of the service.
type Deps struct {
	Find   Finder
	Upsert Upserter
	Remove Remover

	Org         OrgFinder
	TenantRoles TenantRoleFinder
	Memberships MembershipLister

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// Service serves the two-level auth policy of one tenant to the console.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// Read answers the policy one level enforces, and names per field whether the
// value is set at that level or inherited from the level below.
//
// An empty orgID reads the tenant default.
func (s *Service) Read(ctx context.Context, a Actor, orgID string) (View, error) {
	s.log.Debug("read the auth policy",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, orgID, "read the auth policy"); err != nil {
		return View{}, err
	}

	view, err := s.resolved(ctx, a.TenantID, orgID)
	if err != nil {
		return View{}, s.fail(a, "read the auth policy", err)
	}

	s.log.Debug("read the auth policy",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", orgID), logger.RequestID(ctx))
	return view, nil
}

// Write replaces the row of one level and answers the policy that then holds.
//
// The whole row is written, so a field the body left out goes back to
// inheriting the level below. A field the body carries is an explicit setting,
// and zero is a value: a threshold of 0 disables lockout.
func (s *Service) Write(ctx context.Context, a Actor, orgID string, body Body) (View, error) {
	s.log.Debug("write the auth policy",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, orgID, "write the auth policy"); err != nil {
		return View{}, err
	}

	var view View
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Upsert(ctx, body.row(a.TenantID, orgID)); err != nil {
			return err
		}
		if err := s.record(ctx, a, audit.ActionAuthPolicyUpdated, orgID); err != nil {
			return err
		}

		var err error
		view, err = s.resolved(ctx, a.TenantID, orgID)
		return err
	})
	if err != nil {
		return View{}, s.fail(a, "write the auth policy", err)
	}

	s.log.Info("wrote the auth policy",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID))
	return view, nil
}

// Reset removes the override of one organization, so every field of it goes
// back to the tenant default.
//
// It exists at organization level only. The tenant default is the bottom of the
// two levels, and it has nothing to inherit.
//
// An organization that holds no override is already in the state the reset asks
// for, so the answer is the same and nothing is recorded.
func (s *Service) Reset(ctx context.Context, a Actor, orgID string) error {
	s.log.Debug("remove the auth policy override",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID), logger.RequestID(ctx))

	if orgID == "" {
		return ErrTenantScope
	}
	if err := s.authorize(ctx, a, orgID, "remove the auth policy override"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Remove(ctx, a.TenantID, orgID); err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil
			}
			return err
		}
		return s.record(ctx, a, audit.ActionAuthPolicyReset, orgID)
	})
	if err != nil {
		return s.fail(a, "remove the auth policy override", err)
	}

	s.log.Info("removed the auth policy override",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID))
	return nil
}

// resolved reads the levels one answer is built from. The tenant default reads
// one row, and an organization reads its own row over that default.
//
// A level that stores nothing is not a failure. It inherits the level below,
// and the tenant default falls back to the code defaults.
func (s *Service) resolved(ctx context.Context, tenantID, orgID string) (View, error) {
	def, err := s.level(ctx, tenantID, "")
	if err != nil {
		return View{}, err
	}
	if orgID == "" {
		return resolve("", def, Row{}), nil
	}

	override, err := s.level(ctx, tenantID, orgID)
	if err != nil {
		return View{}, err
	}
	return resolve(orgID, override, def), nil
}

// level reads the stored row of one level, and answers an empty row when the
// level stores nothing.
func (s *Service) level(ctx context.Context, tenantID, orgID string) (Row, error) {
	row, err := s.deps.Find(ctx, tenantID, orgID)
	switch {
	case errors.Is(err, ErrNotFound):
		return Row{}, nil
	case err != nil:
		return Row{}, err
	default:
		return row, nil
	}
}

// record writes one audit event on the caller's transaction. The entity is the
// organization the override belongs to, and the tenant itself for the default,
// so the trail reads as one entity per level.
func (s *Service) record(ctx context.Context, a Actor, action audit.Action, orgID string) error {
	entityID := orgID
	if entityID == "" {
		entityID = a.TenantID
	}
	return s.deps.Audit.Record(ctx, audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityAuthPolicy,
		EntityID:   entityID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
		Metadata:   map[string]any{"org_id": orgID},
	})
}

// authorize is the gate of every route of this service.
//
// A tenant manager administers the tenant default and every organization. An
// ORG_OWNER administers the override of its own organization and nothing else:
// the policy decides how a person of that organization signs in, so an
// ORG_USER_MANAGER who administers the people is not enough.
//
// An organization the tenant does not hold is refused before the gate answers,
// so a typed id cannot write a policy nobody can reach.
func (s *Service) authorize(ctx context.Context, a Actor, orgID, what string) error {
	if orgID != "" {
		if _, err := s.deps.Org(ctx, a.TenantID, orgID); err != nil {
			if errors.Is(err, organization.ErrNotFound) {
				return err
			}
			return s.fail(a, "read the organization", err)
		}
	}

	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}
	if slices.Contains(roles, tenant.RoleIAMOwner) || slices.Contains(roles, tenant.RoleIAMAdmin) {
		return nil
	}

	if orgID != "" {
		memberships, err := s.deps.Memberships(ctx, a.TenantID, a.UserID)
		if err != nil {
			return s.fail(a, "read organization memberships", err)
		}
		for _, m := range memberships {
			if m.OrgID == orgID && slices.Contains(m.Roles, organization.RoleOrgOwner) {
				return nil
			}
		}
	}

	s.log.Warn("refused a person who does not hold the role",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *Service) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}
