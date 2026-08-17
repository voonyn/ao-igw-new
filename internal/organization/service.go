package organization

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
	"alphaomega/identitygateway/internal/utils"
)

// ErrNotAdmin reports that the person holds none of the four administrative
// roles. The bearer guard admits any token minted for the admin resource, so
// the roles decide who reads the organizations of a tenant.
var ErrNotAdmin = errors.New("no administrative role")

// ErrForbidden reports that the person administers this tenant or another
// organization, but not the one the request names.
var ErrForbidden = errors.New("cannot write this organization")

// ErrDefaultOrg reports an attempt to delete the organization
// self-registration points at. A new person would have nowhere to land.
var ErrDefaultOrg = errors.New("the default organization cannot be deleted")

// Actor is the person behind one admin request. The IP and the user agent reach
// the audit trail, so a change is traceable to where it came from.
type Actor struct {
	TenantID  string
	UserID    string
	IP        string
	UserAgent string
}

// Query is the window and the narrowing one list read asks for. Sort names a
// column of the route's allowlist, and an empty State means every state.
type Query struct {
	Search string
	State  int
	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// The reads and writes the service composes its answers from. Each one is a
// function value, so the logic is testable without a database.
type (
	// Lister reads one page of organizations and the total behind it.
	Lister func(ctx context.Context, tenantID string, q Query) ([]Organization, int64, error)

	// Finder reads one organization. It returns ErrNotFound on a miss.
	Finder func(ctx context.Context, tenantID, orgID string) (Organization, error)

	// TenantFinder reads the tenant of the request, for its default
	// organization.
	TenantFinder func(ctx context.Context, tenantID string) (tenant.Tenant, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// role gets an empty answer, not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// MembershipLister reads the organization memberships of one person.
	MembershipLister func(ctx context.Context, tenantID, userID string) ([]Membership, error)

	// Inserter writes one new organization.
	Inserter func(ctx context.Context, row Organization) error

	// Renamer writes the new name of one organization.
	Renamer func(ctx context.Context, tenantID, orgID, name string) error

	// Deleter soft deletes one organization.
	Deleter func(ctx context.Context, tenantID, orgID string) error
)

// Deps is the database side of the service.
type Deps struct {
	List        Lister
	Find        Finder
	Insert      Inserter
	Rename      Renamer
	Delete      Deleter
	Tenant      TenantFinder
	TenantRoles TenantRoleFinder
	Memberships MembershipLister
	InTx        db.TxRunner
	Audit       *audit.Recorder
	Log         logger.Logger
}

// Service serves the organizations of one tenant to the console.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// rights is what one person may do in this tenant: administer all of it, or
// administer the organizations named here.
type rights struct {
	tenantManager bool
	orgRoles      map[string][]string
}

// canWrite reports whether the person may write one organization. A tenant
// manager writes any of them, and an ORG_OWNER writes its own.
func (r rights) canWrite(orgID string) bool {
	return r.tenantManager || slices.Contains(r.orgRoles[orgID], RoleOrgOwner)
}

// admits reports whether the person administers anything at all.
func (r rights) admits() bool {
	if r.tenantManager {
		return true
	}
	for _, roles := range r.orgRoles {
		if slices.Contains(roles, RoleOrgOwner) || slices.Contains(roles, RoleOrgUserManager) {
			return true
		}
	}
	return false
}

// List reads one page of the organizations of the tenant.
//
// Every administrator of the tenant reads the whole list, because the console
// shell already names every organization on /me. Writing one is what the roles
// narrow.
func (s *Service) List(ctx context.Context, a Actor, q Query) ([]View, int64, error) {
	s.log.Debug("list organizations",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if _, err := s.admitted(ctx, a); err != nil {
		return nil, 0, err
	}

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		return nil, 0, s.fail(a, "list organizations", err)
	}

	defaultOrgID, err := s.defaultOrgID(ctx, a)
	if err != nil {
		return nil, 0, err
	}

	views := make([]View, 0, len(rows))
	for _, row := range rows {
		views = append(views, newView(row, defaultOrgID))
	}

	s.log.Debug("listed organizations",
		logger.String("tenant_id", a.TenantID), logger.Int("count", len(views)))
	return views, total, nil
}

// Find reads one organization of the tenant. An id nobody holds answers
// ErrNotFound.
func (s *Service) Find(ctx context.Context, a Actor, orgID string) (View, error) {
	s.log.Debug("read organization",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", orgID))

	if _, err := s.admitted(ctx, a); err != nil {
		return View{}, err
	}

	row, err := s.find(ctx, a, orgID)
	if err != nil {
		return View{}, err
	}

	defaultOrgID, err := s.defaultOrgID(ctx, a)
	if err != nil {
		return View{}, err
	}
	return newView(row, defaultOrgID), nil
}

// Create adds one organization to the tenant.
//
// Only a tenant manager creates one. A new organization belongs to nobody yet,
// so no organization role can reach it.
//
// The row and the audit event land on one transaction. A failed audit write
// rolls the row back, because a change nobody can audit is not allowed to
// stand.
func (s *Service) Create(ctx context.Context, a Actor, name string) (View, error) {
	s.log.Debug("create organization", logger.String("tenant_id", a.TenantID))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return View{}, err
	}
	if !held.tenantManager {
		return View{}, s.refuse(a, "", "create an organization")
	}

	row := Organization{
		ID:        utils.NewUUIDv7(),
		TenantID:  a.TenantID,
		Name:      name,
		State:     StateActive,
		CreatedAt: time.Now().UTC(),
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Insert(ctx, row); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionOrgCreated, row.ID))
	})
	if err != nil {
		return View{}, s.fail(a, "create organization", err)
	}

	s.log.Info("created organization",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", row.ID))

	// A new organization is never the tenant default, so the mark reads false
	// without a second read of the tenant.
	return newView(row, ""), nil
}

// Update renames one organization. A tenant manager renames any of them, and an
// ORG_OWNER renames its own.
func (s *Service) Update(ctx context.Context, a Actor, orgID, name string) (View, error) {
	s.log.Debug("rename organization",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", orgID))

	row, err := s.writable(ctx, a, orgID, "rename an organization")
	if err != nil {
		return View{}, err
	}
	row.Name = name

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Rename(ctx, a.TenantID, orgID, name); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionOrgUpdated, orgID))
	})
	if err != nil {
		return View{}, s.fail(a, "rename organization", err)
	}

	s.log.Info("renamed organization",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID))

	defaultOrgID, err := s.defaultOrgID(ctx, a)
	if err != nil {
		return View{}, err
	}
	return newView(row, defaultOrgID), nil
}

// Delete soft deletes one organization. The row stays in the database, and the
// console never shows it again.
//
// The organization self-registration points at cannot go, because a new person
// would have nowhere to land.
func (s *Service) Delete(ctx context.Context, a Actor, orgID string) error {
	s.log.Debug("delete organization",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", orgID))

	if _, err := s.writable(ctx, a, orgID, "delete an organization"); err != nil {
		return err
	}

	defaultOrgID, err := s.defaultOrgID(ctx, a)
	if err != nil {
		return err
	}
	if orgID == defaultOrgID {
		s.log.Warn("refused a delete of the default organization",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.String("org_id", orgID))
		return fmt.Errorf("%w: %s", ErrDefaultOrg, orgID)
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Delete(ctx, a.TenantID, orgID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionOrgDeleted, orgID))
	})
	if err != nil {
		return s.fail(a, "delete organization", err)
	}

	s.log.Info("deleted organization",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID))
	return nil
}

// writable reads the organization one write names, once the person is allowed
// to write it. The gate runs before the read, so a refusal never reports
// whether the id exists.
func (s *Service) writable(ctx context.Context, a Actor, orgID, what string) (Organization, error) {
	held, err := s.admitted(ctx, a)
	if err != nil {
		return Organization{}, err
	}
	if !held.canWrite(orgID) {
		return Organization{}, s.refuse(a, orgID, what)
	}
	return s.find(ctx, a, orgID)
}

// refuse logs one refused write and returns ErrForbidden.
func (s *Service) refuse(a Actor, orgID, what string) error {
	s.log.Warn("refused a write",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// entry is the audit event one write of this person records.
func (a Actor) entry(action audit.Action, orgID string) audit.Entry {
	return audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityOrganization,
		EntityID:   orgID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
	}
}

// find reads one row. A miss is the caller's answer, not a failure of this
// service, so only a broken read is logged.
func (s *Service) find(ctx context.Context, a Actor, orgID string) (Organization, error) {
	row, err := s.deps.Find(ctx, a.TenantID, orgID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Organization{}, err
		}
		return Organization{}, s.fail(a, "read organization", err)
	}
	return row, nil
}

// admitted reads what the person may do here, and refuses a person who
// administers nothing.
func (s *Service) admitted(ctx context.Context, a Actor) (rights, error) {
	tenantRoles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return rights{}, s.fail(a, "read tenant roles", err)
	}
	memberships, err := s.deps.Memberships(ctx, a.TenantID, a.UserID)
	if err != nil {
		return rights{}, s.fail(a, "read organization memberships", err)
	}

	held := rights{
		tenantManager: slices.Contains(tenantRoles, tenant.RoleIAMOwner) ||
			slices.Contains(tenantRoles, tenant.RoleIAMAdmin),
		orgRoles: make(map[string][]string, len(memberships)),
	}
	for _, m := range memberships {
		held.orgRoles[m.OrgID] = m.Roles
	}

	if !held.admits() {
		s.log.Warn("refused a person without an administrative role",
			logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
		return rights{}, fmt.Errorf("%w: tenant %s, user %s", ErrNotAdmin, a.TenantID, a.UserID)
	}
	return held, nil
}

// defaultOrgID reads the organization self-registration points at.
func (s *Service) defaultOrgID(ctx context.Context, a Actor) (string, error) {
	row, err := s.deps.Tenant(ctx, a.TenantID)
	if err != nil {
		return "", s.fail(a, "read tenant", err)
	}
	return row.DefaultOrgID, nil
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
