package project

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
	"alphaomega/identitygateway/internal/utils"
)

// ErrNotAdmin reports that the person holds none of the four administrative
// roles. The bearer guard admits any token minted for the admin resource, so
// the roles decide who reads the projects of a tenant.
var ErrNotAdmin = errors.New("no administrative role")

// ErrForbidden reports that the person administers this tenant or another
// organization, but not the organization the project belongs to.
var ErrForbidden = errors.New("cannot write this project")

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
	OrgID  string
	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// The reads and writes the service composes its answers from. Each one is a
// function value, so the logic is testable without a database.
type (
	// Lister reads one page of projects and the total behind it.
	Lister func(ctx context.Context, tenantID string, q Query) ([]Project, int64, error)

	// Finder reads one project. It returns ErrNotFound on a miss.
	Finder func(ctx context.Context, tenantID, projectID string) (Project, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// role gets an empty answer, not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// MembershipLister reads the organization memberships of one person.
	MembershipLister func(ctx context.Context, tenantID, userID string) ([]organization.Membership, error)

	// Inserter writes one new project.
	Inserter func(ctx context.Context, row Project) error

	// Updater writes the name and the four settings of one project.
	Updater func(ctx context.Context, row Project) error

	// Deleter soft deletes one project.
	Deleter func(ctx context.Context, tenantID, projectID string) error
)

// Deps is the database side of the service.
type Deps struct {
	List        Lister
	Find        Finder
	Insert      Inserter
	Update      Updater
	Delete      Deleter
	TenantRoles TenantRoleFinder
	Memberships MembershipLister
	InTx        db.TxRunner
	Audit       *audit.Recorder
	Log         logger.Logger
}

// Service serves the projects of one tenant to the console.
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

// canWrite reports whether the person may write the projects of one
// organization. A tenant manager writes any of them, and an ORG_OWNER writes
// those of its own organization.
func (r rights) canWrite(orgID string) bool {
	return r.tenantManager || slices.Contains(r.orgRoles[orgID], organization.RoleOrgOwner)
}

// admits reports whether the person administers anything at all.
func (r rights) admits() bool {
	if r.tenantManager {
		return true
	}
	for _, roles := range r.orgRoles {
		if slices.Contains(roles, organization.RoleOrgOwner) ||
			slices.Contains(roles, organization.RoleOrgUserManager) {
			return true
		}
	}
	return false
}

// List reads one page of the projects of the tenant.
//
// Every administrator of the tenant reads the whole list, the same way the
// organization list reads. Writing one is what the roles narrow. The console
// narrows the page to one organization with the orgId filter.
func (s *Service) List(ctx context.Context, a Actor, q Query) ([]View, int64, error) {
	s.log.Debug("list projects",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if _, err := s.admitted(ctx, a); err != nil {
		return nil, 0, err
	}

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		return nil, 0, s.fail(a, "list projects", err)
	}

	views := make([]View, 0, len(rows))
	for _, row := range rows {
		views = append(views, newView(row))
	}

	s.log.Debug("listed projects",
		logger.String("tenant_id", a.TenantID), logger.Int("count", len(views)))
	return views, total, nil
}

// Find reads one project of the tenant. An id nobody holds answers ErrNotFound.
func (s *Service) Find(ctx context.Context, a Actor, projectID string) (View, error) {
	s.log.Debug("read project",
		logger.String("tenant_id", a.TenantID), logger.String("project_id", projectID))

	if _, err := s.admitted(ctx, a); err != nil {
		return View{}, err
	}

	row, err := s.find(ctx, a, projectID)
	if err != nil {
		return View{}, err
	}
	return newView(row), nil
}

// Create adds one project to the organization the body names. A tenant manager
// creates one anywhere, and an ORG_OWNER creates one in its own organization.
//
// The row and the audit event land on one transaction. A failed audit write
// rolls the row back, because a change nobody can audit is not allowed to
// stand.
func (s *Service) Create(ctx context.Context, a Actor, body CreateBody) (View, error) {
	s.log.Debug("create project",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", body.OrgID))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return View{}, err
	}
	if !held.canWrite(body.OrgID) {
		return View{}, s.refuse(a, "", "create a project")
	}

	row := Project{
		ID:              utils.NewUUIDv7(),
		TenantID:        a.TenantID,
		OrgID:           body.OrgID,
		Name:            body.Name,
		State:           StateActive,
		RoleAssertion:   body.RoleAssertion,
		RoleCheck:       body.RoleCheck,
		HasProjectCheck: body.HasProjectCheck,
		PrivateLabeling: body.PrivateLabeling,
		CreatedAt:       time.Now().UTC(),
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Insert(ctx, row); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionProjectCreated, row.ID))
	})
	if err != nil {
		return View{}, s.fail(a, "create project", err)
	}

	s.log.Info("created project",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("project_id", row.ID))
	return newView(row), nil
}

// Update writes the name and the four settings of one project. A tenant manager
// writes any of them, and an ORG_OWNER writes those of its own organization.
//
// A project does not move between organizations, so the stored organization
// stands.
func (s *Service) Update(ctx context.Context, a Actor, projectID string, body UpdateBody) (View, error) {
	s.log.Debug("update project",
		logger.String("tenant_id", a.TenantID), logger.String("project_id", projectID))

	row, err := s.writable(ctx, a, projectID, "update a project")
	if err != nil {
		return View{}, err
	}
	row.Name = body.Name
	row.RoleAssertion = body.RoleAssertion
	row.RoleCheck = body.RoleCheck
	row.HasProjectCheck = body.HasProjectCheck
	row.PrivateLabeling = body.PrivateLabeling

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Update(ctx, row); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionProjectUpdated, projectID))
	})
	if err != nil {
		return View{}, s.fail(a, "update project", err)
	}

	s.log.Info("updated project",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("project_id", projectID))
	return newView(row), nil
}

// Delete soft deletes one project. The row stays in the database, and the
// console never shows it again.
//
// The applications of the project are not touched. They carry their own rows,
// and slice 3 owns them.
func (s *Service) Delete(ctx context.Context, a Actor, projectID string) error {
	s.log.Debug("delete project",
		logger.String("tenant_id", a.TenantID), logger.String("project_id", projectID))

	if _, err := s.writable(ctx, a, projectID, "delete a project"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Delete(ctx, a.TenantID, projectID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionProjectDeleted, projectID))
	})
	if err != nil {
		return s.fail(a, "delete project", err)
	}

	s.log.Info("deleted project",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("project_id", projectID))
	return nil
}

// writable reads the project one write names, once the person is allowed to
// write it.
//
// The row decides which organization the gate reads, so the read runs first. An
// administrator of the tenant therefore learns that an id exists before the
// refusal. Only an administrator reaches this far, and every administrator
// already reads the whole list, so the read discloses nothing the list withheld.
func (s *Service) writable(ctx context.Context, a Actor, projectID, what string) (Project, error) {
	held, err := s.admitted(ctx, a)
	if err != nil {
		return Project{}, err
	}

	row, err := s.find(ctx, a, projectID)
	if err != nil {
		return Project{}, err
	}
	if !held.canWrite(row.OrgID) {
		return Project{}, s.refuse(a, projectID, what)
	}
	return row, nil
}

// refuse logs one refused write and returns ErrForbidden.
func (s *Service) refuse(a Actor, projectID, what string) error {
	s.log.Warn("refused a write",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("project_id", projectID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// entry is the audit event one write of this person records.
func (a Actor) entry(action audit.Action, projectID string) audit.Entry {
	return audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityProject,
		EntityID:   projectID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
	}
}

// find reads one row. A miss is the caller's answer, not a failure of this
// service, so only a broken read is logged.
func (s *Service) find(ctx context.Context, a Actor, projectID string) (Project, error) {
	row, err := s.deps.Find(ctx, a.TenantID, projectID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Project{}, err
		}
		return Project{}, s.fail(a, "read project", err)
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

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *Service) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}
