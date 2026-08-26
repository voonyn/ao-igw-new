package application

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alphaomega/identitygateway/internal/actor"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/project"
	"alphaomega/identitygateway/internal/utils"
)

// ErrNotAdmin reports that the person holds none of the four administrative
// roles. The bearer guard admits any token minted for the admin resource, so
// the roles decide who reads the applications of a tenant.
var ErrNotAdmin = errors.New("no administrative role")

// ErrForbidden reports that the person administers this tenant or another
// organization, but not the organization the application belongs to.
var ErrForbidden = errors.New("cannot write this application")

// ErrNoClient reports a rotation asked for an application that holds no OIDC
// client. A SAML application is the case.
var ErrNoClient = errors.New("application holds no client")

// ErrPublicClient reports a rotation asked for a client that authenticates with
// PKCE alone. It presents no secret, so a secret minted for it is unusable.
var ErrPublicClient = errors.New("a public client holds no secret")

// Actor is the person behind one admin request. The IP and the user agent reach
// the audit trail, so a change is traceable to where it came from.
type Actor actor.Actor

// Query is the window and the narrowing one list read asks for. Sort names a
// column of the route's allowlist, and a zero State means every state.
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
	// Lister reads one page of applications and the total behind it.
	Lister func(ctx context.Context, tenantID string, q Query) ([]Application, int64, error)

	// Finder reads one application. It returns ErrNotFound on a miss.
	Finder func(ctx context.Context, tenantID, appID string) (Application, error)

	// ConfigLister reads the clients of the applications it is given. An
	// application without a client is absent from the answer.
	ConfigLister func(ctx context.Context, tenantID string, appIDs []string) ([]oidc.Client, error)

	// ProjectFinder reads the project one application sits in. The project
	// names the organization the write gate reads.
	ProjectFinder func(ctx context.Context, tenantID, projectID string) (project.Project, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// role gets an empty answer, not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// MembershipLister reads the organization memberships of one person.
	MembershipLister func(ctx context.Context, tenantID, userID string) ([]organization.Membership, error)

	// Inserter writes one new application.
	Inserter func(ctx context.Context, row Application) error

	// ConfigInserter writes the client of one new application.
	ConfigInserter func(ctx context.Context, row oidc.Client) error

	// Updater writes the name of one application.
	Updater func(ctx context.Context, row Application) error

	// ConfigUpdater writes the settings of one client.
	ConfigUpdater func(ctx context.Context, row oidc.Client) error

	// SecretSetter writes the bcrypt hash of one rotated client secret.
	SecretSetter func(ctx context.Context, tenantID, appID, hash string) error

	// Deleter soft deletes one application and its client.
	Deleter func(ctx context.Context, tenantID, appID string) error
)

// Deps is the database side of the service.
type Deps struct {
	List         Lister
	Find         Finder
	Configs      ConfigLister
	Project      ProjectFinder
	Insert       Inserter
	InsertConfig ConfigInserter
	Update       Updater
	UpdateConfig ConfigUpdater
	SetSecret    SecretSetter
	Delete       Deleter
	TenantRoles  TenantRoleFinder
	Memberships  MembershipLister
	InTx         db.TxRunner
	Audit        *audit.Recorder
	Log          logger.Logger
}

// Service serves the applications of one tenant to the console.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// List reads one page of the applications of the tenant.
//
// Every administrator of the tenant reads the whole list, the same way the
// project list reads. Writing one is what the roles narrow. The console narrows
// the page to one organization with the orgId filter.
func (s *Service) List(ctx context.Context, a Actor, q Query) ([]View, int64, error) {
	s.log.Debug("list applications",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return nil, 0, err
	}

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		return nil, 0, s.fail(a, "list applications", err)
	}

	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	configs, err := s.deps.Configs(ctx, a.TenantID, ids)
	if err != nil {
		return nil, 0, s.fail(a, "read clients", err)
	}
	byApp := make(map[string]oidc.Client, len(configs))
	for _, cfg := range configs {
		byApp[cfg.AppID] = cfg
	}

	views := make([]View, 0, len(rows))
	for _, row := range rows {
		cfg, ok := byApp[row.ID]
		if !ok {
			views = append(views, newView(row, nil))
			continue
		}
		views = append(views, newView(row, &cfg))
	}

	s.log.Debug("listed applications",
		logger.String("tenant_id", a.TenantID), logger.Int("count", len(views)), logger.RequestID(ctx))
	return views, total, nil
}

// Find reads one application of the tenant, with its client. An id nobody holds
// answers ErrNotFound.
func (s *Service) Find(ctx context.Context, a Actor, appID string) (View, error) {
	s.log.Debug("read application",
		logger.String("tenant_id", a.TenantID), logger.String("app_id", appID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return View{}, err
	}

	row, err := s.find(ctx, a, appID)
	if err != nil {
		return View{}, err
	}
	cfg, err := s.client(ctx, a, appID)
	if err != nil {
		return View{}, err
	}
	return newView(row, cfg), nil
}

// Create registers one application in the project the body names, with the
// client the body carries. A tenant manager creates one anywhere, and an
// ORG_OWNER creates one in its own organization.
//
// The application, its client, and the audit event land on one transaction. A
// failed audit write rolls the rows back, because a change nobody can audit is
// not allowed to stand.
//
// A create stores no secret. A confidential client gets one from the first
// rotation, so the secret is disclosed exactly once, in the answer of that
// rotation.
func (s *Service) Create(ctx context.Context, a Actor, body CreateBody) (View, error) {
	s.log.Debug("create application",
		logger.String("tenant_id", a.TenantID), logger.String("project_id", body.ProjectID), logger.RequestID(ctx))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return View{}, err
	}

	// The project names the organization the gate reads, so the project is read
	// before the gate.
	parent, err := s.deps.Project(ctx, a.TenantID, body.ProjectID)
	if err != nil {
		if errors.Is(err, project.ErrNotFound) {
			return View{}, err
		}
		return View{}, s.fail(a, "read project", err)
	}
	if !held.CanWrite(parent.OrgID) {
		return View{}, s.refuse(a, "", "create an application")
	}

	now := time.Now().UTC()
	row := Application{
		ID:          utils.NewUUIDv7(),
		TenantID:    a.TenantID,
		ProjectID:   parent.ID,
		ProjectName: parent.Name,
		OrgID:       parent.OrgID,
		Name:        body.Name,
		AppType:     body.AppType,
		State:       StateActive,
		CreatedAt:   now,
	}

	var cfg *oidc.Client
	if body.OIDC != nil {
		written := body.OIDC.config(a.TenantID, row.ID)
		written.CreatedAt = now
		// A client without an id cannot be reached, so one is minted when the
		// body carries none.
		if written.ClientID == "" {
			written.ClientID = utils.NewUUIDv7()
		}
		cfg = &written
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Insert(ctx, row); err != nil {
			return err
		}
		if cfg != nil {
			if err := s.deps.InsertConfig(ctx, *cfg); err != nil {
				return err
			}
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionAppCreated, row.ID))
	})
	if err != nil {
		return View{}, s.fail(a, "create application", err)
	}

	s.log.Info("created application",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("app_id", row.ID))
	return newView(row, cfg), nil
}

// Update writes the name of one application and the settings of its client. A
// tenant manager writes any of them, and an ORG_OWNER writes those of its own
// organization.
//
// An application does not move between projects, so the stored project stands.
// A body without a client renames the application and leaves the client as it
// is.
func (s *Service) Update(ctx context.Context, a Actor, appID string, body UpdateBody) (View, error) {
	s.log.Debug("update application",
		logger.String("tenant_id", a.TenantID), logger.String("app_id", appID), logger.RequestID(ctx))

	row, err := s.writable(ctx, a, appID, "update an application")
	if err != nil {
		return View{}, err
	}
	row.Name = body.Name

	stored, err := s.client(ctx, a, appID)
	if err != nil {
		return View{}, err
	}

	var cfg *oidc.Client
	if body.OIDC != nil && stored != nil {
		written := body.OIDC.config(a.TenantID, appID)
		// The client id, the stored secret, and the first-party flag are not
		// writable here, so the stored values travel into the answer.
		written.ClientID = stored.ClientID
		written.CreatedAt = stored.CreatedAt
		written.SecretExpiresAt = stored.SecretExpiresAt
		written.IsFirstParty = stored.IsFirstParty
		written.DefaultMaxAge = stored.DefaultMaxAge
		cfg = &written
	} else {
		cfg = stored
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Update(ctx, row); err != nil {
			return err
		}
		if body.OIDC != nil && stored != nil {
			if err := s.deps.UpdateConfig(ctx, *cfg); err != nil {
				return err
			}
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionAppUpdated, appID))
	})
	if err != nil {
		return View{}, s.fail(a, "update application", err)
	}

	s.log.Info("updated application",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("app_id", appID))

	view := newView(row, cfg)
	if view.OIDC != nil && stored != nil {
		view.OIDC.SecretSet = stored.Secret != ""
	}
	return view, nil
}

// Delete soft deletes one application and its client. Both rows stay in the
// database, and the console never shows them again.
func (s *Service) Delete(ctx context.Context, a Actor, appID string) error {
	s.log.Debug("delete application",
		logger.String("tenant_id", a.TenantID), logger.String("app_id", appID), logger.RequestID(ctx))

	if _, err := s.writable(ctx, a, appID, "delete an application"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Delete(ctx, a.TenantID, appID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionAppDeleted, appID))
	})
	if err != nil {
		return s.fail(a, "delete application", err)
	}

	s.log.Info("deleted application",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("app_id", appID))
	return nil
}

// RotateSecret mints one new client secret, stores its bcrypt hash, and answers
// the secret exactly once. The secret is in the answer and nowhere else: it is
// not stored, and it never reaches a log line.
//
// An operator who loses it rotates again. The old secret stops working the
// moment the transaction commits.
func (s *Service) RotateSecret(ctx context.Context, a Actor, appID string) (SecretView, error) {
	s.log.Debug("rotate client secret",
		logger.String("tenant_id", a.TenantID), logger.String("app_id", appID), logger.RequestID(ctx))

	if _, err := s.writable(ctx, a, appID, "rotate a client secret"); err != nil {
		return SecretView{}, err
	}

	cfg, err := s.client(ctx, a, appID)
	if err != nil {
		return SecretView{}, err
	}
	if cfg == nil {
		return SecretView{}, fmt.Errorf("%w: %s", ErrNoClient, appID)
	}
	if cfg.IsPublic() {
		return SecretView{}, fmt.Errorf("%w: %s", ErrPublicClient, cfg.ClientID)
	}

	secret, err := crypto.RandomToken()
	if err != nil {
		return SecretView{}, s.fail(a, "mint a client secret", err)
	}
	hash, err := crypto.HashPassword(secret)
	if err != nil {
		return SecretView{}, s.fail(a, "hash a client secret", err)
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.SetSecret(ctx, a.TenantID, appID, hash); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionAppSecretRotated, appID))
	})
	if err != nil {
		return SecretView{}, s.fail(a, "rotate client secret", err)
	}

	s.log.Info("rotated client secret",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("app_id", appID),
		logger.String("client_id", cfg.ClientID))
	return SecretView{ClientID: cfg.ClientID, Secret: secret}, nil
}

// writable reads the application one write names, once the person is allowed to
// write it.
//
// The row decides which organization the gate reads, so the read runs first. An
// administrator of the tenant therefore learns that an id exists before the
// refusal. Only an administrator reaches this far, and every administrator
// already reads the whole list, so the read discloses nothing the list withheld.
func (s *Service) writable(ctx context.Context, a Actor, appID, what string) (Application, error) {
	held, err := s.admitted(ctx, a)
	if err != nil {
		return Application{}, err
	}

	row, err := s.find(ctx, a, appID)
	if err != nil {
		return Application{}, err
	}
	if !held.CanWrite(row.OrgID) {
		return Application{}, s.refuse(a, appID, what)
	}
	return row, nil
}

// refuse logs one refused write and returns ErrForbidden.
func (s *Service) refuse(a Actor, appID, what string) error {
	s.log.Warn("refused a write",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("app_id", appID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// entry is the audit event one write of this person records.
func (a Actor) entry(action audit.Action, appID string) audit.Entry {
	return audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityApplication,
		EntityID:   appID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
	}
}

// find reads one row. A miss is the caller's answer, not a failure of this
// service, so only a broken read is logged.
func (s *Service) find(ctx context.Context, a Actor, appID string) (Application, error) {
	row, err := s.deps.Find(ctx, a.TenantID, appID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Application{}, err
		}
		return Application{}, s.fail(a, "read application", err)
	}
	return row, nil
}

// client reads the client of one application. An application without one
// answers nil, which is what a SAML application holds.
func (s *Service) client(ctx context.Context, a Actor, appID string) (*oidc.Client, error) {
	rows, err := s.deps.Configs(ctx, a.TenantID, []string{appID})
	if err != nil {
		return nil, s.fail(a, "read client", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// admitted reads what the person may do here, and refuses a person who
// administers nothing.
func (s *Service) admitted(ctx context.Context, a Actor) (organization.Rights, error) {
	tenantRoles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return organization.Rights{}, s.fail(a, "read tenant roles", err)
	}
	memberships, err := s.deps.Memberships(ctx, a.TenantID, a.UserID)
	if err != nil {
		return organization.Rights{}, s.fail(a, "read organization memberships", err)
	}

	held := organization.NewRights(tenantRoles, memberships)

	if !held.Admits() {
		s.log.Warn("refused a person without an administrative role",
			logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
		return organization.Rights{}, fmt.Errorf("%w: tenant %s, user %s", ErrNotAdmin, a.TenantID, a.UserID)
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
