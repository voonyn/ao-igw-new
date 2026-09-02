package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"alphaomega/identitygateway/internal/actor"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
	"alphaomega/identitygateway/internal/utils"
)

// ErrNotAdmin reports that the person holds none of the administrative roles.
// The bearer guard admits any token minted for the admin resource, so the roles
// decide who reads the directories of a tenant.
var ErrNotAdmin = errors.New("no administrative role")

// ErrForbidden reports that the person administers this tenant or another
// organization, but not the level the provider belongs to. A tenant-wide
// provider is written by a tenant manager alone.
var ErrForbidden = errors.New("cannot write this identity provider")

// ErrServerScheme reports a server string that does not match the transport. A
// plain bind and a StartTLS bind carry ldap://, and LDAPS carries ldaps://.
var ErrServerScheme = errors.New("the server does not match the transport")

// ErrLevelFixed reports a write that would move a provider between the tenant
// level and an organization. The level decides which organization a bind creates
// people in, so a move would relocate every person the next bind creates.
var ErrLevelFixed = errors.New("an identity provider does not move between levels")

// ErrLastLink reports the removal of the last Identity Link of a person who
// holds no password hash. That person signs in through the directory and through
// nothing else, so the removal locks them out for ever.
//
// It is the second guard rail of docs/specs/0002-directory-sign-in.md. The
// removal looks like tidy-up, which is why it needs a rail of its own: an
// administrator who unlinks a person expects the person to keep an account, and
// password_hash is NULL.
var ErrLastLink = errors.New("the person would keep no way to sign in")

// ErrUserNotFound reports that the tenant holds no such person. The composition
// root maps the user domain's own sentinel onto this one, so this package
// imports neither the user domain nor the login session domain.
var ErrUserNotFound = errors.New("user not found")

// Actor is the person behind one admin request. The IP and the user agent reach
// the audit trail, so a change is traceable to where it came from.
type Actor actor.Actor

// The reads and writes the service composes its answers from. Each one is a
// function value, so the logic is testable without a database.
type (
	// Lister reads every live provider of one tenant.
	Lister func(ctx context.Context, tenantID string) ([]Provider, error)

	// Finder reads one live provider. It returns ErrNotFound on a miss.
	Finder func(ctx context.Context, tenantID, idpID string) (Provider, error)

	// Inserter writes one new provider.
	Inserter func(ctx context.Context, row Provider) error

	// Updater writes every field of one provider.
	Updater func(ctx context.Context, row Provider) error

	// Deleter marks one provider deleted and releases the domains it claimed.
	Deleter func(ctx context.Context, tenantID, idpID string) error

	// DomainLister reads the live claims of the providers it is given.
	DomainLister func(ctx context.Context, tenantID string, idpIDs []string) ([]Domain, error)

	// Claimer replaces the whole domain list of one provider. It returns
	// ErrDomainClaimed when another live provider already holds one of them.
	Claimer func(ctx context.Context, tenantID, idpID string, claimed []string) error

	// LinkLister reads every Identity Link of one person.
	LinkLister func(ctx context.Context, tenantID, userID string) ([]Link, error)

	// LinkDeleter removes the Identity Link one person holds with one provider.
	LinkDeleter func(ctx context.Context, tenantID, idpID, userID string) error

	// LinkWriter writes one Identity Link. It runs on the caller's transaction.
	LinkWriter func(ctx context.Context, row Link) error

	// LinkedUserFinder answers the person one directory account is tied to, by
	// the stable external id the Identity Link holds. A miss answers
	// ErrLinkNotFound.
	LinkedUserFinder func(ctx context.Context, tenantID, idpID, externalID string) (string, error)

	// SignInReporter reports whether one person can still sign in. A person the
	// tenant does not hold, a deactivated one, a soft-deleted one, and a machine
	// account all answer false.
	//
	// It is a function value, and not a user model, so this package never
	// imports the user domain.
	SignInReporter func(ctx context.Context, tenantID, userID string) (bool, error)

	// PersonCreator writes the local rows of one new person and answers the id
	// it wrote. It runs on the caller's transaction.
	//
	// It is a function value, and not a user model, so this package never
	// imports the user domain. The composition root writes the account, the
	// person, and the membership behind it.
	PersonCreator func(ctx context.Context, p Person) (string, error)

	// OrgFinder reads one organization. It returns organization.ErrNotFound on a
	// miss, so no org id can name a level the tenant does not hold.
	OrgFinder func(ctx context.Context, tenantID, orgID string) (organization.Organization, error)

	// UserOrgFinder answers the organization one person belongs to. A person the
	// tenant does not hold answers ErrUserNotFound. It is a function value and
	// not a user model, so this package never imports the user domain.
	UserOrgFinder func(ctx context.Context, tenantID, userID string) (string, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// role gets an empty answer, not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// LocalOwnerLister reads the people who sit as IAM_OWNER of one tenant and
	// whom the local password compare still signs in.
	LocalOwnerLister func(ctx context.Context, tenantID string) ([]tenant.LocalOwner, error)

	// PasswordReporter reports whether one person holds a password hash. A
	// person the tenant does not hold answers false, because they hold none.
	//
	// It is a function value, and not a user model, so this package never
	// imports the user domain. No caller ever reads the hash itself.
	PasswordReporter func(ctx context.Context, tenantID, userID string) (bool, error)

	// MembershipLister reads the organization memberships of one person.
	MembershipLister func(ctx context.Context, tenantID, userID string) ([]organization.Membership, error)

	// RateLimiter records one hit against key and reports whether the trailing
	// window is still within limit. cache.Client.AllowInWindow satisfies it.
	RateLimiter func(ctx context.Context, key string, limit int, window time.Duration) (bool, error)

	// RateReleaser gives one hit of key back. cache.Client.ReleaseInWindow
	// satisfies it. See Service.releaseBind.
	RateReleaser func(ctx context.Context, key string) error
)

// Deps is the database side of the service.
type Deps struct {
	List    Lister
	Find    Finder
	Insert  Inserter
	Update  Updater
	Delete  Deleter
	Domains DomainLister
	Claim   Claimer

	Links LinkLister

	// Linked is the live active providers that take a typed password and that
	// one person holds an Identity Link with. The resolver names the provider of
	// a sign-in with it, the guard rail on the unlink counts the links that
	// still sign somebody in, and Service.PersonOf refuses a bind whose entry
	// another link of the same provider names.
	Linked       LinkedFinder
	DeleteLink   LinkDeleter
	WriteLink    LinkWriter
	CreatePerson PersonCreator

	// The three reads of the sign-in bind. FindLink names the person the proved
	// directory account is tied to, and CanSignIn says whether that person may
	// still sign in. See Service.PersonOf.
	//
	// Held is the read of the first bind, and it filters neither the state nor
	// the soft delete. It is the same read the resolver carries as
	// ResolverDeps.Held, and Service.heldAlready states why the write needs one
	// of its own.
	FindLink  LinkedUserFinder
	CanSignIn SignInReporter
	Held      PersonFinder

	Org         OrgFinder
	UserOrg     UserOrgFinder
	TenantRoles TenantRoleFinder
	Memberships MembershipLister

	// The two reads behind the guard rails. LocalOwners refuses a domain claim
	// that would take the last local IAM_OWNER of the tenant, and HasPassword
	// refuses the removal of the last Identity Link of a person who holds no
	// password hash. See docs/specs/0002-directory-sign-in.md.
	LocalOwners LocalOwnerLister
	HasPassword PasswordReporter

	// Allow is the connection test budget and the sign-in bind budget. Both are
	// Redis-only exceptions to the stateless rule CLAUDE.md lists: no table holds
	// either counter, and a cache failure refuses the call instead of letting an
	// outbound call through. See Service.spendTest and Service.spendBind.
	//
	// Release gives one bind back when the directory did not answer, so an outage
	// costs the person nothing. Only Service.Prove releases: the connection test
	// meters a call its own administrator drove, and a refund there would leave
	// that call unmetered. See Service.releaseBind.
	Allow   RateLimiter
	Release RateReleaser

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// Service serves the identity providers of one tenant to the console.
//
// No method of this service ever puts a bind password in a log line, in an audit
// row, or in an answer. The repository opens the credential on a read because
// the sign-in bind needs it, and every view drops it.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// List reads every live provider of the tenant, with the domains each one
// claims.
//
// Every administrator of the tenant reads the whole list, the same way the
// application list reads. Writing one is what the roles narrow.
func (s *Service) List(ctx context.Context, a Actor) ([]View, error) {
	s.log.Debug("list identity providers",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID),
		logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return nil, err
	}

	rows, err := s.deps.List(ctx, a.TenantID)
	if err != nil {
		return nil, s.fail(a, "list identity providers", err)
	}

	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}
	claims, err := s.deps.Domains(ctx, a.TenantID, ids)
	if err != nil {
		return nil, s.fail(a, "read the claimed domains", err)
	}
	byProvider := make(map[string][]string, len(rows))
	for _, claim := range claims {
		byProvider[claim.IdpID] = append(byProvider[claim.IdpID], claim.Domain)
	}

	views := make([]View, 0, len(rows))
	for _, row := range rows {
		row.Domains = byProvider[row.ID]
		views = append(views, newView(row))
	}

	s.log.Debug("listed identity providers",
		logger.String("tenant_id", a.TenantID), logger.Int("count", len(views)),
		logger.RequestID(ctx))
	return views, nil
}

// Find reads one live provider of the tenant, with the domains it claims. An id
// nobody holds, and a soft-deleted provider, both answer ErrNotFound.
func (s *Service) Find(ctx context.Context, a Actor, idpID string) (View, error) {
	s.log.Debug("read identity provider",
		logger.String("tenant_id", a.TenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return View{}, err
	}

	row, err := s.withDomains(ctx, a, idpID)
	if err != nil {
		return View{}, err
	}

	s.log.Debug("read the identity provider",
		logger.String("tenant_id", a.TenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))
	return newView(row), nil
}

// Create registers one directory at the level the body names. A tenant manager
// creates one anywhere, and an ORG_OWNER creates one in its own organization.
//
// The provider, its domain claims, and the audit event land on one transaction.
// A domain another live provider already holds answers ErrDomainClaimed and
// leaves nothing behind.
func (s *Service) Create(ctx context.Context, a Actor, body Body) (View, error) {
	s.log.Debug("create identity provider",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", body.OrgID),
		logger.RequestID(ctx))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return View{}, err
	}
	if !held.CanWrite(body.OrgID) {
		return View{}, s.refuse(a, "", "create an identity provider")
	}
	if err := s.checkBody(ctx, a, body); err != nil {
		return View{}, err
	}

	row := body.apply(Provider{
		ID:        utils.NewUUIDv7(),
		TenantID:  a.TenantID,
		OrgID:     body.OrgID,
		CreatedAt: time.Now().UTC(),
	})

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Insert(ctx, row); err != nil {
			return err
		}
		if err := s.deps.Claim(ctx, a.TenantID, row.ID, row.Domains); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionIdpCreated, row.ID, row.OrgID))
	})
	if err != nil {
		if errors.Is(err, ErrDomainClaimed) || errors.Is(err, ErrNameTaken) {
			return View{}, err
		}
		return View{}, s.fail(a, "create identity provider", err)
	}

	s.log.Info("created identity provider",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("idp_id", row.ID))
	return newView(row), nil
}

// Update writes every field of one provider, and replaces the domains it claims.
//
// The level is not writable. A provider that moved between the tenant level and
// an organization would relocate every person the next bind creates, so a body
// that names another level answers ErrLevelFixed.
//
// The bind password is write-only. An absent field keeps the stored credential,
// an empty string clears it, and a value replaces it.
func (s *Service) Update(ctx context.Context, a Actor, idpID string, body Body) (View, error) {
	s.log.Debug("update identity provider",
		logger.String("tenant_id", a.TenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	stored, err := s.writable(ctx, a, idpID, "update an identity provider")
	if err != nil {
		return View{}, err
	}
	if body.OrgID != stored.OrgID {
		return View{}, fmt.Errorf("%w: provider %s", ErrLevelFixed, idpID)
	}
	if err := s.checkBody(ctx, a, body); err != nil {
		return View{}, err
	}

	row := body.apply(stored)

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Update(ctx, row); err != nil {
			return err
		}
		if err := s.deps.Claim(ctx, a.TenantID, row.ID, row.Domains); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionIdpUpdated, row.ID, row.OrgID))
	})
	if err != nil {
		if errors.Is(err, ErrDomainClaimed) || errors.Is(err, ErrNameTaken) {
			return View{}, err
		}
		return View{}, s.fail(a, "update identity provider", err)
	}

	s.log.Info("updated identity provider",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("idp_id", row.ID))
	return newView(row), nil
}

// Delete marks one provider deleted. The row stays in the database, the console
// never shows it again, and the domains it claimed are released.
func (s *Service) Delete(ctx context.Context, a Actor, idpID string) error {
	s.log.Debug("delete identity provider",
		logger.String("tenant_id", a.TenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	stored, err := s.writable(ctx, a, idpID, "delete an identity provider")
	if err != nil {
		return err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Delete(ctx, a.TenantID, idpID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionIdpDeleted, idpID, stored.OrgID))
	})
	if err != nil {
		return s.fail(a, "delete identity provider", err)
	}

	s.log.Info("deleted identity provider",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("idp_id", idpID))
	return nil
}

// Links reads every Identity Link of one person. Every administrator of the
// tenant reads them, the same way the user list reads.
func (s *Service) Links(ctx context.Context, a Actor, userID string) ([]LinkView, error) {
	s.log.Debug("list identity links",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID),
		logger.String("subject_id", userID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return nil, err
	}
	// The read names the person, so a person the tenant does not hold answers a
	// miss instead of an empty list.
	if _, err := s.personOrg(ctx, a, userID); err != nil {
		return nil, err
	}

	rows, err := s.deps.Links(ctx, a.TenantID, userID)
	if err != nil {
		return nil, s.fail(a, "list identity links", err)
	}

	views := make([]LinkView, 0, len(rows))
	for _, row := range rows {
		views = append(views, newLinkView(row))
	}
	s.log.Debug("listed identity links",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID),
		logger.String("subject_id", userID), logger.Int("count", len(views)), logger.RequestID(ctx))
	return views, nil
}

// Unlink removes the Identity Link one person holds with one provider. The row
// is hard deleted, and the idp.unlinked audit row is the record.
//
// A tenant manager unlinks anybody, and an ORG_OWNER unlinks a person of its own
// organization.
func (s *Service) Unlink(ctx context.Context, a Actor, userID, idpID string) error {
	s.log.Debug("delete identity link",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID),
		logger.String("subject_id", userID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return err
	}
	orgID, err := s.personOrg(ctx, a, userID)
	if err != nil {
		return err
	}
	if !held.CanWrite(orgID) {
		return s.refuse(a, idpID, "unlink an identity")
	}
	if err := s.keepsACredential(ctx, a, userID, idpID); err != nil {
		return err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.DeleteLink(ctx, a.TenantID, idpID, userID); err != nil {
			return err
		}
		entry := a.entry(audit.ActionIdpUnlinked, idpID, orgID)
		entry.Metadata["user_id"] = userID
		return s.deps.Audit.Record(ctx, entry)
	})
	if err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			return err
		}
		return s.fail(a, "delete identity link", err)
	}

	s.log.Info("deleted identity link",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("subject_id", userID),
		logger.String("idp_id", idpID))
	return nil
}

// checkShape runs the rules a validate tag cannot carry: the transport of every
// server string, and the two organizations the row names.
//
// The plaintext confirmation is a tag, because the answer names the field the
// console must tick. See Body.ConfirmPlaintext.
//
// A connection test stops here. It dials, binds and searches, and it reads no
// domain, so the last-owner rail below belongs to the save alone.
func (s *Service) checkShape(ctx context.Context, a Actor, body Body) error {
	if err := checkServers(body.Mode, body.Servers); err != nil {
		return err
	}
	for _, orgID := range []string{body.OrgID, body.DefaultOrgID} {
		if orgID == "" {
			continue
		}
		if _, err := s.deps.Org(ctx, a.TenantID, orgID); err != nil {
			if errors.Is(err, organization.ErrNotFound) {
				return err
			}
			return s.fail(a, "read the organization", err)
		}
	}
	return nil
}

// checkBody runs every rule of one write: the shape above, and the domain claim
// the write stores.
func (s *Service) checkBody(ctx context.Context, a Actor, body Body) error {
	if err := s.checkShape(ctx, a, body); err != nil {
		return err
	}
	return s.keepsALocalOwner(ctx, a, body)
}

// keepsALocalOwner refuses a domain claim that would leave the tenant with no
// IAM_OWNER whom the local password compare signs in.
//
// A claim ties people the same way an Identity Link does, and it is the easier
// one to miss. Provider Resolution case 1 outranks case 3, so claiming
// corp.example routes every person whose email address carries it to the
// directory, including the people who hold a local password and no directory
// account. One directory outage would then lock every administrator out of the
// console.
//
// An inactive provider claims nothing that routes anybody, so the guard reads
// the state the write stores and not the state the row holds. A write that
// switches a provider on runs the guard with the claims it switches on.
//
// LocalOwners already drops the owners a live active claim routes today, so a
// write that stores the claims it already holds refuses nothing new.
func (s *Service) keepsALocalOwner(ctx context.Context, a Actor, body Body) error {
	claimed := domains(body.Domains)
	if body.State != StateActive || len(claimed) == 0 {
		return nil
	}

	owners, err := s.deps.LocalOwners(ctx, a.TenantID)
	if err != nil {
		return s.fail(a, "read the local owners of the tenant", err)
	}
	takes := func(owner tenant.LocalOwner) bool {
		return slices.Contains(claimed, emailDomain(owner.Email))
	}
	if !tenant.LastLocalOwner(owners, takes) {
		return nil
	}

	s.log.Warn("refused a domain claim that would leave the tenant without a local owner",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
	return fmt.Errorf("%w: tenant %s", tenant.ErrLastLocalOwner, a.TenantID)
}

// keepsACredential refuses the removal of the last Identity Link of a person who
// holds no password hash.
//
// A person the directory owns holds a NULL password_hash for ever, so the link
// is the whole of their credential. The removal looks like tidy-up and it locks
// them out for ever, and no console screen can put the link back.
//
// A person who holds a password hash keeps a way in, so the removal goes
// through. So does the removal of one link out of two, and so does a link the
// person does not hold at all: DeleteLink answers that miss itself.
//
// The read is the resolver's, and not the console list, so it counts the links
// that still sign somebody in. A link with a provider that is inactive or soft
// deleted signs nobody in already, and refusing its removal would trap the
// administrator who is moving those people off a directory that is gone. That is
// the same reason the delete of a provider is never blocked by its live links.
func (s *Service) keepsACredential(ctx context.Context, a Actor, userID, idpID string) error {
	held, err := s.deps.HasPassword(ctx, a.TenantID, userID)
	if err != nil {
		return s.fail(a, "read whether the person holds a password", err)
	}
	if held {
		return nil
	}

	working, err := s.deps.Linked(ctx, a.TenantID, userID)
	if err != nil {
		return s.fail(a, "read the linked identity providers of the person", err)
	}
	if len(working) == 0 {
		return nil
	}
	for _, linkedIdpID := range working {
		if linkedIdpID != idpID {
			return nil
		}
	}

	s.log.Warn("refused the removal of the last identity link of a person who holds no password",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("subject_id", userID),
		logger.String("idp_id", idpID))
	return fmt.Errorf("%w: tenant %s, user %s", ErrLastLink, a.TenantID, userID)
}

// withDomains reads one provider and the domains it claims.
func (s *Service) withDomains(ctx context.Context, a Actor, idpID string) (Provider, error) {
	row, err := s.find(ctx, a, idpID)
	if err != nil {
		return Provider{}, err
	}

	claims, err := s.deps.Domains(ctx, a.TenantID, []string{idpID})
	if err != nil {
		return Provider{}, s.fail(a, "read the claimed domains", err)
	}
	for _, claim := range claims {
		row.Domains = append(row.Domains, claim.Domain)
	}
	return row, nil
}

// writable reads the provider one write names, once the person is allowed to
// write it.
//
// The row decides which level the gate reads, so the read runs first. Only an
// administrator reaches this far, and every administrator already reads the
// whole list, so the read discloses nothing the list withheld.
func (s *Service) writable(ctx context.Context, a Actor, idpID, what string) (Provider, error) {
	held, err := s.admitted(ctx, a)
	if err != nil {
		return Provider{}, err
	}

	row, err := s.find(ctx, a, idpID)
	if err != nil {
		return Provider{}, err
	}
	if !held.CanWrite(row.OrgID) {
		return Provider{}, s.refuse(a, idpID, what)
	}
	return row, nil
}

// find reads one row. A miss is the caller's answer, not a failure of this
// service, so only a broken read is logged.
func (s *Service) find(ctx context.Context, a Actor, idpID string) (Provider, error) {
	row, err := s.deps.Find(ctx, a.TenantID, idpID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Provider{}, err
		}
		return Provider{}, s.fail(a, "read identity provider", err)
	}
	return row, nil
}

// personOrg reads the organization one person belongs to. A person the tenant
// does not hold is the caller's answer, not a failure of this service.
func (s *Service) personOrg(ctx context.Context, a Actor, userID string) (string, error) {
	orgID, err := s.deps.UserOrg(ctx, a.TenantID, userID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return "", err
		}
		return "", s.fail(a, "read the person", err)
	}
	return orgID, nil
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

// refuse logs one refused write and returns ErrForbidden.
func (s *Service) refuse(a Actor, idpID, what string) error {
	s.log.Warn("refused a write",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("idp_id", idpID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// entry is the audit event one write of this person records. The metadata names
// the level, and it never names a credential of any kind.
func (a Actor) entry(action audit.Action, idpID, orgID string) audit.Entry {
	return audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityIdentityProvider,
		EntityID:   idpID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
		Metadata:   map[string]any{"org_id": orgID},
	}
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
