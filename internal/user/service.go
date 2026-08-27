package user

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"alphaomega/identitygateway/internal/actor"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/di"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
	"alphaomega/identitygateway/internal/utils"
)

// ErrNoAdminRole reports that the person holds none of the four administrative
// roles. The console is for administrators, so the person belongs in the portal.
var ErrNoAdminRole = errors.New("no administrative role")

// ErrForbidden reports that the person administers this tenant or another
// organization, but not the organization the account belongs to.
var ErrForbidden = errors.New("cannot write this user")

// ErrLastOwner reports that the write would take the last sitting IAM_OWNER of
// the tenant out of service. The membership service answers the same slug for
// the revoke of the same seat.
var ErrLastOwner = errors.New("the tenant would keep no owner")

// resetTokenTTL is how long a password reset token stays redeemable. An operator
// hands it over in one sitting, so an hour is long enough, and a value that
// outlives the conversation is a credential nobody is watching.
const resetTokenTTL = time.Hour

// inviteTokenTTL is how long an invitation stays redeemable. Nobody hands it
// over in one sitting: it reaches a person who has no account yet, and they
// answer it when they read the message. A week covers a working week away, and
// an invitation nobody answered by then is one an operator sends again.
const inviteTokenTTL = 7 * 24 * time.Hour

// Actor is the person behind one admin request. The IP and the user agent reach
// the audit trail, so a change is traceable to where it came from.
type Actor actor.Actor

// Query is the window and the narrowing one list read asks for. Sort names a
// column of the route's allowlist, and a zero State or UserType means every one.
type Query struct {
	Search   string
	State    int
	UserType int
	OrgID    string
	Sort     string
	Desc     bool
	Limit    int
	Offset   int
}

// The reads the admin front door composes its answer from. Each one is a
// function value, so the logic is testable without a database.
type (
	// Finder reads one person by id. It returns ErrNotFound on a miss.
	Finder func(ctx context.Context, tenantID, userID string) (User, error)

	// TenantFinder reads the tenant of the request.
	TenantFinder func(ctx context.Context, tenantID string) (tenant.Tenant, error)

	// DomainLister reads the live hostnames of the tenant.
	DomainLister func(ctx context.Context, tenantID string) ([]tenant.Domain, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// role gets an empty answer, not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// OrgLister reads every live organization of the tenant.
	OrgLister func(ctx context.Context, tenantID string) ([]organization.Organization, error)

	// OrgMembershipLister reads the organization memberships of one person.
	OrgMembershipLister func(ctx context.Context, tenantID, userID string) ([]organization.Membership, error)
)

// The reads and writes the administrative half of the service composes its
// answers from. Each one is a function value, so the logic is testable without a
// database.
type (
	// Lister reads one page of accounts and the total behind it.
	Lister func(ctx context.Context, tenantID string, q Query) ([]User, int64, error)

	// Reader reads one account in any state. It returns ErrNoSuchUser on a miss.
	Reader func(ctx context.Context, tenantID, userID string) (User, error)

	// OrgFinder reads the organization a create names. It returns
	// organization.ErrNotFound on a miss.
	OrgFinder func(ctx context.Context, tenantID, orgID string) (organization.Organization, error)

	// Inserter writes one new account.
	Inserter func(ctx context.Context, row User) error

	// HumanInserter writes the person behind one new account.
	HumanInserter func(ctx context.Context, row Human) error

	// MemberInserter writes the organization membership of one new account.
	MemberInserter func(ctx context.Context, row organization.Membership) error

	// HumanUpdater writes the profile of one person.
	HumanUpdater func(ctx context.Context, row Human) error

	// StateSetter writes the state of one account.
	StateSetter func(ctx context.Context, tenantID, userID string, state int) error

	// Unlocker clears the lockout of one account.
	Unlocker func(ctx context.Context, tenantID, userID string) error

	// Deleter soft deletes one account.
	Deleter func(ctx context.Context, tenantID, userID string) error

	// TokenInserter writes one account token.
	TokenInserter func(ctx context.Context, row AccountToken) error

	// MFAClearer removes every second factor of one person.
	MFAClearer func(ctx context.Context, tenantID, userID string) error

	// TenantMemberFinder reads the tenant membership of one person. A person
	// with no membership gets an empty answer, not an error.
	TenantMemberFinder func(ctx context.Context, tenantID, userID string) (tenant.Member, error)

	// TenantOwnerCounter counts how many people sit as IAM_OWNER of the tenant.
	TenantOwnerCounter func(ctx context.Context, tenantID string) (int64, error)

	// DIEnroller registers one person with the Scan Verifier and answers the
	// identifier it keeps for them.
	DIEnroller func(ctx context.Context, u di.EnrolUser) (string, error)

	// DIWriter stores the identifier the Scan Verifier answered.
	DIWriter func(ctx context.Context, tenantID, userID, uuid string) error
)

// Deps is the database side of the service. The first block serves the admin
// front door, and the second serves the eleven administrative endpoints.
type Deps struct {
	Find           Finder
	Tenant         TenantFinder
	Domains        DomainLister
	TenantRoles    TenantRoleFinder
	Orgs           OrgLister
	OrgMemberships OrgMembershipLister

	List         Lister
	Read         Reader
	Org          OrgFinder
	Insert       Inserter
	InsertHuman  HumanInserter
	InsertMember MemberInserter
	UpdateHuman  HumanUpdater
	SetState     StateSetter
	Unlock       Unlocker
	SoftDelete   Deleter
	InsertToken  TokenInserter
	ClearMFA     MFAClearer
	TenantMember TenantMemberFinder

	CountTenantOwners TenantOwnerCounter

	// Enrol and SetDI mirror a newly provisioned person into the Scan Verifier.
	// Both are nil when this deployment runs no Scan Verifier, and a nil Enrol is
	// the one switch: no call goes out, and the console answer carries no
	// enrolment field.
	Enrol DIEnroller
	SetDI DIWriter

	// CheckPassword refuses a password the policy of the organization does not
	// accept. It is the same function value the self-service change takes, so
	// the policy an administrator sets in the console is enforced wherever a
	// password is chosen.
	CheckPassword PasswordChecker

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// Service answers the admin front door.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// Me composes the answer the console reads its shell from.
//
// The person must hold an administrative role, on the tenant or in one
// organization. Anybody else gets ErrNoAdminRole, and the console sends them to
// the portal.
func (s *Service) Me(ctx context.Context, tenantID, userID string) (Me, error) {
	s.log.Debug("read admin me",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	person, err := s.deps.Find(ctx, tenantID, userID)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.log.Error("read user",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", userID),
				logger.Err(err))
		}
		return Me{}, err
	}

	tenantRoles, err := s.deps.TenantRoles(ctx, tenantID, userID)
	if err != nil {
		return Me{}, s.fail(tenantID, userID, "read tenant roles", err)
	}
	memberships, err := s.deps.OrgMemberships(ctx, tenantID, userID)
	if err != nil {
		return Me{}, s.fail(tenantID, userID, "read organization memberships", err)
	}

	tenantManager := holdsAny(tenantRoles, tenant.RoleIAMOwner, tenant.RoleIAMAdmin)
	if !tenantManager && !administersAnyOrg(memberships) {
		s.log.Warn("refused a person without an administrative role",
			logger.String("tenant_id", tenantID), logger.String("user_id", userID))
		return Me{}, fmt.Errorf("%w: tenant %s, user %s", ErrNoAdminRole, tenantID, userID)
	}

	row, err := s.deps.Tenant(ctx, tenantID)
	if err != nil {
		return Me{}, s.fail(tenantID, userID, "read tenant", err)
	}
	domains, err := s.deps.Domains(ctx, tenantID)
	if err != nil {
		return Me{}, s.fail(tenantID, userID, "read tenant domains", err)
	}
	orgs, err := s.deps.Orgs(ctx, tenantID)
	if err != nil {
		return Me{}, s.fail(tenantID, userID, "read organizations", err)
	}

	s.log.Debug("read admin me",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID),
		logger.Bool("tenant_manager", tenantManager), logger.RequestID(ctx))

	return Me{
		UserID:          person.ID,
		Username:        person.Username,
		DisplayName:     person.DisplayName,
		Email:           person.Email,
		Tenant:          meTenant(row, domains),
		IsTenantManager: tenantManager,
		TenantRoles:     orEmpty(tenantRoles),
		OrgMemberships:  meMemberships(memberships),
		AccessibleOrgs:  meOrgs(orgs),
	}, nil
}

// rights is what one person may do in this tenant: administer all of it, or
// administer the organizations named here.
//
// This package keeps its own rule and does not use organization.Rights, which
// the project, organization, and application services share. Those three admit
// an ORG_OWNER only. An ORG_USER_MANAGER administers the people of an
// organization, so canWrite below admits it too. Widening the shared type to
// match would let an ORG_USER_MANAGER write projects and applications, which it
// must never do.
type rights struct {
	tenantManager bool
	orgRoles      map[string][]string
}

// canWrite reports whether the person may write the accounts of one
// organization. A tenant manager writes any of them. In one organization, an
// ORG_USER_MANAGER administers the people, and an ORG_OWNER outranks it, so both
// write.
func (r rights) canWrite(orgID string) bool {
	return r.tenantManager || holdsAny(r.orgRoles[orgID],
		organization.RoleOrgOwner, organization.RoleOrgUserManager)
}

// admits reports whether the person administers anything at all.
func (r rights) admits() bool {
	if r.tenantManager {
		return true
	}
	for _, roles := range r.orgRoles {
		if holdsAny(roles, organization.RoleOrgOwner, organization.RoleOrgUserManager) {
			return true
		}
	}
	return false
}

// List reads one page of the people of the tenant.
//
// Every administrator of the tenant reads the whole list, the same way the
// application list reads. Writing one account is what the roles narrow. The
// console narrows the page to one organization with the orgId filter.
func (s *Service) List(ctx context.Context, a Actor, q Query) ([]View, int64, error) {
	s.log.Debug("list users",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return nil, 0, err
	}

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		return nil, 0, s.fail(a.TenantID, a.UserID, "list users", err)
	}

	views := make([]View, 0, len(rows))
	for _, row := range rows {
		views = append(views, newView(row, s.deps.Enrol != nil))
	}

	s.log.Debug("listed users",
		logger.String("tenant_id", a.TenantID), logger.Int("count", len(views)), logger.RequestID(ctx))
	return views, total, nil
}

// Find reads one account of the tenant, in any state. An id nobody holds answers
// ErrNoSuchUser.
func (s *Service) Find(ctx context.Context, a Actor, userID string) (View, error) {
	s.log.Debug("read user",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return View{}, err
	}

	row, err := s.read(ctx, a, userID)
	if err != nil {
		return View{}, err
	}
	return newView(row, s.deps.Enrol != nil), nil
}

// Create registers one person in the organization the body names, and writes the
// membership that puts them there.
//
// The account, the person, the membership, and the audit event land on one
// transaction. A person with no membership belongs nowhere, and a change nobody
// can audit is not allowed to stand, so all four commit together or none do.
//
// The password is hashed before the transaction opens. It reaches no log line,
// it is not in the answer, and only its bcrypt hash is written.
func (s *Service) Create(ctx context.Context, a Actor, body CreateBody) (View, error) {
	s.log.Debug("create user",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", body.OrgID), logger.RequestID(ctx))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return View{}, err
	}
	if !held.canWrite(body.OrgID) {
		return View{}, s.refuse(a, "", "create a user")
	}

	// A tenant manager passes the gate for any organization, so the organization
	// is read as well: an account of an organization nobody holds is unreachable.
	if _, err := s.deps.Org(ctx, a.TenantID, body.OrgID); err != nil {
		if errors.Is(err, organization.ErrNotFound) {
			return View{}, err
		}
		return View{}, s.fail(a.TenantID, a.UserID, "read organization", err)
	}

	// The password the administrator chose meets the policy of the organization
	// the account lands in, or the create is refused. The refusal names no rule,
	// and it is the refusal a person reads when they change their own password.
	if err := s.deps.CheckPassword(ctx, a.TenantID, body.OrgID, body.Password); err != nil {
		return View{}, err
	}

	hash, err := crypto.HashPassword(body.Password)
	if err != nil {
		return View{}, s.fail(a.TenantID, a.UserID, "hash the password", err)
	}

	now := time.Now().UTC()
	row := User{
		ID:        utils.NewUUIDv7(),
		TenantID:  a.TenantID,
		OrgID:     body.OrgID,
		Username:  body.Username,
		UserType:  TypeHuman,
		State:     StateActive,
		CreatedAt: now,
	}
	person := Human{
		UserID:          row.ID,
		TenantID:        a.TenantID,
		FirstName:       body.FirstName,
		LastName:        body.LastName,
		DisplayName:     body.DisplayName,
		Lang:            body.Lang,
		Email:           body.Email,
		IsEmailVerified: body.EmailVerified,
		PasswordHash:    hash,
		CreatedAt:       now,
	}
	member := organization.Membership{
		TenantID:  a.TenantID,
		OrgID:     body.OrgID,
		UserID:    row.ID,
		Roles:     []string{},
		CreatedAt: now,
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Insert(ctx, row); err != nil {
			return err
		}
		if err := s.deps.InsertHuman(ctx, person); err != nil {
			return err
		}
		if err := s.deps.InsertMember(ctx, member); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserCreated, row.ID))
	})
	if err != nil {
		if errors.Is(err, ErrDuplicateUsername) {
			return View{}, err
		}
		return View{}, s.fail(a.TenantID, a.UserID, "create user", err)
	}

	s.log.Info("created user",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("created_user_id", row.ID))

	person.DIUserUUID = s.enrol(ctx, row, person)
	return newView(withProfile(row, person), s.deps.Enrol != nil), nil
}

// Invite registers one person who has no account yet, puts them in the
// organization the body names, and mints the single-use token they set their
// own password with.
//
// An invitation is a membership grant, so it passes the gate a grant passes,
// and only a tenant manager or a sitting ORG_OWNER may invite an owner. Without
// that rule an ORG_USER_MANAGER mints an owner with one request and outranks
// itself.
//
// The account, the person, the membership, the token, and the audit event land
// on one transaction. The account is written in the initial state and holds no
// password: only the person the link reaches can set one.
func (s *Service) Invite(ctx context.Context, a Actor, body InviteBody) (InviteView, error) {
	s.log.Debug("invite a person",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", body.OrgID), logger.RequestID(ctx))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return InviteView{}, err
	}
	if !held.canWrite(body.OrgID) {
		return InviteView{}, s.refuse(a, "", "invite a person")
	}
	if err := organization.AuthorizeOrgRoleGrant(
		held.tenantManager, held.orgRoles[body.OrgID], body.Roles,
	); err != nil {
		s.log.Warn("refused an invitation that confers ORG_OWNER",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.String("org_id", body.OrgID))
		return InviteView{}, err
	}

	// A tenant manager passes the gate for any organization, so the organization
	// is read as well: an account of an organization nobody holds is unreachable.
	if _, err := s.deps.Org(ctx, a.TenantID, body.OrgID); err != nil {
		if errors.Is(err, organization.ErrNotFound) {
			return InviteView{}, err
		}
		return InviteView{}, s.fail(a.TenantID, a.UserID, "read organization", err)
	}

	token, err := crypto.SessionToken()
	if err != nil {
		return InviteView{}, s.fail(a.TenantID, a.UserID, "mint an invitation token", err)
	}

	username := body.Username
	if username == "" {
		username = body.Email
	}

	now := time.Now().UTC()
	row := User{
		ID:        utils.NewUUIDv7(),
		TenantID:  a.TenantID,
		OrgID:     body.OrgID,
		Username:  username,
		UserType:  TypeHuman,
		State:     StateInitial,
		CreatedAt: now,
	}
	person := Human{
		UserID:      row.ID,
		TenantID:    a.TenantID,
		DisplayName: body.DisplayName,
		Email:       body.Email,
		CreatedAt:   now,
	}
	member := organization.Membership{
		TenantID:  a.TenantID,
		OrgID:     body.OrgID,
		UserID:    row.ID,
		Roles:     body.Roles,
		CreatedAt: now,
	}
	invite := AccountToken{
		ID:        utils.NewUUIDv7(),
		TenantID:  a.TenantID,
		UserID:    row.ID,
		Purpose:   PurposeInvitation,
		TokenHash: crypto.Digest(token),
		ExpiresAt: now.Add(inviteTokenTTL),
		CreatedAt: now,
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Insert(ctx, row); err != nil {
			return err
		}
		if err := s.deps.InsertHuman(ctx, person); err != nil {
			return err
		}
		if err := s.deps.InsertMember(ctx, member); err != nil {
			return err
		}
		if err := s.deps.InsertToken(ctx, invite); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserInvited, row.ID))
	})
	if err != nil {
		if errors.Is(err, ErrDuplicateUsername) {
			return InviteView{}, err
		}
		return InviteView{}, s.fail(a.TenantID, a.UserID, "invite a person", err)
	}

	s.enrol(ctx, row, person)

	s.log.Info("invited a person",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", body.OrgID),
		logger.String("invited_user_id", row.ID),
		logger.String("token_id", invite.ID))

	return InviteView{
		UserID:  row.ID,
		Email:   body.Email,
		Token:   token,
		Expires: invite.ExpiresAt,
	}, nil
}

// Update writes the profile of one person.
//
// Nothing that credentials a sign-in is writable here. The username, the email
// address, and the password each admit somebody, and the body carries none of
// them.
func (s *Service) Update(ctx context.Context, a Actor, userID string, body UpdateBody) (View, error) {
	s.log.Debug("update user",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	row, err := s.writable(ctx, a, userID, "update a user")
	if err != nil {
		return View{}, err
	}

	person := Human{
		UserID:      userID,
		TenantID:    a.TenantID,
		FirstName:   body.FirstName,
		LastName:    body.LastName,
		DisplayName: body.DisplayName,
		Lang:        body.Lang,
		Phone:       body.Phone,
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.UpdateHuman(ctx, person); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserUpdated, userID))
	})
	if err != nil {
		return View{}, s.fail(a.TenantID, a.UserID, "update user", err)
	}

	s.log.Info("updated user",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("updated_user_id", userID))

	row.FirstName = body.FirstName
	row.LastName = body.LastName
	row.DisplayName = body.DisplayName
	row.Lang = body.Lang
	row.Phone = body.Phone
	return newView(row, s.deps.Enrol != nil), nil
}

// Activate returns one account to the state where it can sign in.
func (s *Service) Activate(ctx context.Context, a Actor, userID string) error {
	return s.setState(ctx, a, userID, StateActive, audit.ActionUserActivated, "activate a user")
}

// Deactivate stops one account from signing in. A session that is already open
// is not terminated by this, so an administrator who needs that signs the person
// out as well.
func (s *Service) Deactivate(ctx context.Context, a Actor, userID string) error {
	return s.setState(ctx, a, userID, StateInactive, audit.ActionUserDeactivated, "deactivate a user")
}

// setState writes one state change and records one event on it.
func (s *Service) setState(
	ctx context.Context, a Actor, userID string, state int, action audit.Action, what string,
) error {
	s.log.Debug(what,
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if _, err := s.writable(ctx, a, userID, what); err != nil {
		return err
	}
	// Only the inactive state reads the owner guard. Activating an account is
	// the recovery from that refusal, so it must never be refused by it.
	if state == StateInactive {
		if err := s.keepsAnOwner(ctx, a, userID, what); err != nil {
			return err
		}
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.SetState(ctx, a.TenantID, userID, state); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(action, userID))
	})
	if err != nil {
		return s.fail(a.TenantID, a.UserID, what, err)
	}

	s.log.Info(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID),
		logger.Int("state", state))
	return nil
}

// Unlock clears the lockout of one account and returns it to the active state.
// The person can sign in again at once, with the password they already hold.
func (s *Service) Unlock(ctx context.Context, a Actor, userID string) error {
	s.log.Debug("unlock user",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if _, err := s.writable(ctx, a, userID, "unlock a user"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Unlock(ctx, a.TenantID, userID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserUnlocked, userID))
	})
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "unlock user", err)
	}

	s.log.Info("unlocked user",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID))
	return nil
}

// Delete soft deletes one account. The row stays in the database, and the
// console never shows it again.
func (s *Service) Delete(ctx context.Context, a Actor, userID string) error {
	s.log.Debug("delete user",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if _, err := s.writable(ctx, a, userID, "delete a user"); err != nil {
		return err
	}
	if err := s.keepsAnOwner(ctx, a, userID, "delete a user"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.SoftDelete(ctx, a.TenantID, userID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserDeleted, userID))
	})
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "delete user", err)
	}

	s.log.Info("deleted user",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("deleted_user_id", userID))
	return nil
}

// ResetPassword mints one single-use reset token, stores its digest, and answers
// the token exactly once. The token is in the answer and nowhere else: the row
// holds a SHA-256 digest of it, and it never reaches a log line.
//
// Nothing sends it. The notification transport is a later slice, so until it
// lands the operator hands the value over. An operator who loses it resets
// again, and the stored password is unchanged either way.
func (s *Service) ResetPassword(ctx context.Context, a Actor, userID string) (ResetView, error) {
	s.log.Debug("reset the password of a user",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if _, err := s.writable(ctx, a, userID, "reset the password of a user"); err != nil {
		return ResetView{}, err
	}

	token, err := crypto.SessionToken()
	if err != nil {
		return ResetView{}, s.fail(a.TenantID, a.UserID, "mint a reset token", err)
	}
	now := time.Now().UTC()
	row := AccountToken{
		ID:        utils.NewUUIDv7(),
		TenantID:  a.TenantID,
		UserID:    userID,
		Purpose:   PurposePasswordReset,
		TokenHash: crypto.Digest(token),
		ExpiresAt: now.Add(resetTokenTTL),
		CreatedAt: now,
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.InsertToken(ctx, row); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserPasswordReset, userID))
	})
	if err != nil {
		return ResetView{}, s.fail(a.TenantID, a.UserID, "reset the password of a user", err)
	}

	s.log.Info("reset the password of a user",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID),
		logger.String("token_id", row.ID))
	return ResetView{UserID: userID, Token: token, Expires: row.ExpiresAt}, nil
}

// ResetMFA removes every second factor of one person: the TOTP secret, the
// recovery codes behind it, and every registered passkey.
//
// The console offers one button for all three, because a person who lost their
// authenticator lost every factor it held. They sign in with the password alone
// until they enrol again.
func (s *Service) ResetMFA(ctx context.Context, a Actor, userID string) error {
	s.log.Debug("reset the second factors of a user",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if _, err := s.writable(ctx, a, userID, "reset the second factors of a user"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.ClearMFA(ctx, a.TenantID, userID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserMFAReset, userID))
	})
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "reset the second factors of a user", err)
	}

	s.log.Info("reset the second factors of a user",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID))
	return nil
}

// Memberships reads every scope one person holds a membership in: the tenant,
// and each organization.
//
// Both halves come back whole, not paged. One person's memberships are bounded
// by the organizations they belong to, which is not a growth curve the way the
// user list of a tenant is.
func (s *Service) Memberships(ctx context.Context, a Actor, userID string) (MembershipsView, error) {
	s.log.Debug("read the memberships of a user",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return MembershipsView{}, err
	}

	row, err := s.read(ctx, a, userID)
	if err != nil {
		return MembershipsView{}, err
	}
	name := displayName(row)

	member, err := s.deps.TenantMember(ctx, a.TenantID, userID)
	if err != nil {
		return MembershipsView{}, s.fail(a.TenantID, a.UserID, "read tenant membership", err)
	}
	orgs, err := s.deps.OrgMemberships(ctx, a.TenantID, userID)
	if err != nil {
		return MembershipsView{}, s.fail(a.TenantID, a.UserID, "read organization memberships", err)
	}

	// Both lists carry [] and never null, because the console iterates each of
	// them without a guard.
	out := MembershipsView{
		TenantMemberships: []TenantMemberView{},
		OrgMemberships:    make([]OrgMemberView, 0, len(orgs)),
	}
	if len(member.Roles) > 0 {
		out.TenantMemberships = append(out.TenantMemberships, TenantMemberView{
			TenantID: a.TenantID,
			UserID:   userID,
			UserName: name,
			Roles:    member.Roles,
			Created:  member.CreatedAt,
		})
	}
	for _, m := range orgs {
		out.OrgMemberships = append(out.OrgMemberships, OrgMemberView{
			TenantID: m.TenantID,
			OrgID:    m.OrgID,
			UserID:   m.UserID,
			UserName: name,
			Roles:    orEmpty(m.Roles),
			Created:  m.CreatedAt,
		})
	}
	return out, nil
}

// enrol mirrors one committed person into the Scan Verifier and stores the
// identifier it answers. It returns that identifier, or an empty string.
//
// It runs after the commit and outside the transaction. The Scan Verifier is a
// third party with no compensating delete on this side, so letting its outage
// roll back a committed person would trade a missing mirror for a lost person.
// Every failure here is a warning naming the person, never an error the caller
// sees: the account exists, and the console reads it normally.
//
// The call is synchronous and bounded by the configured timeout. A background
// call would be in-process state, and any instance of this deployment must serve
// any request.
//
// The Scan Verifier keys on the username, so a person with no username is
// skipped. The empty identifier that a skip and a failure both leave is how an
// operator finds who is not mirrored, and how a later retry knows whom to skip.
func (s *Service) enrol(ctx context.Context, row User, person Human) string {
	if s.deps.Enrol == nil || s.deps.SetDI == nil {
		return ""
	}
	if row.Username == "" {
		s.log.Warn("digital identity: skipped a person with no username",
			logger.String("tenant_id", row.TenantID), logger.String("user_id", row.ID))
		return ""
	}

	uuid, err := s.deps.Enrol(ctx, di.EnrolUser{
		FullName: person.DisplayName, // the client falls back to the username
		IDNumber: row.Username,
		Email:    person.Email,
		// The address goes out unverified. The client asserts no verification,
		// because this gateway holds none.
	})
	if err != nil {
		s.log.Warn("digital identity: enrolment failed",
			logger.String("tenant_id", row.TenantID),
			logger.String("user_id", row.ID),
			logger.Err(err))
		return ""
	}
	if err := s.deps.SetDI(ctx, row.TenantID, row.ID, uuid); err != nil {
		// The person is enrolled and the column stays empty, so a retry reading
		// that column enrols them twice. The identifier is carried into this line
		// because the log is then the only place it exists. It is an identifier,
		// not a credential.
		s.log.Warn("digital identity: the enrolment could not be stored",
			logger.String("tenant_id", row.TenantID),
			logger.String("user_id", row.ID),
			logger.String("di_user_uuid", uuid),
			logger.Err(err))
		return ""
	}
	s.log.Info("digital identity: enrolled a person",
		logger.String("tenant_id", row.TenantID), logger.String("user_id", row.ID))
	return uuid
}

// displayName is what the console renders for one person. A profile with no
// display name falls back to the username, because a blank row names nobody.
func displayName(row User) string {
	if row.DisplayName != "" {
		return row.DisplayName
	}
	return row.Username
}

// writable reads the account one write names, once the person is allowed to
// write it.
//
// The row decides which organization the gate reads, so the read runs first. An
// administrator of the tenant therefore learns that an id exists before the
// refusal. Only an administrator reaches this far, and every administrator
// already reads the whole list, so the read discloses nothing the list withheld.
func (s *Service) writable(ctx context.Context, a Actor, userID, what string) (User, error) {
	held, err := s.admitted(ctx, a)
	if err != nil {
		return User{}, err
	}

	row, err := s.read(ctx, a, userID)
	if err != nil {
		return User{}, err
	}
	if !held.canWrite(row.OrgID) {
		return User{}, s.refuse(a, userID, what)
	}
	return row, nil
}

// keepsAnOwner refuses a write that would take the last sitting IAM_OWNER of
// the tenant out of service.
//
// The membership service refuses the revoke of the same seat. This guard covers
// the account itself: a delete leaves the membership row in the table, and a
// deactivate leaves nobody able to activate the account again. Only an IAM_OWNER
// writes a tenant membership, so either one ends with a tenant that can never
// grant the role again, and recovery would be a SQL statement. The count reads
// the account behind each seat, so a seat already emptied this way is not one of
// the owners it reports.
//
// ponytail: the count runs outside the transaction. Two writes that each take
// one of the last two owners can both read two and both pass. Take a locking
// read inside the transaction if an operator ever hits it.
func (s *Service) keepsAnOwner(ctx context.Context, a Actor, userID, what string) error {
	held, err := s.deps.TenantRoles(ctx, a.TenantID, userID)
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "read tenant roles", err)
	}
	if !slices.Contains(held, tenant.RoleIAMOwner) {
		return nil
	}

	owners, err := s.deps.CountTenantOwners(ctx, a.TenantID)
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "count the owners of the tenant", err)
	}
	if owners > 1 {
		return nil
	}

	s.log.Warn("refused a write that would leave the tenant without an owner",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, user %s", ErrLastOwner, what, userID)
}

// refuse logs one refused write and returns ErrForbidden.
func (s *Service) refuse(a Actor, userID, what string) error {
	s.log.Warn("refused a write",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// entry is the audit event one write of this person records.
func (a Actor) entry(action audit.Action, userID string) audit.Entry {
	return audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityUser,
		EntityID:   userID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
	}
}

// withProfile puts the person a create just wrote onto the account row, so the
// answer reads what the two writes stored without reading them back.
func withProfile(row User, person Human) User {
	row.FirstName = person.FirstName
	row.LastName = person.LastName
	row.DisplayName = person.DisplayName
	row.Lang = person.Lang
	row.Email = person.Email
	row.IsEmailVerified = person.IsEmailVerified
	row.DIUserUUID = person.DIUserUUID
	return row
}

// read reads one account. A miss is the caller's answer, not a failure of this
// service, so only a broken read is logged.
func (s *Service) read(ctx context.Context, a Actor, userID string) (User, error) {
	row, err := s.deps.Read(ctx, a.TenantID, userID)
	if err != nil {
		if errors.Is(err, ErrNoSuchUser) {
			return User{}, err
		}
		return User{}, s.fail(a.TenantID, a.UserID, "read user", err)
	}
	return row, nil
}

// admitted reads what the person may do here, and refuses a person who
// administers nothing.
func (s *Service) admitted(ctx context.Context, a Actor) (rights, error) {
	tenantRoles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return rights{}, s.fail(a.TenantID, a.UserID, "read tenant roles", err)
	}
	memberships, err := s.deps.OrgMemberships(ctx, a.TenantID, a.UserID)
	if err != nil {
		return rights{}, s.fail(a.TenantID, a.UserID, "read organization memberships", err)
	}

	held := rights{
		tenantManager: holdsAny(tenantRoles, tenant.RoleIAMOwner, tenant.RoleIAMAdmin),
		orgRoles:      make(map[string][]string, len(memberships)),
	}
	for _, m := range memberships {
		held.orgRoles[m.OrgID] = m.Roles
	}

	if !held.admits() {
		s.log.Warn("refused a person without an administrative role",
			logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
		return rights{}, fmt.Errorf("%w: tenant %s, user %s", ErrNoAdminRole, a.TenantID, a.UserID)
	}
	return held, nil
}

// fail logs one failed read and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *Service) fail(tenantID, userID, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID),
		logger.Err(err))
	return err
}

// administersAnyOrg reports whether the person administers one organization.
func administersAnyOrg(memberships []organization.Membership) bool {
	for _, m := range memberships {
		if holdsAny(m.Roles, organization.RoleOrgOwner, organization.RoleOrgUserManager) {
			return true
		}
	}
	return false
}

// holdsAny reports whether roles carries one of the wanted names.
func holdsAny(roles []string, wanted ...string) bool {
	for _, want := range wanted {
		if slices.Contains(roles, want) {
			return true
		}
	}
	return false
}

func meTenant(row tenant.Tenant, domains []tenant.Domain) MeTenant {
	out := MeTenant{
		ID:           row.ID,
		Name:         row.Name,
		State:        row.State,
		DefaultOrgID: row.DefaultOrgID,
		Created:      row.CreatedAt,
		Domains:      make([]MeDomain, 0, len(domains)),
	}
	for _, d := range domains {
		out.Domains = append(out.Domains, MeDomain{
			Domain:     d.Domain,
			IsPrimary:  d.IsPrimary,
			IsVerified: d.IsVerified,
			State:      d.State,
		})
	}
	return out
}

func meMemberships(rows []organization.Membership) []MeOrgMembership {
	out := make([]MeOrgMembership, 0, len(rows))
	for _, m := range rows {
		out = append(out, MeOrgMembership{
			TenantID: m.TenantID,
			OrgID:    m.OrgID,
			UserID:   m.UserID,
			Roles:    orEmpty(m.Roles),
			Created:  m.CreatedAt,
		})
	}
	return out
}

func meOrgs(rows []organization.Organization) []MeOrg {
	out := make([]MeOrg, 0, len(rows))
	for _, o := range rows {
		out = append(out, MeOrg{ID: o.ID, Name: o.Name})
	}
	return out
}

// orEmpty turns a nil slice into an empty one, so the answer carries [] and
// never null. The console iterates every list without a guard.
func orEmpty(roles []string) []string {
	if roles == nil {
		return []string{}
	}
	return roles
}
