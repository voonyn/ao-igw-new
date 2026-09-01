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
)

// ErrOwnerGrant reports an attempt to confer ORG_OWNER by somebody who does not
// hold it. It answers 403, the same as any other refused write, so the response
// never reports which seats somebody else holds.
var ErrOwnerGrant = errors.New("cannot confer ORG_OWNER")

// ErrLastOwner reports a write that would leave the tenant with nobody sitting
// as IAM_OWNER. Only an IAM_OWNER writes a tenant membership, so a tenant
// without one can never grant one again and recovery would be a SQL statement.
var ErrLastOwner = errors.New("the last IAM_OWNER of the tenant cannot be removed")

// ErrUnknownRole reports a role name outside the scope the write names: an
// organization role on a tenant membership, or a tenant role in an
// organization. Neither means anything where it was sent.
var ErrUnknownRole = errors.New("unknown role for this membership")

// AuthorizeOrgRoleGrant reports whether the caller may confer the roles named
// in one organization.
//
// Only a tenant manager, or a person who sits as ORG_OWNER of that same
// organization, may confer ORG_OWNER. Without this rule an ORG_USER_MANAGER
// mints an owner and outranks itself, because administering the people of an
// organization would include handing out the seat above its own.
//
// held is what the caller holds in the organization the grant names. A seat in
// another organization says nothing here.
func AuthorizeOrgRoleGrant(tenantManager bool, held, wanted []string) error {
	if !slices.Contains(wanted, RoleOrgOwner) {
		return nil
	}
	if tenantManager || slices.Contains(held, RoleOrgOwner) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrOwnerGrant, RoleOrgOwner)
}

// The reads and writes the members service composes its answers from. Each one
// is a function value, so the logic is testable without a database.
//
// The tenant owns tenant_members and the organization owns
// organization_members, so each write is the method of the domain that owns the
// table. One service holds both, because one endpoint serves both rosters: the
// console sends an empty orgId for the tenant and a real one for an
// organization.
type (
	// TenantMemberLister reads one page of the tenant roster.
	TenantMemberLister func(
		ctx context.Context, tenantID string, desc bool, limit, offset int,
	) ([]tenant.Member, int64, error)

	// OrgMemberLister reads one page of the roster of one organization. An
	// empty orgID reads every organization of the tenant.
	OrgMemberLister func(
		ctx context.Context, tenantID, orgID string, desc bool, limit, offset int,
	) ([]Membership, int64, error)

	// TenantMemberSaver grants one tenant membership, or replaces its roles.
	TenantMemberSaver func(ctx context.Context, row tenant.Member) error

	// OrgMemberSaver grants one organization membership, or replaces its roles.
	OrgMemberSaver func(ctx context.Context, row Membership) error

	// TenantMemberDeleter revokes one tenant membership.
	TenantMemberDeleter func(ctx context.Context, tenantID, userID string) error

	// OrgMemberDeleter revokes one organization membership.
	OrgMemberDeleter func(ctx context.Context, tenantID, orgID, userID string) error

	// TenantOwnerCounter reads how many people sit as IAM_OWNER of one tenant.
	TenantOwnerCounter func(ctx context.Context, tenantID string) (int64, error)

	// LocalOwnerLister reads the people who sit as IAM_OWNER of one tenant and
	// whom the local password compare still signs in.
	LocalOwnerLister func(ctx context.Context, tenantID string) ([]tenant.LocalOwner, error)
)

// MemberDeps is the database side of the members service.
type MemberDeps struct {
	ListTenantMembers  TenantMemberLister
	ListOrgMembers     OrgMemberLister
	SaveTenantMember   TenantMemberSaver
	SaveOrgMember      OrgMemberSaver
	DeleteTenantMember TenantMemberDeleter
	DeleteOrgMember    OrgMemberDeleter

	CountTenantOwners TenantOwnerCounter
	LocalTenantOwners LocalOwnerLister

	Org         Finder
	TenantRoles TenantRoleFinder
	Memberships MembershipLister

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// MemberService serves the two rosters of a tenant to the console, and the
// three writes that change them.
type MemberService struct {
	deps MemberDeps
	log  logger.Logger
}

func NewMemberService(deps MemberDeps) *MemberService {
	return &MemberService{deps: deps, log: deps.Log}
}

// holder is what one person holds in this tenant. It carries the tenant role
// names themselves, because a tenant membership is written by an IAM_OWNER
// alone and an IAM_ADMIN must not pass that gate.
type holder struct {
	tenantRoles []string
	orgRoles    map[string][]string
}

// iamOwner reports whether the person owns the tenant.
func (h holder) iamOwner() bool {
	return slices.Contains(h.tenantRoles, tenant.RoleIAMOwner)
}

// tenantManager reports whether the person administers the whole tenant.
func (h holder) tenantManager() bool {
	return h.iamOwner() || slices.Contains(h.tenantRoles, tenant.RoleIAMAdmin)
}

// managesOrg reports whether the person administers the people of one
// organization. A tenant manager administers any of them.
func (h holder) managesOrg(orgID string) bool {
	return h.tenantManager() ||
		slices.Contains(h.orgRoles[orgID], RoleOrgOwner) ||
		slices.Contains(h.orgRoles[orgID], RoleOrgUserManager)
}

// administers reports whether the person administers anything at all.
func (h holder) administers() bool {
	if h.tenantManager() {
		return true
	}
	for orgID := range h.orgRoles {
		if h.managesOrg(orgID) {
			return true
		}
	}
	return false
}

// ListTenant reads one page of the administrator roster of the tenant.
//
// The list is tenant-scoped, so a person who administers one organization reads
// an empty page and not a refusal. The console renders the tab for every
// administrator: an empty table says that none of these memberships are theirs,
// where a 403 says the page is broken.
func (s *MemberService) ListTenant(
	ctx context.Context, a Actor, desc bool, limit, offset int,
) ([]TenantMemberView, int64, error) {
	s.log.Debug("list tenant members",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	held, err := s.admitted(ctx, a)
	if err != nil {
		return nil, 0, err
	}
	// The answer carries [] and never null, because the console iterates it
	// without a guard.
	if !held.tenantManager() {
		return []TenantMemberView{}, 0, nil
	}

	rows, total, err := s.deps.ListTenantMembers(ctx, a.TenantID, desc, limit, offset)
	if err != nil {
		return nil, 0, s.fail(a, "list tenant members", err)
	}

	views := make([]TenantMemberView, 0, len(rows))
	for _, row := range rows {
		views = append(views, TenantMemberView{
			TenantID: row.TenantID,
			UserID:   row.UserID,
			UserName: row.UserName,
			Roles:    orEmpty(row.Roles),
			Created:  row.CreatedAt,
		})
	}
	return views, total, nil
}

// ListOrg reads one page of the roster of one organization. An empty orgID
// reads every organization of the tenant.
//
// Every administrator of the tenant reads it, the same way the user list reads.
// Writing one membership is what the roles narrow.
func (s *MemberService) ListOrg(
	ctx context.Context, a Actor, orgID string, desc bool, limit, offset int,
) ([]OrgMemberView, int64, error) {
	s.log.Debug("list organization members",
		logger.String("tenant_id", a.TenantID), logger.String("org_id", orgID), logger.RequestID(ctx))

	if _, err := s.admitted(ctx, a); err != nil {
		return nil, 0, err
	}

	rows, total, err := s.deps.ListOrgMembers(ctx, a.TenantID, orgID, desc, limit, offset)
	if err != nil {
		return nil, 0, s.fail(a, "list organization members", err)
	}

	views := make([]OrgMemberView, 0, len(rows))
	for _, row := range rows {
		views = append(views, OrgMemberView{
			TenantID: row.TenantID,
			OrgID:    row.OrgID,
			UserID:   row.UserID,
			UserName: row.UserName,
			Roles:    orEmpty(row.Roles),
			Created:  row.CreatedAt,
		})
	}
	return views, total, nil
}

// Add grants one membership: on the tenant when the body names no organization,
// and in that organization when it does.
//
// A membership that was revoked is granted again by this write, which is what
// the console offers. The row and the audit event land on one transaction.
func (s *MemberService) Add(ctx context.Context, a Actor, body MemberBody) error {
	s.log.Debug("grant a membership",
		logger.String("tenant_id", a.TenantID),
		logger.String("org_id", body.OrgID),
		logger.String("target_user_id", body.UserID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, body.OrgID, body.Roles, "grant a membership"); err != nil {
		return err
	}
	return s.save(ctx, a, body.UserID, body.OrgID, body.Roles, audit.ActionMemberAdded, "grant a membership")
}

// UpdateRoles replaces the roles of one sitting member.
//
// The membership must already exist. A write that created one would grant
// access through the endpoint that exists to change it, and it would record the
// change under the wrong action.
func (s *MemberService) UpdateRoles(ctx context.Context, a Actor, userID string, body RolesBody) error {
	s.log.Debug("change the roles of a membership",
		logger.String("tenant_id", a.TenantID),
		logger.String("org_id", body.OrgID),
		logger.String("target_user_id", userID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, body.OrgID, body.Roles, "change the roles of a membership"); err != nil {
		return err
	}
	if err := s.sitting(ctx, a, userID, body.OrgID); err != nil {
		return err
	}
	if err := s.keepsAnOwner(ctx, a, userID, body.OrgID, body.Roles); err != nil {
		return err
	}
	return s.save(ctx, a, userID, body.OrgID, body.Roles,
		audit.ActionMemberUpdated, "change the roles of a membership")
}

// Remove revokes one membership. The person keeps the account and loses every
// role the membership carried.
func (s *MemberService) Remove(ctx context.Context, a Actor, userID, orgID string) error {
	s.log.Debug("revoke a membership",
		logger.String("tenant_id", a.TenantID),
		logger.String("org_id", orgID),
		logger.String("target_user_id", userID), logger.RequestID(ctx))

	// A revoke carries no roles, so it passes the seat gate and the role gate
	// has nothing to read.
	if err := s.authorize(ctx, a, orgID, nil, "revoke a membership"); err != nil {
		return err
	}
	// A revoke leaves the person no roles at all, so it is the same lockout as a
	// role change that drops IAM_OWNER.
	if err := s.keepsAnOwner(ctx, a, userID, orgID, nil); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.revoke(ctx, a, userID, orgID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.memberEntry(audit.ActionMemberRemoved, userID, orgID))
	})
	if err != nil {
		if errors.Is(err, ErrMemberNotFound) {
			return err
		}
		return s.fail(a, "revoke a membership", err)
	}

	s.log.Info("revoked a membership",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("target_user_id", userID))
	return nil
}

// save writes one membership and records one event on the same transaction.
func (s *MemberService) save(
	ctx context.Context, a Actor, userID, orgID string, roles []string,
	action audit.Action, what string,
) error {
	now := time.Now().UTC()

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		var err error
		if orgID == "" {
			err = s.deps.SaveTenantMember(ctx, tenant.Member{
				TenantID: a.TenantID, UserID: userID, Roles: roles, CreatedAt: now,
			})
		} else {
			err = s.deps.SaveOrgMember(ctx, Membership{
				TenantID: a.TenantID, OrgID: orgID, UserID: userID, Roles: roles, CreatedAt: now,
			})
		}
		if err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.memberEntry(action, userID, orgID))
	})
	if err != nil {
		return s.fail(a, what, err)
	}

	s.log.Info(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("target_user_id", userID))
	return nil
}

// revoke removes one membership from the table that holds it. The tenant owns
// its own sentinel, so the answer is turned into this domain's, and the handler
// registers one status for both rosters.
func (s *MemberService) revoke(ctx context.Context, a Actor, userID, orgID string) error {
	if orgID != "" {
		return s.deps.DeleteOrgMember(ctx, a.TenantID, orgID, userID)
	}
	if err := s.deps.DeleteTenantMember(ctx, a.TenantID, userID); err != nil {
		if errors.Is(err, tenant.ErrMemberNotFound) {
			return fmt.Errorf("%w: %s", ErrMemberNotFound, userID)
		}
		return err
	}
	return nil
}

// keepsAnOwner refuses a tenant membership write that would leave nobody
// sitting as IAM_OWNER.
//
// Only an IAM_OWNER writes a tenant membership. A tenant whose last owner went
// can therefore never grant one again, through the console or through the API,
// and recovery would be a SQL statement against the table.
//
// wanted is the roles the write leaves behind: the roles of a role change, and
// nothing at all for a revoke. An organization membership grants no tenant role,
// so the guard has nothing to say about one.
//
// ponytail: the count runs outside the transaction. Two revokes that each take
// one of the last two owners can both read two and both pass. Take a locking
// read inside the transaction if an operator ever hits it.
func (s *MemberService) keepsAnOwner(
	ctx context.Context, a Actor, userID, orgID string, wanted []string,
) error {
	if orgID != "" || slices.Contains(wanted, tenant.RoleIAMOwner) {
		return nil
	}

	held, err := s.deps.TenantRoles(ctx, a.TenantID, userID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}
	if !slices.Contains(held, tenant.RoleIAMOwner) {
		return nil
	}

	owners, err := s.deps.CountTenantOwners(ctx, a.TenantID)
	if err != nil {
		return s.fail(a, "count the owners of the tenant", err)
	}
	if owners <= 1 {
		s.log.Warn("refused a write that would leave the tenant without an owner",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.String("target_user_id", userID))
		return fmt.Errorf("%w: tenant %s, user %s", ErrLastOwner, a.TenantID, userID)
	}
	return s.keepsALocalOwner(ctx, a, userID)
}

// keepsALocalOwner refuses a tenant membership write that would leave nobody
// sitting as IAM_OWNER whom the local password compare signs in.
//
// It runs after the count above, and it refuses writes that count passes. A
// tenant with ten owners a directory proves and one owner this gateway proves
// counts eleven, so the revoke of the eleventh reads ten and goes through, and
// the next directory outage locks every administrator out of the console.
//
// The caller has already read that this person sits as IAM_OWNER, so the only
// question left is whether anybody else is a local owner.
//
// ponytail: the read runs outside the transaction, the way the count above
// already does. Two revokes that each take one of the last two local owners can
// both pass. Take a locking read inside the transaction if an operator ever hits
// it.
func (s *MemberService) keepsALocalOwner(ctx context.Context, a Actor, userID string) error {
	owners, err := s.deps.LocalTenantOwners(ctx, a.TenantID)
	if err != nil {
		return s.fail(a, "read the local owners of the tenant", err)
	}
	if !tenant.LastLocalOwner(owners, func(o tenant.LocalOwner) bool { return o.UserID == userID }) {
		return nil
	}

	s.log.Warn("refused a write that would leave the tenant without a local owner",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID))
	return fmt.Errorf("%w: tenant %s, user %s", tenant.ErrLastLocalOwner, a.TenantID, userID)
}

// authorize is the role gate of every membership write.
//
// A tenant membership grants the whole tenant, so only an IAM_OWNER confers
// one. An organization membership is conferred by a tenant manager, by an
// ORG_OWNER of that organization, or by its ORG_USER_MANAGER, and
// AuthorizeOrgRoleGrant then decides what each of them may hand out.
func (s *MemberService) authorize(ctx context.Context, a Actor, orgID string, roles []string, what string) error {
	held, err := s.admitted(ctx, a)
	if err != nil {
		return err
	}

	if orgID == "" {
		if !held.iamOwner() {
			return s.refuse(a, orgID, what)
		}
		return s.known(a, roles, tenant.RoleIAMOwner, tenant.RoleIAMAdmin)
	}

	if !held.managesOrg(orgID) {
		return s.refuse(a, orgID, what)
	}
	if err := s.known(a, roles, RoleOrgOwner, RoleOrgUserManager); err != nil {
		return err
	}
	if err := AuthorizeOrgRoleGrant(held.tenantManager(), held.orgRoles[orgID], roles); err != nil {
		s.log.Warn("refused a grant of ORG_OWNER",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.String("org_id", orgID))
		return err
	}

	// A tenant manager passes the gate for any organization, so the
	// organization is read as well: a membership of an organization nobody
	// holds is unreachable.
	if _, err := s.deps.Org(ctx, a.TenantID, orgID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return err
		}
		return s.fail(a, "read organization", err)
	}
	return nil
}

// known refuses a role name that means nothing where it was sent. A tenant
// membership and an organization membership name different roles, so the caller
// passes the names its own seat accepts.
//
// The rule is not named for a scope. CONTEXT.md gives Scope the OIDC meaning,
// and one word with two meanings is what the glossary exists to prevent.
func (s *MemberService) known(a Actor, roles []string, allowed ...string) error {
	for _, role := range roles {
		if slices.Contains(allowed, role) {
			continue
		}
		s.log.Warn("refused a role name unknown where it was sent",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.String("role", role))
		return fmt.Errorf("%w: %s", ErrUnknownRole, role)
	}
	return nil
}

// sitting reports that the person already holds the membership one role change
// names. A person with no row answers ErrMemberNotFound.
func (s *MemberService) sitting(ctx context.Context, a Actor, userID, orgID string) error {
	if orgID == "" {
		roles, err := s.deps.TenantRoles(ctx, a.TenantID, userID)
		if err != nil {
			return s.fail(a, "read tenant roles", err)
		}
		if len(roles) == 0 {
			return fmt.Errorf("%w: %s", ErrMemberNotFound, userID)
		}
		return nil
	}

	rows, err := s.deps.Memberships(ctx, a.TenantID, userID)
	if err != nil {
		return s.fail(a, "read organization memberships", err)
	}
	for _, row := range rows {
		if row.OrgID == orgID {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrMemberNotFound, userID)
}

// admitted reads what the person may do here, and refuses a person who
// administers nothing.
func (s *MemberService) admitted(ctx context.Context, a Actor) (holder, error) {
	tenantRoles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return holder{}, s.fail(a, "read tenant roles", err)
	}
	memberships, err := s.deps.Memberships(ctx, a.TenantID, a.UserID)
	if err != nil {
		return holder{}, s.fail(a, "read organization memberships", err)
	}

	held := holder{
		tenantRoles: tenantRoles,
		orgRoles:    make(map[string][]string, len(memberships)),
	}
	for _, m := range memberships {
		held.orgRoles[m.OrgID] = m.Roles
	}

	if !held.administers() {
		s.log.Warn("refused a person without an administrative role",
			logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
		return holder{}, fmt.Errorf("%w: tenant %s, user %s", ErrNotAdmin, a.TenantID, a.UserID)
	}
	return held, nil
}

// refuse logs one refused write and returns ErrForbidden.
func (s *MemberService) refuse(a Actor, orgID, what string) error {
	s.log.Warn("refused a write",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *MemberService) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}

// memberEntry is the audit event one membership write records. The entity is
// the person the membership puts somewhere, because that is the handle an
// operator searches the trail by, and the organization travels beside it.
func (a Actor) memberEntry(action audit.Action, userID, orgID string) audit.Entry {
	entry := audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: audit.EntityMember,
		EntityID:   userID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
	}
	if orgID != "" {
		entry.Metadata = map[string]any{"org_id": orgID}
	}
	return entry
}

// orEmpty turns a nil slice into an empty one, so the answer carries [] and
// never null. The console iterates every list without a guard.
func orEmpty(roles []string) []string {
	if roles == nil {
		return []string{}
	}
	return roles
}
