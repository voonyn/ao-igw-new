package organization

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// memberDeps is what one members test stands the service up with. The first
// three fields are the caller's own rights, and the last two are what the reads
// answer.
type memberDeps struct {
	tenantRoles []string
	memberships []Membership

	targetTenantRoles []string
	targetMemberships []Membership

	tenantRows []tenant.Member
	orgRows    []Membership

	// tenantOwners is how many people sit as IAM_OWNER of the tenant, the
	// revoke of one included.
	tenantOwners int64

	// localOwners is the owners the local password compare still signs in. An
	// empty list is a tenant with none, which the first guard rail leaves alone.
	localOwners []tenant.LocalOwner

	auditFails bool
}

// What the writes of one test did. testMemberService clears them, and the tests
// of one package run one after another, so each test reads its own writes.
var (
	tenantSaves   []tenant.Member
	orgSaves      []Membership
	memberRevokes []string
	memberEvents  []audit.Event
)

// wrote reports how many membership writes the test has seen.
func wrote() int {
	return len(tenantSaves) + len(orgSaves) + len(memberRevokes)
}

func testMemberService(t *testing.T, d memberDeps) *MemberService {
	t.Helper()
	log, _ := logger.NewObserved()
	tenantSaves, orgSaves, memberRevokes, memberEvents = nil, nil, nil, nil

	record := func(_ context.Context, e audit.Event) error {
		if d.auditFails {
			return errors.New("the audit write failed")
		}
		memberEvents = append(memberEvents, e)
		return nil
	}

	// The reads answer the caller with its own rights, and anybody else with the
	// rights of the person a write names.
	roles := func(_ context.Context, _, userID string) ([]string, error) {
		if userID == admin.UserID {
			return d.tenantRoles, nil
		}
		return d.targetTenantRoles, nil
	}
	memberships := func(_ context.Context, _, userID string) ([]Membership, error) {
		if userID == admin.UserID {
			return d.memberships, nil
		}
		return d.targetMemberships, nil
	}

	return NewMemberService(MemberDeps{
		ListTenantMembers: func(context.Context, string, bool, int, int) ([]tenant.Member, int64, error) {
			return d.tenantRows, int64(len(d.tenantRows)), nil
		},
		ListOrgMembers: func(context.Context, string, string, bool, int, int) ([]Membership, int64, error) {
			return d.orgRows, int64(len(d.orgRows)), nil
		},
		SaveTenantMember: func(_ context.Context, row tenant.Member) error {
			tenantSaves = append(tenantSaves, row)
			return nil
		},
		SaveOrgMember: func(_ context.Context, row Membership) error {
			orgSaves = append(orgSaves, row)
			return nil
		},
		DeleteTenantMember: func(_ context.Context, _, userID string) error {
			memberRevokes = append(memberRevokes, userID)
			return nil
		},
		DeleteOrgMember: func(_ context.Context, _, orgID, userID string) error {
			memberRevokes = append(memberRevokes, orgID+"/"+userID)
			return nil
		},
		Org: func(_ context.Context, _, orgID string) (Organization, error) {
			if orgID == testOrgID || orgID == otherOrgID {
				return Organization{ID: orgID, TenantID: testTenantID, Name: "Seeded"}, nil
			}
			return Organization{}, ErrNotFound
		},
		CountTenantOwners: func(context.Context, string) (int64, error) {
			return d.tenantOwners, nil
		},
		LocalTenantOwners: func(context.Context, string) ([]tenant.LocalOwner, error) {
			return d.localOwners, nil
		},
		TenantRoles: roles,
		Memberships: memberships,
		// The unit of work either commits whole or leaves nothing behind, so a
		// failed step clears what the earlier steps wrote.
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			before := wrote()
			err := fn(ctx)
			if err != nil && wrote() != before {
				tenantSaves, orgSaves, memberRevokes = nil, nil, nil
			}
			return err
		},
		Audit: audit.NewRecorder(record, log),
		Log:   log,
	})
}

// TestListTenantAnswersAnEmptyPageToAnOrganizationManager covers the one list
// that is tenant-scoped. An organization manager administers no tenant
// membership, so the roster is empty for them. It is not a refusal: the console
// renders the tab for every administrator, and an empty table says "none of
// these are yours" where a 403 says the page is broken.
func TestListTenantAnswersAnEmptyPageToAnOrganizationManager(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgOwner}}},
		tenantRows:  []tenant.Member{{TenantID: testTenantID, UserID: testUserID}},
	})

	views, total, err := svc.ListTenant(context.Background(), admin, true, 20, 0)
	if err != nil {
		t.Fatalf("ListTenant: %v", err)
	}
	if total != 0 || len(views) != 0 {
		t.Fatalf("the roster reads %d of %d rows, want an empty page", len(views), total)
	}
	if views == nil {
		t.Error("the empty page is null, and the console iterates it without a guard")
	}
}

// TestListTenantReadsTheRoster reads the page a tenant manager reads.
func TestListTenantReadsTheRoster(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles: []string{tenant.RoleIAMAdmin},
		tenantRows: []tenant.Member{{
			TenantID: testTenantID, UserID: testUserID,
			UserName: "The Owner", Roles: []string{tenant.RoleIAMOwner},
		}},
	})

	views, total, err := svc.ListTenant(context.Background(), admin, true, 20, 0)
	if err != nil {
		t.Fatalf("ListTenant: %v", err)
	}
	if total != 1 || len(views) != 1 {
		t.Fatalf("the roster reads %d of %d rows, want 1 of 1", len(views), total)
	}
	if views[0].UserID != testUserID || views[0].UserName != "The Owner" {
		t.Errorf("the view reads %+v, want the named member", views[0])
	}
}

// TestListRefusesPersonWithoutAdminRoleOnMembers refuses a person who holds
// none of the four administrative roles, on both rosters.
func TestListRefusesPersonWithoutAdminRoleOnMembers(t *testing.T) {
	svc := testMemberService(t, memberDeps{})

	if _, _, err := svc.ListTenant(context.Background(), admin, true, 20, 0); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("ListTenant gives %v, want ErrNotAdmin", err)
	}
	if _, _, err := svc.ListOrg(context.Background(), admin, testOrgID, true, 20, 0); !errors.Is(err, ErrNotAdmin) {
		t.Errorf("ListOrg gives %v, want ErrNotAdmin", err)
	}
}

// TestListOrgReadsTheRoster reads the roster of one organization. Every
// administrator reads it, the same way the user list reads, and the roles
// narrow the writes only.
func TestListOrgReadsTheRoster(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: otherOrgID, Roles: []string{RoleOrgUserManager}}},
		orgRows: []Membership{{
			TenantID: testTenantID, OrgID: testOrgID, UserID: testUserID,
			UserName: "The Owner", Roles: []string{RoleOrgOwner},
		}},
	})

	views, total, err := svc.ListOrg(context.Background(), admin, testOrgID, true, 20, 0)
	if err != nil {
		t.Fatalf("ListOrg: %v", err)
	}
	if total != 1 || len(views) != 1 {
		t.Fatalf("the roster reads %d of %d rows, want 1 of 1", len(views), total)
	}
	if views[0].OrgID != testOrgID || views[0].UserName != "The Owner" {
		t.Errorf("the view reads %+v, want the named member", views[0])
	}
}

// TestAddTenantMemberNeedsIAMOwner refuses an IAM_ADMIN. A tenant membership
// grants the whole tenant, so only the owner of the tenant confers one.
func TestAddTenantMemberNeedsIAMOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{tenantRoles: []string{tenant.RoleIAMAdmin}})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, Roles: []string{tenant.RoleIAMAdmin},
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused grant wrote %d rows", wrote())
	}
}

// TestAddTenantMemberWritesTheGrantAndOneEvent covers the write an IAM_OWNER
// makes, and the event that must land with it.
func TestAddTenantMemberWritesTheGrantAndOneEvent(t *testing.T) {
	svc := testMemberService(t, memberDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, Roles: []string{tenant.RoleIAMAdmin},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(tenantSaves) != 1 {
		t.Fatalf("the grant wrote %d tenant memberships, want 1", len(tenantSaves))
	}
	row := tenantSaves[0]
	if row.TenantID != testTenantID || row.UserID != secondUserID {
		t.Errorf("the membership reads %+v, want the person the body names", row)
	}
	if row.CreatedAt.IsZero() {
		t.Error("the membership carries no creation time")
	}
	if len(memberEvents) != 1 || memberEvents[0].Action != string(audit.ActionMemberAdded) {
		t.Fatalf("the grant recorded %+v, want one member.added event", memberEvents)
	}
	if memberEvents[0].EntityType != audit.EntityMember || memberEvents[0].EntityID != secondUserID {
		t.Errorf("the event names %s %s, want the member it granted",
			memberEvents[0].EntityType, memberEvents[0].EntityID)
	}
}

// TestAddRefusesARoleOutsideTheScope refuses an organization role on a tenant
// membership, and a tenant role in an organization. Neither name means anything
// where it was sent, and a stored role nothing reads is a grant nobody can see.
func TestAddRefusesARoleOutsideTheScope(t *testing.T) {
	svc := testMemberService(t, memberDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, Roles: []string{RoleOrgOwner},
	})
	if !errors.Is(err, ErrUnknownRole) {
		t.Errorf("an organization role on a tenant membership gives %v, want ErrUnknownRole", err)
	}

	err = svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{tenant.RoleIAMOwner},
	})
	if !errors.Is(err, ErrUnknownRole) {
		t.Errorf("a tenant role in an organization gives %v, want ErrUnknownRole", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused grant wrote %d rows", wrote())
	}
}

// TestAddOrgMemberAdmitsAnOrganizationUserManager covers the ordinary grant: an
// ORG_USER_MANAGER puts somebody in the organization it administers.
func TestAddOrgMemberAdmitsAnOrganizationUserManager(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgUserManager}}},
	})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{RoleOrgUserManager},
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if len(orgSaves) != 1 || orgSaves[0].OrgID != testOrgID || orgSaves[0].UserID != secondUserID {
		t.Fatalf("the grant wrote %+v, want one membership of the named organization", orgSaves)
	}
	if len(memberEvents) != 1 || memberEvents[0].Action != string(audit.ActionMemberAdded) {
		t.Fatalf("the grant recorded %+v, want one member.added event", memberEvents)
	}
}

// TestAddRefusesAnOrganizationNobodyHolds refuses a grant into an organization
// that does not exist. A tenant manager passes the role gate for every
// organization, so the organization is read as well.
func TestAddRefusesAnOrganizationNobodyHolds(t *testing.T) {
	svc := testMemberService(t, memberDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: deadOrgID, Roles: []string{RoleOrgUserManager},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused grant wrote %d rows", wrote())
	}
}

// TestAddRefusesAnotherOrganization refuses a grant into an organization the
// person does not administer.
func TestAddRefusesAnotherOrganization(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: otherOrgID, Roles: []string{RoleOrgOwner}}},
	})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{RoleOrgUserManager},
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused grant wrote %d rows", wrote())
	}
}

// TestOrganizationUserManagerCannotConferOwner is the rule the slice exists
// for. An ORG_USER_MANAGER administers the people of an organization, so
// without this gate it mints an owner and outranks itself.
func TestOrganizationUserManagerCannotConferOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgUserManager}}},
	})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{RoleOrgOwner},
	})
	if !errors.Is(err, ErrOwnerGrant) {
		t.Fatalf("err = %v, want ErrOwnerGrant", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused grant wrote %d rows", wrote())
	}
}

// TestASittingOwnerConfersOwner covers the two people who may confer
// ORG_OWNER: an owner of the same organization, and a manager of the tenant.
func TestASittingOwnerConfersOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgOwner}}},
	})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{RoleOrgOwner},
	})
	if err != nil {
		t.Fatalf("a sitting owner cannot confer ORG_OWNER: %v", err)
	}

	svc = testMemberService(t, memberDeps{tenantRoles: []string{tenant.RoleIAMAdmin}})
	err = svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{RoleOrgOwner},
	})
	if err != nil {
		t.Fatalf("a tenant manager cannot confer ORG_OWNER: %v", err)
	}
}

// TestAnOwnerOfAnotherOrganizationCannotConferOwner covers the half of the rule
// that names the organization. ORG_OWNER of one organization says nothing about
// another, so the seat must be in the organization the grant names.
func TestAnOwnerOfAnotherOrganizationCannotConferOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{
			{OrgID: otherOrgID, Roles: []string{RoleOrgOwner}},
			{OrgID: testOrgID, Roles: []string{RoleOrgUserManager}},
		},
	})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{RoleOrgOwner},
	})
	if !errors.Is(err, ErrOwnerGrant) {
		t.Fatalf("err = %v, want ErrOwnerGrant", err)
	}
}

// TestUpdateRolesNeedsAMembership refuses to write roles for a person who is
// not in the organization. A PATCH that created the membership would grant
// access through the endpoint that exists to change it.
func TestUpdateRolesNeedsAMembership(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgOwner}}},
	})

	err := svc.UpdateRoles(context.Background(), admin, secondUserID, RolesBody{
		OrgID: testOrgID, Roles: []string{RoleOrgUserManager},
	})
	if !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("err = %v, want ErrMemberNotFound", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused update wrote %d rows", wrote())
	}
}

// TestUpdateRolesWritesTheNewRolesAndOneEvent replaces the roles of one sitting
// member.
func TestUpdateRolesWritesTheNewRolesAndOneEvent(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships:       []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgOwner}}},
		targetMemberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgUserManager}}},
	})

	err := svc.UpdateRoles(context.Background(), admin, secondUserID, RolesBody{
		OrgID: testOrgID, Roles: []string{RoleOrgOwner},
	})
	if err != nil {
		t.Fatalf("UpdateRoles: %v", err)
	}
	if len(orgSaves) != 1 || orgSaves[0].UserID != secondUserID {
		t.Fatalf("the update wrote %+v, want one membership", orgSaves)
	}
	if len(memberEvents) != 1 || memberEvents[0].Action != string(audit.ActionMemberUpdated) {
		t.Fatalf("the update recorded %+v, want one member.updated event", memberEvents)
	}
}

// TestUpdateTenantRolesNeedsAMembership covers the same rule on the tenant
// roster, where a person with no row holds no roles at all.
func TestUpdateTenantRolesNeedsAMembership(t *testing.T) {
	svc := testMemberService(t, memberDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	err := svc.UpdateRoles(context.Background(), admin, secondUserID, RolesBody{
		Roles: []string{tenant.RoleIAMAdmin},
	})
	if !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("err = %v, want ErrMemberNotFound", err)
	}
}

// TestRemoveRevokesTheMembershipAndRecordsOneEvent covers the revoke.
func TestRemoveRevokesTheMembershipAndRecordsOneEvent(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgUserManager}}},
	})

	if err := svc.Remove(context.Background(), admin, secondUserID, testOrgID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(memberRevokes) != 1 || memberRevokes[0] != testOrgID+"/"+secondUserID {
		t.Fatalf("the revoke wrote %v, want the named membership", memberRevokes)
	}
	if len(memberEvents) != 1 || memberEvents[0].Action != string(audit.ActionMemberRemoved) {
		t.Fatalf("the revoke recorded %+v, want one member.removed event", memberEvents)
	}
}

// TestRemoveTenantMemberNeedsIAMOwner refuses an IAM_ADMIN on the tenant
// roster, the same way the grant does.
func TestRemoveTenantMemberNeedsIAMOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{tenantRoles: []string{tenant.RoleIAMAdmin}})

	if err := svc.Remove(context.Background(), admin, secondUserID, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused revoke wrote %d rows", wrote())
	}
}

// TestRemoveRefusesTheLastTenantOwner covers the lockout guard. Only an
// IAM_OWNER writes a tenant membership, so a tenant with no sitting owner can
// never grant one again. Recovery would be a SQL statement.
func TestRemoveRefusesTheLastTenantOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles:       []string{tenant.RoleIAMOwner},
		targetTenantRoles: []string{tenant.RoleIAMOwner},
		tenantOwners:      1,
	})

	err := svc.Remove(context.Background(), admin, secondUserID, "")
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("err = %v, want ErrLastOwner", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused revoke wrote %d rows", wrote())
	}
}

// TestRemoveAllowsAnOwnerWhileAnotherSits covers the other side of the guard. A
// second owner keeps the tenant writable, so the revoke stands.
func TestRemoveAllowsAnOwnerWhileAnotherSits(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles:       []string{tenant.RoleIAMOwner},
		targetTenantRoles: []string{tenant.RoleIAMOwner},
		tenantOwners:      2,
	})

	if err := svc.Remove(context.Background(), admin, secondUserID, ""); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(memberRevokes) != 1 || memberRevokes[0] != secondUserID {
		t.Fatalf("the revoke wrote %v, want the named membership", memberRevokes)
	}
}

// TestRemoveRefusesTheLastLocalOwner covers the first guard rail of
// docs/specs/0002-directory-sign-in.md.
//
// The tenant counts eleven owners, so the count guard passes. Ten of them are
// proved by a directory and one is proved here, and the revoke names that one.
// One directory outage would then leave nobody able to reach the console.
func TestRemoveRefusesTheLastLocalOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles:       []string{tenant.RoleIAMOwner},
		targetTenantRoles: []string{tenant.RoleIAMOwner},
		tenantOwners:      11,
		localOwners:       []tenant.LocalOwner{{UserID: secondUserID, Email: "second@acme.com"}},
	})

	err := svc.Remove(context.Background(), admin, secondUserID, "")
	if !errors.Is(err, tenant.ErrLastLocalOwner) {
		t.Fatalf("err = %v, want tenant.ErrLastLocalOwner", err)
	}
	if errors.Is(err, ErrLastOwner) {
		t.Errorf("err = %v, want the local rail and not the count guard", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused revoke wrote %d rows", wrote())
	}
}

// TestRemoveAllowsADirectoryOwnerWhileALocalOwnerSits covers the other side of
// the same rail. A tenant with one local owner and ten directory owners passes
// both checks, so the revoke of a directory owner stands.
func TestRemoveAllowsADirectoryOwnerWhileALocalOwnerSits(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles:       []string{tenant.RoleIAMOwner},
		targetTenantRoles: []string{tenant.RoleIAMOwner},
		tenantOwners:      11,
		localOwners:       []tenant.LocalOwner{{UserID: testUserID, Email: "owner@acme.com"}},
	})

	if err := svc.Remove(context.Background(), admin, secondUserID, ""); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(memberRevokes) != 1 || memberRevokes[0] != secondUserID {
		t.Fatalf("the revoke wrote %v, want the named membership", memberRevokes)
	}
}

// TestUpdateRolesRefusesToStripTheLastLocalOwner covers the same rail through
// the role change. A membership that keeps IAM_ADMIN alone takes the seat
// exactly as a revoke does.
func TestUpdateRolesRefusesToStripTheLastLocalOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles:       []string{tenant.RoleIAMOwner},
		targetTenantRoles: []string{tenant.RoleIAMOwner},
		tenantOwners:      11,
		localOwners:       []tenant.LocalOwner{{UserID: secondUserID, Email: "second@acme.com"}},
	})

	err := svc.UpdateRoles(context.Background(), admin, secondUserID, RolesBody{
		Roles: []string{tenant.RoleIAMAdmin},
	})
	if !errors.Is(err, tenant.ErrLastLocalOwner) {
		t.Fatalf("err = %v, want tenant.ErrLastLocalOwner", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused role change wrote %d rows", wrote())
	}
}

// TestRemoveIgnoresTheLocalRailForATenantWithNoLocalOwner covers a tenant whose
// owners a directory proves, every one of them. There is no local owner left to
// protect, so a refusal would only trap an administrator whose directory is gone
// for good.
func TestRemoveIgnoresTheLocalRailForATenantWithNoLocalOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles:       []string{tenant.RoleIAMOwner},
		targetTenantRoles: []string{tenant.RoleIAMOwner},
		tenantOwners:      11,
	})

	if err := svc.Remove(context.Background(), admin, secondUserID, ""); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(memberRevokes) != 1 {
		t.Fatalf("the revoke wrote %v, want the named membership", memberRevokes)
	}
}

// TestUpdateRolesRefusesToStripTheLastTenantOwner covers the same lockout
// through the role change. A membership that keeps IAM_ADMIN alone locks the
// tenant exactly as a revoke does.
func TestUpdateRolesRefusesToStripTheLastTenantOwner(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles:       []string{tenant.RoleIAMOwner},
		targetTenantRoles: []string{tenant.RoleIAMOwner},
		tenantOwners:      1,
	})

	err := svc.UpdateRoles(context.Background(), admin, secondUserID, RolesBody{
		Roles: []string{tenant.RoleIAMAdmin},
	})
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("err = %v, want ErrLastOwner", err)
	}
	if wrote() != 0 {
		t.Errorf("a refused role change wrote %d rows", wrote())
	}
}

// TestAFailedAuditWriteRollsTheGrantBack covers the transaction. A change
// nobody can audit is not allowed to stand, so the membership goes with the
// event.
func TestAFailedAuditWriteRollsTheGrantBack(t *testing.T) {
	svc := testMemberService(t, memberDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		auditFails:  true,
	})

	err := svc.Add(context.Background(), admin, MemberBody{
		UserID: secondUserID, OrgID: testOrgID, Roles: []string{RoleOrgUserManager},
	})
	if err == nil {
		t.Fatal("a failed audit write left the grant standing")
	}
	if wrote() != 0 {
		t.Errorf("the rolled back grant left %d rows", wrote())
	}
}
