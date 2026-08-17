package organization

import (
	"errors"
	"reflect"
	"testing"
)

// TestListMembersOfOneOrganization covers the roster of one organization. A
// revoked membership and a membership on a deleted account are both gone from
// it, and each row names the person, so the console renders a name and not an
// id.
func TestListMembersOfOneOrganization(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.ListMembers(ctx, testTenantID, testOrgID, true, 20, 0)
	if err != nil {
		t.Fatalf("list the organization members: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("the roster holds %d of %d rows, want 2 of 2: %+v", len(rows), total, rows)
	}

	// Newest first, so the second membership leads.
	if rows[0].UserID != secondUserID || rows[1].UserID != testUserID {
		t.Fatalf("the roster reads %s then %s, want the newest membership first",
			rows[0].UserID, rows[1].UserID)
	}
	if rows[0].UserName != "second" {
		t.Errorf("a person with no profile is named %q, want the username", rows[0].UserName)
	}
	if rows[1].UserName != "The Owner" {
		t.Errorf("a person with a profile is named %q, want the display name", rows[1].UserName)
	}
	if rows[1].OrgID != testOrgID || !reflect.DeepEqual(rows[1].Roles, []string{RoleOrgOwner}) {
		t.Errorf("the membership reads %+v, want the owner of the default organization", rows[1])
	}
	if rows[1].CreatedAt.IsZero() {
		t.Error("the membership carries no creation time")
	}
}

// TestListMembersOfTheWholeTenant covers the roster with no organization named.
// The console reads it before an operator picks one organization.
func TestListMembersOfTheWholeTenant(t *testing.T) {
	repo, ctx := testRepo(t)

	_, total, err := repo.ListMembers(ctx, testTenantID, "", true, 20, 0)
	if err != nil {
		t.Fatalf("list the members of the tenant: %v", err)
	}
	// Two live memberships in the default organization, and one in the second.
	if total != 3 {
		t.Errorf("the tenant holds %d live memberships, want 3", total)
	}

	rows, total, err := repo.ListMembers(ctx, testTenantID, otherOrgID, true, 20, 0)
	if err != nil {
		t.Fatalf("list the members of one organization: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].UserID != testUserID {
		t.Fatalf("the second organization reads %+v, want one row for %s", rows, testUserID)
	}
}

// TestListMembersPagesTheRoster reads the window the pager asks for, and
// reports the total behind it. The console renders page numbers from that
// total.
func TestListMembersPagesTheRoster(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.ListMembers(ctx, testTenantID, testOrgID, false, 1, 1)
	if err != nil {
		t.Fatalf("list the organization members: %v", err)
	}
	if total != 2 {
		t.Errorf("the total is %d, want 2", total)
	}
	// Oldest first, so the second page holds the newer membership.
	if len(rows) != 1 || rows[0].UserID != secondUserID {
		t.Fatalf("the second page reads %+v, want one row for %s", rows, secondUserID)
	}
}

// TestSaveMembershipWritesAndRevives covers the one write that grants an
// organization membership. A person who holds none gets one, a person who holds
// one has the roles replaced, and a person whose membership was revoked gets it
// back.
//
// The key of the table does not carry deleted_at, so a plain insert would be
// refused for the third of those. Re-adding a revoked membership is what the
// console offers, so the write clears the mark.
func TestSaveMembershipWritesAndRevives(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.SaveMembership(ctx, Membership{
		TenantID: testTenantID, OrgID: testOrgID, UserID: newUserID,
		Roles: []string{RoleOrgUserManager},
	}); err != nil {
		t.Fatalf("grant a new membership: %v", err)
	}
	if err := repo.SaveMembership(ctx, Membership{
		TenantID: testTenantID, OrgID: testOrgID, UserID: testUserID,
		Roles: []string{RoleOrgUserManager},
	}); err != nil {
		t.Fatalf("replace the roles of a membership: %v", err)
	}
	if err := repo.SaveMembership(ctx, Membership{
		TenantID: testTenantID, OrgID: testOrgID, UserID: revokedUserID,
		Roles: []string{RoleOrgOwner},
	}); err != nil {
		t.Fatalf("revive a revoked membership: %v", err)
	}

	roles := map[string][]string{}
	for _, user := range []string{newUserID, testUserID, revokedUserID} {
		rows, err := repo.ListMemberships(ctx, testTenantID, user)
		if err != nil {
			t.Fatalf("read the memberships of %s: %v", user, err)
		}
		for _, row := range rows {
			if row.OrgID == testOrgID {
				roles[user] = row.Roles
			}
		}
	}
	if !reflect.DeepEqual(roles[newUserID], []string{RoleOrgUserManager}) {
		t.Errorf("the new membership holds %v, want [%s]", roles[newUserID], RoleOrgUserManager)
	}
	if !reflect.DeepEqual(roles[testUserID], []string{RoleOrgUserManager}) {
		t.Errorf("the replaced membership holds %v, want [%s]", roles[testUserID], RoleOrgUserManager)
	}
	if !reflect.DeepEqual(roles[revokedUserID], []string{RoleOrgOwner}) {
		t.Errorf("the revived membership holds %v, want [%s]", roles[revokedUserID], RoleOrgOwner)
	}
}

// TestDeleteMembership revokes one organization membership. The row stays in
// the database, and every read filters it out. A membership nobody holds
// answers ErrMemberNotFound.
func TestDeleteMembership(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.DeleteMembership(ctx, testTenantID, testOrgID, testUserID); err != nil {
		t.Fatalf("revoke the membership: %v", err)
	}
	rows, err := repo.ListMemberships(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the memberships after the revoke: %v", err)
	}
	if len(rows) != 1 || rows[0].OrgID != otherOrgID {
		t.Errorf("the person holds %+v, want the second organization only", rows)
	}

	err = repo.DeleteMembership(ctx, testTenantID, testOrgID, newUserID)
	if !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("revoking a membership nobody holds gives %v, want ErrMemberNotFound", err)
	}
}
