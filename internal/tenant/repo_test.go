package tenant

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	testTenantID = "11111111-1111-1111-1111-111111111111"
	testOrgID    = "22222222-2222-2222-2222-222222222222"
	testUserID   = "33333333-3333-3333-3333-333333333333"

	secondUserID  = "44444444-4444-4444-4444-444444444444"
	revokedUserID = "55555555-5555-5555-5555-555555555555"
	goneUserID    = "66666666-6666-6666-6666-666666666666"
	newUserID     = "77777777-7777-7777-7777-777777777777"
)

// seed writes the shape bootstrap writes: one tenant with a default
// organization, one primary domain, one live member, and one soft-deleted
// member of another tenant.
func seed(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO tenants (id, name, state, default_org_id) VALUES (?, 'AlphaOmega', 1, ?)`,
		testTenantID, testOrgID)
	exec(`INSERT INTO tenant_domains (domain, tenant_id, is_primary, is_verified, state)
	      VALUES ('auth.acme.com', ?, 1, 1, 1)`, testTenantID)
	exec(`INSERT INTO tenant_domains (domain, tenant_id, is_primary, is_verified, state, deleted_at)
	      VALUES ('old.acme.com', ?, 0, 1, 1, NOW(6))`, testTenantID)
	exec(`INSERT INTO tenant_members (tenant_id, user_id, roles) VALUES (?, ?, '["IAM_OWNER","IAM_ADMIN"]')`,
		testTenantID, testUserID)

	// The roster joins the account, so the people behind the memberships are
	// seeded too. The second person holds a membership that was revoked, and the
	// third holds a live membership on an account that is gone.
	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'owner', 1, 1)`, testUserID, testTenantID, testOrgID)
	exec(`INSERT INTO user_humans (user_id, tenant_id, display_name, email)
	      VALUES (?, ?, 'The Owner', 'owner@acme.com')`, testUserID, testTenantID)

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'second', 1, 1)`, secondUserID, testTenantID, testOrgID)
	exec(`INSERT INTO tenant_members (tenant_id, user_id, roles, created_at)
	      VALUES (?, ?, '["IAM_ADMIN"]', NOW(3) + INTERVAL 1 SECOND)`, testTenantID, secondUserID)

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'revoked', 1, 1)`, revokedUserID, testTenantID, testOrgID)
	exec(`INSERT INTO tenant_members (tenant_id, user_id, roles, deleted_at)
	      VALUES (?, ?, '["IAM_ADMIN"]', NOW(6))`, testTenantID, revokedUserID)

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state, deleted_at)
	      VALUES (?, ?, ?, 'gone', 1, 1, NOW(6))`, goneUserID, testTenantID, testOrgID)
	exec(`INSERT INTO tenant_members (tenant_id, user_id, roles) VALUES (?, ?, '["IAM_ADMIN"]')`,
		testTenantID, goneUserID)
}

func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	repo, _, ctx := testRepoDB(t)
	return repo, ctx
}

// testRepoDB also hands back the database, for a test that must write a column
// no method of this package writes.
func testRepoDB(t *testing.T) (*Repository, *bun.DB, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "tenant")
	seed(t, bdb)
	return NewRepository(bdb, logger.New()), bdb, context.Background()
}

// TestFindByID covers the tenant row the admin front door answers with. A
// soft-deleted tenant never comes back.
func TestFindByID(t *testing.T) {
	repo, ctx := testRepo(t)

	row, err := repo.FindByID(ctx, testTenantID)
	if err != nil {
		t.Fatalf("read the tenant: %v", err)
	}
	if row.ID != testTenantID {
		t.Errorf("tenant id is %q, want %q", row.ID, testTenantID)
	}
	if row.Name != "AlphaOmega" {
		t.Errorf("tenant name is %q, want %q", row.Name, "AlphaOmega")
	}
	if row.State != 1 {
		t.Errorf("tenant state is %d, want 1", row.State)
	}
	if row.DefaultOrgID != testOrgID {
		t.Errorf("default org is %q, want %q", row.DefaultOrgID, testOrgID)
	}
	if row.CreatedAt.IsZero() {
		t.Error("the tenant carries no creation time")
	}

	if _, err := repo.FindByID(ctx, "no-such-tenant"); !errors.Is(err, ErrTenantNotFound) {
		t.Errorf("a tenant nobody owns gives %v, want ErrTenantNotFound", err)
	}
}

// TestListDomains covers the domains of one tenant. A soft-deleted domain is not
// one of them, so a name the tenant released never appears in the answer.
func TestListDomains(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, err := repo.ListDomains(ctx, testTenantID)
	if err != nil {
		t.Fatalf("read the domains: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the tenant has %d live domains, want 1: %+v", len(rows), rows)
	}
	if rows[0].Domain != "auth.acme.com" || !rows[0].IsPrimary || !rows[0].IsVerified {
		t.Errorf("the domain reads %+v, want the live primary domain", rows[0])
	}
}

// TestMemberRoles covers the tenant roles of one person. A person with no row
// holds no role, which is not an error: most people of a tenant hold none.
func TestMemberRoles(t *testing.T) {
	repo, ctx := testRepo(t)

	roles, err := repo.MemberRoles(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the tenant roles: %v", err)
	}
	want := []string{RoleIAMOwner, RoleIAMAdmin}
	if !reflect.DeepEqual(roles, want) {
		t.Errorf("the roles read %v, want %v", roles, want)
	}

	none, err := repo.MemberRoles(ctx, testTenantID, "no-such-user")
	if err != nil {
		t.Fatalf("read the roles of a person with no row: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("a person with no row holds %v, want no role", none)
	}
}

// TestListMembers covers the roster the console reads. A revoked membership and
// a membership on a deleted account are both gone from it, and each row names
// the person, so the console renders a name and not an id.
func TestListMembers(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.ListMembers(ctx, testTenantID, true, 20, 0)
	if err != nil {
		t.Fatalf("list the tenant members: %v", err)
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
	if !reflect.DeepEqual(rows[1].Roles, []string{RoleIAMOwner, RoleIAMAdmin}) {
		t.Errorf("the roles read %v, want the two seeded roles", rows[1].Roles)
	}
	if rows[1].CreatedAt.IsZero() {
		t.Error("the membership carries no creation time")
	}
}

// TestListMembersPages reads the window the pager asks for, and reports the
// total behind it. The console renders page numbers from that total.
func TestListMembersPages(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.ListMembers(ctx, testTenantID, false, 1, 1)
	if err != nil {
		t.Fatalf("list the tenant members: %v", err)
	}
	if total != 2 {
		t.Errorf("the total is %d, want 2", total)
	}
	// Oldest first, so the second page holds the newer membership.
	if len(rows) != 1 || rows[0].UserID != secondUserID {
		t.Fatalf("the second page reads %+v, want one row for %s", rows, secondUserID)
	}
}

// TestSaveMemberWritesAndRevives covers the one write that grants a tenant
// membership. A person who holds none gets one, a person who holds one has the
// roles replaced, and a person whose membership was revoked gets it back.
//
// The key of the table does not carry deleted_at, so a plain insert would be
// refused for the third of those. Re-adding a revoked membership is what the
// console offers, so the write clears the mark.
func TestSaveMemberWritesAndRevives(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.SaveMember(ctx, Member{
		TenantID: testTenantID, UserID: newUserID, Roles: []string{RoleIAMAdmin},
	}); err != nil {
		t.Fatalf("grant a new tenant membership: %v", err)
	}
	row, err := repo.FindMember(ctx, testTenantID, newUserID)
	if err != nil {
		t.Fatalf("read the new membership: %v", err)
	}
	if !reflect.DeepEqual(row.Roles, []string{RoleIAMAdmin}) {
		t.Errorf("the new membership holds %v, want [IAM_ADMIN]", row.Roles)
	}

	if err := repo.SaveMember(ctx, Member{
		TenantID: testTenantID, UserID: testUserID, Roles: []string{RoleIAMAdmin},
	}); err != nil {
		t.Fatalf("replace the roles of a tenant membership: %v", err)
	}
	row, err = repo.FindMember(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the replaced membership: %v", err)
	}
	if !reflect.DeepEqual(row.Roles, []string{RoleIAMAdmin}) {
		t.Errorf("the replaced membership holds %v, want [IAM_ADMIN]", row.Roles)
	}

	if err := repo.SaveMember(ctx, Member{
		TenantID: testTenantID, UserID: revokedUserID, Roles: []string{RoleIAMOwner},
	}); err != nil {
		t.Fatalf("revive a revoked tenant membership: %v", err)
	}
	row, err = repo.FindMember(ctx, testTenantID, revokedUserID)
	if err != nil {
		t.Fatalf("read the revived membership: %v", err)
	}
	if !reflect.DeepEqual(row.Roles, []string{RoleIAMOwner}) {
		t.Errorf("the revived membership holds %v, want [IAM_OWNER]", row.Roles)
	}
}

// TestCountOwners counts the sitting owners of a tenant: a membership that
// carries IAM_OWNER and belongs to an account that can still sign in.
//
// The seed holds one owner, one IAM_ADMIN, and one revoked membership, so the
// count is 1. The JSON_CONTAINS match reads inside the array and the soft
// delete filter drops the revoked row.
//
// A membership on a deleted account and a membership on a deactivated account
// each hold a seat that no person fills. The guard that reads this count
// refuses the last owner out of service, so neither seat may count: a count
// that reads them lets the last live owner go.
func TestCountOwners(t *testing.T) {
	repo, bdb, ctx := testRepoDB(t)

	owners, err := repo.CountOwners(ctx, testTenantID)
	if err != nil {
		t.Fatalf("count the owners: %v", err)
	}
	if owners != 1 {
		t.Errorf("the tenant counts %d owners, want 1", owners)
	}

	if err := repo.SaveMember(ctx, Member{
		TenantID: testTenantID, UserID: goneUserID, Roles: []string{RoleIAMOwner},
	}); err != nil {
		t.Fatalf("grant the role to a deleted account: %v", err)
	}
	owners, err = repo.CountOwners(ctx, testTenantID)
	if err != nil {
		t.Fatalf("count the owners after the grant to a deleted account: %v", err)
	}
	if owners != 1 {
		t.Errorf("a deleted account counts, the tenant reads %d owners, want 1", owners)
	}

	if _, err := bdb.ExecContext(ctx, `UPDATE users SET state = 2 WHERE id = ?`,
		secondUserID); err != nil {
		t.Fatalf("deactivate the second account: %v", err)
	}
	if err := repo.SaveMember(ctx, Member{
		TenantID: testTenantID, UserID: secondUserID, Roles: []string{RoleIAMOwner},
	}); err != nil {
		t.Fatalf("grant the role to a deactivated account: %v", err)
	}
	owners, err = repo.CountOwners(ctx, testTenantID)
	if err != nil {
		t.Fatalf("count the owners after the grant to a deactivated account: %v", err)
	}
	if owners != 1 {
		t.Errorf("a deactivated account counts, the tenant reads %d owners, want 1", owners)
	}

	if err := repo.DeleteMember(ctx, testTenantID, testUserID); err != nil {
		t.Fatalf("revoke the tenant membership: %v", err)
	}
	owners, err = repo.CountOwners(ctx, testTenantID)
	if err != nil {
		t.Fatalf("count the owners after the revoke: %v", err)
	}
	if owners != 0 {
		t.Errorf("the tenant counts %d owners after the revoke, want 0", owners)
	}
}

// TestDeleteMember revokes one tenant membership. The row stays in the
// database, and every read filters it out. A membership nobody holds answers
// ErrMemberNotFound.
func TestDeleteMember(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.DeleteMember(ctx, testTenantID, testUserID); err != nil {
		t.Fatalf("revoke the tenant membership: %v", err)
	}
	roles, err := repo.MemberRoles(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the roles after the revoke: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("a revoked member still holds %v, want no role", roles)
	}

	if err := repo.DeleteMember(ctx, testTenantID, newUserID); !errors.Is(err, ErrMemberNotFound) {
		t.Errorf("revoking a membership nobody holds gives %v, want ErrMemberNotFound", err)
	}
}
