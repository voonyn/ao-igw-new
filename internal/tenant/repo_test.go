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

// TestLocalOwners covers the read behind the first guard rail of
// docs/specs/0002-directory-sign-in.md: the owners the local password compare
// still signs in.
//
// Each step of the test takes one of the four predicates away and reads the
// count back, so a predicate that stopped working is named by the step that
// fails.
func TestLocalOwners(t *testing.T) {
	repo, bdb, ctx := testRepoDB(t)

	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("write %q: %v", query, err)
		}
	}
	read := func(what string) []LocalOwner {
		t.Helper()
		rows, err := repo.LocalOwners(ctx, testTenantID)
		if err != nil {
			t.Fatalf("read the local owners %s: %v", what, err)
		}
		return rows
	}

	// The seeded owner holds no password hash, so the directory owns them and
	// the local compare signs nobody in.
	if rows := read("of the seed"); len(rows) != 0 {
		t.Fatalf("the seed reads %+v local owners, want none", rows)
	}

	exec(`UPDATE user_humans SET password_hash = '$2a$10$a-bcrypt-hash' WHERE user_id = ?`, testUserID)
	rows := read("after the hash")
	if len(rows) != 1 || rows[0].UserID != testUserID {
		t.Fatalf("the tenant reads %+v local owners, want the seeded owner", rows)
	}
	if rows[0].Email != "owner@acme.com" {
		t.Errorf("the local owner carries the address %q, want the seeded one", rows[0].Email)
	}

	// A second owner, on an address of another domain.
	exec(`INSERT INTO user_humans (user_id, tenant_id, email, password_hash)
	      VALUES (?, ?, 'second@other.test', '$2a$10$a-bcrypt-hash')`, secondUserID, testTenantID)
	exec(`UPDATE tenant_members SET roles = '["IAM_OWNER"]' WHERE user_id = ?`, secondUserID)
	if rows := read("after the second grant"); len(rows) != 2 {
		t.Fatalf("the tenant reads %+v local owners, want both", rows)
	}

	// A Federation Link with a live active federation takes the second owner:
	// Federation Resolution case 2 sends them to that directory.
	const federationID = "88888888-8888-8888-8888-888888888888"
	exec(`INSERT INTO user_federations (id, tenant_id, name, type, state)
	      VALUES (?, ?, 'Head office', 1, 1)`, federationID, testTenantID)
	exec(`INSERT INTO user_federation_links (tenant_id, federation_id, external_id, user_id)
	      VALUES (?, ?, 'a-stable-guid', ?)`, testTenantID, federationID, secondUserID)
	rows = read("after the link")
	if len(rows) != 1 || rows[0].UserID != testUserID {
		t.Fatalf("the tenant reads %+v local owners, want the linked owner dropped", rows)
	}

	// A claimed domain takes the first owner: case 1 outranks case 3, so the
	// claim routes them even though they hold a hash.
	exec(`INSERT INTO user_federation_domains (tenant_id, domain, federation_id)
	      VALUES (?, 'acme.com', ?)`, testTenantID, federationID)
	if rows := read("after the claim"); len(rows) != 0 {
		t.Fatalf("the tenant reads %+v local owners, want the claimed owner dropped", rows)
	}

	// An inactive federation routes nobody, and a soft-deleted one behaves alike.
	// Both give the two owners back.
	exec(`UPDATE user_federations SET state = 2 WHERE id = ?`, federationID)
	if rows := read("after the federation was switched off"); len(rows) != 2 {
		t.Fatalf("the tenant reads %+v local owners, want both back", rows)
	}
	exec(`UPDATE user_federations SET state = 1, deleted_at = NOW(6) WHERE id = ?`, federationID)
	if rows := read("after the federation was deleted"); len(rows) != 2 {
		t.Fatalf("the tenant reads %+v local owners, want both back", rows)
	}
}

// TestPeopleAtDomains covers the read behind the claim preview of
// docs/specs/0002-directory-sign-in.md: the people one candidate domain list
// moves onto a directory.
//
// The seeded owner is an IAM_OWNER of the tenant, so the first step proves the
// answer for a domain that moves a local IAM_OWNER. The steps that follow prove
// that the read names the whole population and not the owner subset.
func TestPeopleAtDomains(t *testing.T) {
	repo, bdb, ctx := testRepoDB(t)

	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("write %q: %v", query, err)
		}
	}
	read := func(what string, domains []string, limit int) ([]DomainPerson, int) {
		t.Helper()
		rows, total, err := repo.PeopleAtDomains(ctx, testTenantID, domains, limit)
		if err != nil {
			t.Fatalf("read the people %s: %v", what, err)
		}
		return rows, total
	}

	// The seeded owner carries owner@acme.com and holds IAM_OWNER. A claim on
	// acme.com moves them, whether or not they hold a password hash.
	rows, total := read("of the claimed domain", []string{"acme.com"}, 50)
	if total != 1 || len(rows) != 1 || rows[0].UserID != testUserID {
		t.Fatalf("acme.com moves %+v (total %d), want the seeded owner", rows, total)
	}
	if rows[0].Email != "owner@acme.com" {
		t.Errorf("the moved person carries the address %q, want the seeded one", rows[0].Email)
	}

	// The match is on the domain and it ignores case on both sides.
	if _, total := read("of the claimed domain in capitals", []string{"ACME.COM"}, 50); total != 1 {
		t.Errorf("ACME.COM moves %d people, want 1", total)
	}
	if _, total := read("of a domain nobody carries", []string{"corp.example"}, 50); total != 0 {
		t.Errorf("corp.example moves %d people, want 0", total)
	}
	if _, total := read("of an empty list", nil, 50); total != 0 {
		t.Errorf("an empty domain list moves %d people, want 0", total)
	}

	// A person who holds no role and no password hash moves too. The preview
	// names the whole population, and the guard rail names the owner subset.
	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'second', 1, 1)`, secondUserID, testTenantID, testOrgID)
	exec(`INSERT INTO user_humans (user_id, tenant_id, email)
	      VALUES (?, ?, 'second@acme.com')`, secondUserID, testTenantID)
	if _, total := read("after the second person", []string{"acme.com"}, 50); total != 2 {
		t.Errorf("acme.com moves %d people, want both", total)
	}

	// A deactivated person moves. They are reactivated later, and the claim
	// routes them when they are.
	exec(`UPDATE users SET state = 2 WHERE id = ?`, secondUserID)
	if _, total := read("after the deactivation", []string{"acme.com"}, 50); total != 2 {
		t.Errorf("acme.com moves %d people after a deactivation, want both", total)
	}

	// The limit caps the page, and the total still counts every match.
	rows, total = read("with a limit of one", []string{"acme.com"}, 1)
	if len(rows) != 1 || total != 2 {
		t.Errorf("a limit of one reads %d rows of %d, want 1 of 2", len(rows), total)
	}

	// A soft-deleted person moves nobody, because they sign in nowhere.
	exec(`UPDATE users SET deleted_at = NOW(6) WHERE id = ?`, secondUserID)
	if _, total := read("after the soft delete", []string{"acme.com"}, 50); total != 1 {
		t.Errorf("acme.com moves %d people after a soft delete, want 1", total)
	}

	// The username is the second form Federation Resolution case 1 reads. This
	// person carries another address, and the claim still moves them.
	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'fourth@acme.com', 1, 1)`, revokedUserID, testTenantID, testOrgID)
	exec(`INSERT INTO user_humans (user_id, tenant_id, email)
	      VALUES (?, ?, 'fourth@elsewhere.test')`, revokedUserID, testTenantID)
	rows, total = read("of the domain the username carries", []string{"acme.com"}, 50)
	if total != 2 {
		t.Errorf("acme.com moves %+v (total %d), want the seeded owner and the username", rows, total)
	}

	// Two domains read as one list.
	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'third', 1, 1)`, newUserID, testTenantID, testOrgID)
	exec(`INSERT INTO user_humans (user_id, tenant_id, email)
	      VALUES (?, ?, 'third@other.test')`, newUserID, testTenantID)
	if _, total := read("of both domains", []string{"acme.com", "other.test"}, 50); total != 2 {
		t.Errorf("both domains move %d people, want 2", total)
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
