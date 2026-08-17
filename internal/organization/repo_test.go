package organization

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	testTenantID = "11111111-1111-1111-1111-111111111111"
	testOrgID    = "22222222-2222-2222-2222-222222222222"
	testUserID   = "33333333-3333-3333-3333-333333333333"
	otherOrgID   = "44444444-4444-4444-4444-444444444444"
	deadOrgID    = "55555555-5555-5555-5555-555555555555"

	secondUserID  = "66666666-6666-6666-6666-666666666666"
	revokedUserID = "77777777-7777-7777-7777-777777777777"
	goneUserID    = "88888888-8888-8888-8888-888888888888"
	newUserID     = "99999999-9999-9999-9999-999999999999"
)

// seed writes one tenant with three organizations: two live and one
// soft-deleted. The person owns the first and manages users in the second.
func seed(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO organizations (id, tenant_id, name, state) VALUES (?, ?, 'AlphaOmega', 1)`,
		testOrgID, testTenantID)
	exec(`INSERT INTO organizations (id, tenant_id, name, state) VALUES (?, ?, 'Beta', 1)`,
		otherOrgID, testTenantID)
	exec(`INSERT INTO organizations (id, tenant_id, name, state, deleted_at) VALUES (?, ?, 'Closed', 1, NOW(6))`,
		deadOrgID, testTenantID)

	exec(`INSERT INTO organization_members (tenant_id, org_id, user_id, roles) VALUES (?, ?, ?, '["ORG_OWNER"]')`,
		testTenantID, testOrgID, testUserID)
	exec(`INSERT INTO organization_members (tenant_id, org_id, user_id, roles) VALUES (?, ?, ?, '["ORG_USER_MANAGER"]')`,
		testTenantID, otherOrgID, testUserID)
	exec(`INSERT INTO organization_members (tenant_id, org_id, user_id, roles, deleted_at)
	      VALUES (?, ?, ?, '["ORG_OWNER"]', NOW(6))`, testTenantID, deadOrgID, testUserID)

	// The roster joins the account, so the people behind the memberships are
	// seeded too. The second person holds a later membership in the same
	// organization, the third holds a revoked one, and the fourth holds a live
	// membership on an account that is gone.
	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'owner', 1, 1)`, testUserID, testTenantID, testOrgID)
	exec(`INSERT INTO user_humans (user_id, tenant_id, display_name, email)
	      VALUES (?, ?, 'The Owner', 'owner@acme.com')`, testUserID, testTenantID)

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'second', 1, 1)`, secondUserID, testTenantID, testOrgID)
	exec(`INSERT INTO organization_members (tenant_id, org_id, user_id, roles, created_at)
	      VALUES (?, ?, ?, '["ORG_USER_MANAGER"]', NOW(3) + INTERVAL 1 SECOND)`,
		testTenantID, testOrgID, secondUserID)

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'revoked', 1, 1)`, revokedUserID, testTenantID, testOrgID)
	exec(`INSERT INTO organization_members (tenant_id, org_id, user_id, roles, deleted_at)
	      VALUES (?, ?, ?, '["ORG_USER_MANAGER"]', NOW(6))`, testTenantID, testOrgID, revokedUserID)

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state, deleted_at)
	      VALUES (?, ?, ?, 'gone', 1, 1, NOW(6))`, goneUserID, testTenantID, testOrgID)
	exec(`INSERT INTO organization_members (tenant_id, org_id, user_id, roles)
	      VALUES (?, ?, ?, '["ORG_OWNER"]')`, testTenantID, testOrgID, goneUserID)
}

func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "organization")
	seed(t, bdb)
	return NewRepository(bdb, logger.New()), context.Background()
}

// TestListByTenant covers every live organization of one tenant. The admin front
// door answers with this list, so a soft-deleted organization must not appear.
func TestListByTenant(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, err := repo.ListByTenant(ctx, testTenantID)
	if err != nil {
		t.Fatalf("read the organizations: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("the tenant has %d live organizations, want 2: %+v", len(rows), rows)
	}
	got := []string{rows[0].Name, rows[1].Name}
	if !reflect.DeepEqual(got, []string{"AlphaOmega", "Beta"}) {
		t.Errorf("the organizations read %v, want [AlphaOmega Beta]", got)
	}
	if rows[0].ID != testOrgID || rows[0].TenantID != testTenantID {
		t.Errorf("the first organization reads %+v, want the seeded default", rows[0])
	}
}

// TestListPagesTheWholeTenant covers the admin list: every state, the
// soft-deleted row excluded, and the window the pager asks for.
func TestListPagesTheWholeTenant(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.List(ctx, testTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the organizations: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("the page holds %d of %d rows, want 2 of 2", len(rows), total)
	}

	page, total, err := repo.List(ctx, testTenantID, Query{Sort: "name", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("list the second page: %v", err)
	}
	if total != 2 {
		t.Errorf("the total reads %d, want 2 on every page", total)
	}
	if len(page) != 1 || page[0].Name != "Beta" {
		t.Fatalf("the second page by name reads %+v, want Beta", page)
	}

	found, _, err := repo.List(ctx, testTenantID, Query{Search: "Alph", Limit: 20})
	if err != nil {
		t.Fatalf("search the organizations: %v", err)
	}
	if len(found) != 1 || found[0].Name != "AlphaOmega" {
		t.Fatalf("the search reads %+v, want AlphaOmega", found)
	}
}

// TestWriteOneOrganization covers the three writes: the insert, the rename, and
// the soft delete. A soft-deleted organization is gone from every read and
// still holds its row.
func TestWriteOneOrganization(t *testing.T) {
	repo, ctx := testRepo(t)

	row := Organization{
		ID:        "66666666-6666-6666-6666-666666666666",
		TenantID:  testTenantID,
		Name:      "Gamma",
		State:     StateActive,
		CreatedAt: time.Now().UTC(),
	}
	if err := repo.Insert(ctx, row); err != nil {
		t.Fatalf("write the organization: %v", err)
	}

	if err := repo.Rename(ctx, testTenantID, row.ID, "Gamma Renamed"); err != nil {
		t.Fatalf("rename the organization: %v", err)
	}
	read, err := repo.FindByID(ctx, testTenantID, row.ID)
	if err != nil {
		t.Fatalf("read the organization: %v", err)
	}
	if read.Name != "Gamma Renamed" || read.State != StateActive {
		t.Errorf("the organization reads %+v, want the new name", read)
	}

	if err := repo.SoftDelete(ctx, testTenantID, row.ID); err != nil {
		t.Fatalf("delete the organization: %v", err)
	}
	if _, err := repo.FindByID(ctx, testTenantID, row.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound after the delete", err)
	}
	if err := repo.SoftDelete(ctx, testTenantID, row.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound on a second delete", err)
	}
}

// TestFindByIDMisses covers an id nobody holds and the soft-deleted row.
func TestFindByIDMisses(t *testing.T) {
	repo, ctx := testRepo(t)

	if _, err := repo.FindByID(ctx, testTenantID, deadOrgID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for a soft-deleted organization", err)
	}
	if _, err := repo.FindByID(ctx, "no-such-tenant", testOrgID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for another tenant", err)
	}
}

// TestListMemberships covers the organization roles of one person. A
// soft-deleted membership is not one of them, so a person removed from an
// organization loses the access it carried.
func TestListMemberships(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, err := repo.ListMemberships(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the memberships: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("the person holds %d live memberships, want 2: %+v", len(rows), rows)
	}

	roles := map[string][]string{}
	for _, row := range rows {
		if row.TenantID != testTenantID || row.UserID != testUserID {
			t.Errorf("the membership reads %+v, want the seeded person", row)
		}
		if row.CreatedAt.IsZero() {
			t.Errorf("the membership of organization %s carries no creation time", row.OrgID)
		}
		roles[row.OrgID] = row.Roles
	}
	if !reflect.DeepEqual(roles[testOrgID], []string{RoleOrgOwner}) {
		t.Errorf("the roles of the default organization read %v, want [%s]", roles[testOrgID], RoleOrgOwner)
	}
	if !reflect.DeepEqual(roles[otherOrgID], []string{RoleOrgUserManager}) {
		t.Errorf("the roles of the second organization read %v, want [%s]", roles[otherOrgID], RoleOrgUserManager)
	}

	none, err := repo.ListMemberships(ctx, testTenantID, "no-such-user")
	if err != nil {
		t.Fatalf("read the memberships of a person with no row: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("a person with no row holds %v, want no membership", none)
	}
}
