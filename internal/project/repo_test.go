package project

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	testTenantID   = "11111111-1111-1111-1111-111111111111"
	testOrgID      = "22222222-2222-2222-2222-222222222222"
	testUserID     = "33333333-3333-3333-3333-333333333333"
	otherOrgID     = "44444444-4444-4444-4444-444444444444"
	testProjectID  = "66666666-6666-6666-6666-666666666666"
	otherProjectID = "77777777-7777-7777-7777-777777777777"
	deadProjectID  = "88888888-8888-8888-8888-888888888888"
)

// seed writes one tenant with three projects: two live, in two organizations,
// and one soft-deleted.
func seed(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO projects (id, tenant_id, org_id, name, state, private_labeling_setting)
	      VALUES (?, ?, ?, 'Checkout', 1, 2)`, testProjectID, testTenantID, testOrgID)
	exec(`INSERT INTO projects (id, tenant_id, org_id, name, state)
	      VALUES (?, ?, ?, 'Ledger', 1)`, otherProjectID, testTenantID, otherOrgID)
	exec(`INSERT INTO projects (id, tenant_id, org_id, name, state, deleted_at)
	      VALUES (?, ?, ?, 'Closed', 1, NOW(6))`, deadProjectID, testTenantID, testOrgID)
}

func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "project")
	seed(t, bdb)
	return NewRepository(bdb, logger.New()), context.Background()
}

// TestListPagesTheWholeTenant covers the admin list: the soft-deleted row
// excluded, the window the pager asks for, the search, and the organization
// filter the console sends.
func TestListPagesTheWholeTenant(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.List(ctx, testTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the projects: %v", err)
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
	if len(page) != 1 || page[0].Name != "Ledger" {
		t.Fatalf("the second page by name reads %+v, want Ledger", page)
	}

	found, _, err := repo.List(ctx, testTenantID, Query{Search: "Check", Limit: 20})
	if err != nil {
		t.Fatalf("search the projects: %v", err)
	}
	if len(found) != 1 || found[0].Name != "Checkout" {
		t.Fatalf("the search reads %+v, want Checkout", found)
	}

	mine, _, err := repo.List(ctx, testTenantID, Query{OrgID: otherOrgID, Limit: 20})
	if err != nil {
		t.Fatalf("filter the projects by organization: %v", err)
	}
	if len(mine) != 1 || mine[0].ID != otherProjectID {
		t.Fatalf("the filtered page reads %+v, want the project of %s", mine, otherOrgID)
	}
}

// TestWriteOneProject covers the three writes: the insert, the update of the
// name and the four settings, and the soft delete.
func TestWriteOneProject(t *testing.T) {
	repo, ctx := testRepo(t)

	row := Project{
		ID:            "99999999-9999-9999-9999-999999999999",
		TenantID:      testTenantID,
		OrgID:         testOrgID,
		Name:          "Billing",
		State:         StateActive,
		RoleAssertion: true,
		CreatedAt:     time.Now().UTC(),
	}
	if err := repo.Insert(ctx, row); err != nil {
		t.Fatalf("write the project: %v", err)
	}

	row.Name = "Billing Renamed"
	row.RoleAssertion = false
	row.RoleCheck = true
	row.HasProjectCheck = true
	row.PrivateLabeling = 2
	if err := repo.Update(ctx, row); err != nil {
		t.Fatalf("update the project: %v", err)
	}

	read, err := repo.FindByID(ctx, testTenantID, row.ID)
	if err != nil {
		t.Fatalf("read the project: %v", err)
	}
	if read.Name != "Billing Renamed" || read.OrgID != testOrgID || read.State != StateActive {
		t.Errorf("the project reads %+v, want the new name", read)
	}
	if read.RoleAssertion || !read.RoleCheck || !read.HasProjectCheck || read.PrivateLabeling != 2 {
		t.Errorf("the settings read %+v, want the four written values", read)
	}

	if err := repo.SoftDelete(ctx, testTenantID, row.ID); err != nil {
		t.Fatalf("delete the project: %v", err)
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

	if _, err := repo.FindByID(ctx, testTenantID, deadProjectID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for a soft-deleted project", err)
	}
	if _, err := repo.FindByID(ctx, "no-such-tenant", testProjectID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for another tenant", err)
	}
}
