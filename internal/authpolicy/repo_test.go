package authpolicy

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "auth_policy")
	return NewRepository(bdb, logger.New()), context.Background()
}

// TestFindAnswersNotFoundForALevelThatStoresNothing covers the read of an
// organization that holds no override. It is not a failure: the level inherits
// the one below it.
func TestFindAnswersNotFoundForALevelThatStoresNothing(t *testing.T) {
	repo, ctx := testRepo(t)

	if _, err := repo.Find(ctx, policyTenantID, policyOrgID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a level that stores nothing reads %v, want ErrNotFound", err)
	}
}

// TestUpsertWritesAndThenReplacesTheWholeRow covers the write of one level. The
// second write names one field, and every other column goes back to NULL, so a
// field the console cleared inherits the level below again.
func TestUpsertWritesAndThenReplacesTheWholeRow(t *testing.T) {
	repo, ctx := testRepo(t)

	written := Row{
		TenantID: policyTenantID, OrgID: policyOrgID,
		LockoutThreshold: ptr(0), LockoutWindowMS: ptr(60000),
		PwMinLength: ptr(12), PwDenyList: ptr(`["password"]`), PwCheckBreach: ptr(true),
		MFARequired: ptr(true),
	}
	if err := repo.Upsert(ctx, written); err != nil {
		t.Fatalf("write the override: %v", err)
	}

	row, err := repo.Find(ctx, policyTenantID, policyOrgID)
	if err != nil {
		t.Fatalf("read the override: %v", err)
	}
	if row.LockoutThreshold == nil || *row.LockoutThreshold != 0 {
		t.Errorf("the row reads threshold %v, want the stored 0", row.LockoutThreshold)
	}
	if row.PwDenyList == nil || *row.PwDenyList != `["password"]` {
		t.Errorf("the row reads deny list %v, want the stored list", row.PwDenyList)
	}
	if row.MFARequired == nil || !*row.MFARequired {
		t.Errorf("the row reads MFA %v, want the stored true", row.MFARequired)
	}
	if row.PwMinClasses != nil {
		t.Errorf("the row reads classes %v, want NULL", row.PwMinClasses)
	}

	if err := repo.Upsert(ctx, Row{
		TenantID: policyTenantID, OrgID: policyOrgID, PwMinClasses: ptr(3),
	}); err != nil {
		t.Fatalf("replace the override: %v", err)
	}

	row, err = repo.Find(ctx, policyTenantID, policyOrgID)
	if err != nil {
		t.Fatalf("read the replaced override: %v", err)
	}
	if row.PwMinClasses == nil || *row.PwMinClasses != 3 {
		t.Errorf("the row reads classes %v, want 3", row.PwMinClasses)
	}
	if row.LockoutThreshold != nil || row.PwDenyList != nil || row.MFARequired != nil {
		t.Errorf("the row reads %+v, want every field the write left out back to NULL", row)
	}
}

// TestRemoveTakesTheOverrideOutOfEveryRead covers the reset. The row is soft
// deleted, and a write of the same organization takes the key back.
func TestRemoveTakesTheOverrideOutOfEveryRead(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.Upsert(ctx, Row{
		TenantID: policyTenantID, OrgID: policyOrgID, PwMinLength: ptr(12),
	}); err != nil {
		t.Fatalf("write the override: %v", err)
	}
	if err := repo.Remove(ctx, policyTenantID, policyOrgID); err != nil {
		t.Fatalf("remove the override: %v", err)
	}
	if _, err := repo.Find(ctx, policyTenantID, policyOrgID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the removed override reads %v, want ErrNotFound", err)
	}

	if err := repo.Remove(ctx, policyTenantID, policyOrgID); !errors.Is(err, ErrNotFound) {
		t.Errorf("removing it twice reads %v, want ErrNotFound", err)
	}

	// The primary key is (tenant_id, org_id), so the soft deleted row still
	// holds it. A write of the same organization has to take it back.
	if err := repo.Upsert(ctx, Row{
		TenantID: policyTenantID, OrgID: policyOrgID, PwMinLength: ptr(20),
	}); err != nil {
		t.Fatalf("write the override again: %v", err)
	}
	row, err := repo.Find(ctx, policyTenantID, policyOrgID)
	if err != nil {
		t.Fatalf("read the rewritten override: %v", err)
	}
	if row.PwMinLength == nil || *row.PwMinLength != 20 {
		t.Errorf("the row reads min length %v, want 20", row.PwMinLength)
	}
}

// TestFindReadsOneTenantOnly covers the tenant boundary. The default row of one
// tenant is never read by another, so no path can reach across it.
func TestFindReadsOneTenantOnly(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.Upsert(ctx, Row{
		TenantID: policyTenantID, OrgID: "", PwMinLength: ptr(12),
	}); err != nil {
		t.Fatalf("write the tenant default: %v", err)
	}
	if _, err := repo.Find(ctx, "t-other", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("another tenant reads %v, want ErrNotFound", err)
	}
}
