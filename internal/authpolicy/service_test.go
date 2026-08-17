package authpolicy

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

const (
	policyTenantID = "t-1"
	policyUserID   = "u-1"
	policyOrgID    = "o-1"
	otherOrgID     = "o-2"
)

// policyOperator is the person every test of this package acts as.
var policyOperator = Actor{
	TenantID: policyTenantID, UserID: policyUserID, IP: "203.0.113.7", UserAgent: "a-browser",
}

// ptr answers the address of a value, so a test writes an explicit setting the
// way the table stores one.
func ptr[T any](v T) *T { return &v }

// seededRows is what the tests read: a tenant default that sets every knob, and
// one organization that overrides two of them.
func seededRows() map[string]Row {
	return map[string]Row{
		"": {
			TenantID: policyTenantID, OrgID: "",
			LockoutThreshold: ptr(5), LockoutWindowMS: ptr(900000), LockoutCooldownMS: ptr(900000),
			PwMinLength: ptr(8), PwMinClasses: ptr(1), PwDenyList: ptr(`["password"]`),
			PwCheckBreach:      ptr(false),
			RecoveryResetTTLMS: ptr(3600000), RecoveryVerifyTTLMS: ptr(86400000),
			MFARequired: ptr(false),
		},
		policyOrgID: {
			TenantID: policyTenantID, OrgID: policyOrgID,
			LockoutThreshold: ptr(0), PwMinLength: ptr(12),
		},
	}
}

// What the writes of one test left behind.
var (
	upsertedRows []Row
	removedOrgs  []string
	policyEvents []audit.Event
)

// testService builds the service over the seeded rows, with the roles the
// caller holds. memberships names the organizations the caller administers.
func testService(t *testing.T, roles []string, memberships []organization.Membership) *Service {
	t.Helper()
	log, _ := logger.NewObserved()
	upsertedRows, removedOrgs, policyEvents = nil, nil, nil

	stored := seededRows()

	return NewService(Deps{
		Find: func(_ context.Context, _, orgID string) (Row, error) {
			row, ok := stored[orgID]
			if !ok {
				return Row{}, ErrNotFound
			}
			return row, nil
		},
		// The store is written the way the table is, so the answer of a write
		// resolves from what the write left behind.
		Upsert: func(_ context.Context, row Row) error {
			upsertedRows = append(upsertedRows, row)
			stored[row.OrgID] = row
			return nil
		},
		Remove: func(_ context.Context, _, orgID string) error {
			if _, ok := stored[orgID]; !ok {
				return ErrNotFound
			}
			delete(stored, orgID)
			removedOrgs = append(removedOrgs, orgID)
			return nil
		},
		Org: func(_ context.Context, _, orgID string) (organization.Organization, error) {
			if orgID != policyOrgID && orgID != otherOrgID {
				return organization.Organization{}, organization.ErrNotFound
			}
			return organization.Organization{ID: orgID, TenantID: policyTenantID}, nil
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) { return roles, nil },
		Memberships: func(context.Context, string, string) ([]organization.Membership, error) {
			return memberships, nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			err := fn(ctx)
			if err != nil {
				upsertedRows, removedOrgs = nil, nil
			}
			return err
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			policyEvents = append(policyEvents, e)
			return nil
		}, log),
		Log: log,
	})
}

// orgOwner is the membership of a person who owns one organization.
func orgOwner(orgID string) []organization.Membership {
	return []organization.Membership{
		{TenantID: policyTenantID, OrgID: orgID, UserID: policyUserID,
			Roles: []string{organization.RoleOrgOwner}},
	}
}

// TestReadTenantDefaultAnswersTheStoredPolicy covers the tenant read. Every
// field of the default row is set at this level, so nothing is inherited and the
// durations answer in seconds.
func TestReadTenantDefaultAnswersTheStoredPolicy(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMAdmin}, nil)

	view, err := svc.Read(context.Background(), policyOperator, "")
	if err != nil {
		t.Fatalf("read the tenant policy: %v", err)
	}
	if view.OrgID != "" {
		t.Errorf("the answer names organization %q, want the tenant default", view.OrgID)
	}
	if view.LockoutThreshold != 5 || view.LockoutWindowSeconds != 900 {
		t.Errorf("the answer reads %+v, want the stored lockout in seconds", view)
	}
	if view.PwMinLength != 8 || len(view.PwDenyList) != 1 || view.PwDenyList[0] != "password" {
		t.Errorf("the answer reads %+v, want the stored password rules", view)
	}
	if !view.Overridden["lockoutThreshold"] || !view.Overridden["pwDenyList"] {
		t.Errorf("the answer reads %+v, want every stored field marked set here", view.Overridden)
	}
}

// TestReadTenantDefaultFallsBackToTheCodeDefaults covers a tenant whose default
// row sets nothing. The code defaults answer, and no field is marked as set at
// this level.
func TestReadTenantDefaultFallsBackToTheCodeDefaults(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)
	svc.deps.Find = func(context.Context, string, string) (Row, error) { return Row{}, ErrNotFound }

	view, err := svc.Read(context.Background(), policyOperator, "")
	if err != nil {
		t.Fatalf("read the tenant policy: %v", err)
	}
	if view.LockoutThreshold != DefaultLockoutThreshold {
		t.Errorf("the answer reads threshold %d, want the code default", view.LockoutThreshold)
	}
	if view.RecoveryVerifyTtlSeconds != int(DefaultRecoveryVerifyTTL.Seconds()) {
		t.Errorf("the answer reads %d, want the code default in seconds", view.RecoveryVerifyTtlSeconds)
	}
	if len(view.PwDenyList) != 0 {
		t.Errorf("the answer reads deny list %v, want an empty list", view.PwDenyList)
	}
	if view.Overridden["lockoutThreshold"] {
		t.Errorf("the answer reads %+v, want nothing marked set here", view.Overridden)
	}
}

// TestReadOrgResolvesTheOverrideOverTheDefault covers the two-level read. The
// organization sets two knobs and inherits the rest, and a stored 0 is an
// explicit setting: it disables lockout and does not mean "inherit".
func TestReadOrgResolvesTheOverrideOverTheDefault(t *testing.T) {
	svc := testService(t, nil, orgOwner(policyOrgID))

	view, err := svc.Read(context.Background(), policyOperator, policyOrgID)
	if err != nil {
		t.Fatalf("read the organization policy: %v", err)
	}
	if view.OrgID != policyOrgID {
		t.Errorf("the answer names organization %q, want %q", view.OrgID, policyOrgID)
	}
	if view.LockoutThreshold != 0 || !view.Overridden["lockoutThreshold"] {
		t.Errorf("the answer reads %+v, want a stored 0 read as an explicit setting", view)
	}
	if view.PwMinLength != 12 || !view.Overridden["pwMinLength"] {
		t.Errorf("the answer reads %+v, want the override", view)
	}
	if view.LockoutWindowSeconds != 900 || view.Overridden["lockoutWindowSeconds"] {
		t.Errorf("the answer reads %+v, want the inherited window", view)
	}
	if len(view.PwDenyList) != 1 || view.Overridden["pwDenyList"] {
		t.Errorf("the answer reads %+v, want the inherited deny list", view)
	}
}

// TestReadOrgWithoutAnOverrideInheritsEverything covers an organization that
// stores no row at all.
func TestReadOrgWithoutAnOverrideInheritsEverything(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	view, err := svc.Read(context.Background(), policyOperator, otherOrgID)
	if err != nil {
		t.Fatalf("read the organization policy: %v", err)
	}
	if view.LockoutThreshold != 5 || view.PwMinLength != 8 {
		t.Errorf("the answer reads %+v, want the tenant default", view)
	}
	for field, set := range view.Overridden {
		if set {
			t.Errorf("the answer marks %s set here, want everything inherited", field)
		}
	}
}

// TestReadRefusesAPersonWithoutTheRole covers the gate. A tenant manager reads
// the default, an ORG_OWNER reads its own organization, and nobody else reads
// either.
func TestReadRefusesAPersonWithoutTheRole(t *testing.T) {
	svc := testService(t, nil, orgOwner(policyOrgID))
	if _, err := svc.Read(context.Background(), policyOperator, ""); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner reads the tenant default %v, want ErrForbidden", err)
	}
	if _, err := svc.Read(context.Background(), policyOperator, otherOrgID); !errors.Is(err, ErrForbidden) {
		t.Errorf("an owner reads another organization %v, want ErrForbidden", err)
	}

	svc = testService(t, nil, []organization.Membership{
		{TenantID: policyTenantID, OrgID: policyOrgID, UserID: policyUserID,
			Roles: []string{organization.RoleOrgUserManager}},
	})
	if _, err := svc.Read(context.Background(), policyOperator, policyOrgID); !errors.Is(err, ErrForbidden) {
		t.Errorf("a user manager reads the policy %v, want ErrForbidden", err)
	}
}

// TestReadRefusesAnOrganizationNobodyHolds covers an org id that names nothing.
// A tenant manager passes the gate, so without this read a typed id would answer
// a policy for an organization that does not exist.
func TestReadRefusesAnOrganizationNobodyHolds(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	_, err := svc.Read(context.Background(), policyOperator, "o-nothing")
	if !errors.Is(err, organization.ErrNotFound) {
		t.Errorf("an organization nobody holds reads %v, want organization.ErrNotFound", err)
	}
}

// TestWriteOrgStoresOnlyTheFieldsTheBodyCarries covers the two halves of one
// write. A field the body names is stored, and a field it leaves out is stored
// as NULL, so the organization goes back to inheriting it.
func TestWriteOrgStoresOnlyTheFieldsTheBodyCarries(t *testing.T) {
	svc := testService(t, nil, orgOwner(policyOrgID))

	view, err := svc.Write(context.Background(), policyOperator, policyOrgID, Body{
		PwMinLength: ptr(16), MfaRequired: ptr(true),
	})
	if err != nil {
		t.Fatalf("write the organization policy: %v", err)
	}
	if len(upsertedRows) != 1 {
		t.Fatalf("the write stored %d rows, want one", len(upsertedRows))
	}

	row := upsertedRows[0]
	if row.OrgID != policyOrgID || row.TenantID != policyTenantID {
		t.Errorf("the row reads %+v, want the override of the organization", row)
	}
	if row.PwMinLength == nil || *row.PwMinLength != 16 {
		t.Errorf("the row reads min length %v, want 16", row.PwMinLength)
	}
	if row.PwMinClasses != nil || row.LockoutThreshold != nil {
		t.Errorf("the row reads %+v, want the absent fields stored as NULL", row)
	}

	if view.PwMinLength != 16 || !view.Overridden["pwMinLength"] {
		t.Errorf("the answer reads %+v, want the written value", view)
	}
	if view.PwMinClasses != 1 || view.Overridden["pwMinClasses"] {
		t.Errorf("the answer reads %+v, want the inherited classes", view)
	}
	if !view.MfaRequired {
		t.Errorf("the answer reads %+v, want MFA required", view)
	}

	if len(policyEvents) != 1 {
		t.Fatalf("the write recorded %d events, want one", len(policyEvents))
	}
	if policyEvents[0].Action != string(audit.ActionAuthPolicyUpdated) ||
		policyEvents[0].EntityType != audit.EntityAuthPolicy ||
		policyEvents[0].EntityID != policyOrgID {
		t.Errorf("the event reads %+v, want the written override", policyEvents[0])
	}
}

// TestWriteStoresAZeroAsAnExplicitSetting covers the field a null and a zero
// mean different things on. A threshold of 0 disables lockout, and it must not
// be stored as NULL, which would inherit the level below.
func TestWriteStoresAZeroAsAnExplicitSetting(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	view, err := svc.Write(context.Background(), policyOperator, "", Body{
		LockoutThreshold: ptr(0), PwCheckBreach: ptr(false), PwDenyList: []string{},
	})
	if err != nil {
		t.Fatalf("write the tenant policy: %v", err)
	}

	row := upsertedRows[0]
	if row.LockoutThreshold == nil || *row.LockoutThreshold != 0 {
		t.Errorf("the row reads threshold %v, want an explicit 0", row.LockoutThreshold)
	}
	if row.PwCheckBreach == nil || *row.PwCheckBreach {
		t.Errorf("the row reads breach check %v, want an explicit false", row.PwCheckBreach)
	}
	if row.PwDenyList == nil || *row.PwDenyList != "[]" {
		t.Errorf("the row reads deny list %v, want an explicit empty list", row.PwDenyList)
	}
	if view.LockoutThreshold != 0 || !view.Overridden["lockoutThreshold"] {
		t.Errorf("the answer reads %+v, want lockout disabled at this level", view)
	}
	if len(view.PwDenyList) != 0 {
		t.Errorf("the answer reads deny list %v, want an empty list", view.PwDenyList)
	}
}

// TestWriteStoresTheDurationsInMilliseconds covers the unit the API and the
// table differ on. The console reads and writes seconds, and the column holds
// milliseconds.
func TestWriteStoresTheDurationsInMilliseconds(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	view, err := svc.Write(context.Background(), policyOperator, "", Body{
		LockoutWindowSeconds: ptr(60), RecoveryResetTtlSeconds: ptr(1800),
	})
	if err != nil {
		t.Fatalf("write the tenant policy: %v", err)
	}
	if row := upsertedRows[0]; row.LockoutWindowMS == nil || *row.LockoutWindowMS != 60000 {
		t.Errorf("the row reads window %v, want 60000 milliseconds", row.LockoutWindowMS)
	}
	if view.LockoutWindowSeconds != 60 || view.RecoveryResetTtlSeconds != 1800 {
		t.Errorf("the answer reads %+v, want the seconds that were written", view)
	}
}

// TestWriteRefusesAPersonWithoutTheRole covers the write gate. An
// ORG_USER_MANAGER administers the people of an organization and not the rules
// their sign-in meets.
func TestWriteRefusesAPersonWithoutTheRole(t *testing.T) {
	svc := testService(t, nil, []organization.Membership{
		{TenantID: policyTenantID, OrgID: policyOrgID, UserID: policyUserID,
			Roles: []string{organization.RoleOrgUserManager}},
	})

	_, err := svc.Write(context.Background(), policyOperator, policyOrgID, Body{PwMinLength: ptr(20)})
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("a user manager writes %v, want ErrForbidden", err)
	}
	if len(upsertedRows) != 0 {
		t.Errorf("the refused write stored %+v, want nothing", upsertedRows)
	}

	svc = testService(t, nil, orgOwner(policyOrgID))
	if _, err := svc.Write(context.Background(), policyOperator, "", Body{PwMinLength: ptr(20)}); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner writes the tenant default %v, want ErrForbidden", err)
	}
	if len(upsertedRows) != 0 {
		t.Errorf("the refused write stored %+v, want nothing", upsertedRows)
	}
}

// TestResetRemovesTheOverride covers the delete. Every field of the
// organization goes back to the tenant default, and one event records it.
func TestResetRemovesTheOverride(t *testing.T) {
	svc := testService(t, nil, orgOwner(policyOrgID))

	if err := svc.Reset(context.Background(), policyOperator, policyOrgID); err != nil {
		t.Fatalf("remove the override: %v", err)
	}
	if len(removedOrgs) != 1 || removedOrgs[0] != policyOrgID {
		t.Errorf("the reset removed %v, want the override of the organization", removedOrgs)
	}
	if len(policyEvents) != 1 || policyEvents[0].Action != string(audit.ActionAuthPolicyReset) {
		t.Errorf("the reset recorded %+v, want one auth_policy.reset event", policyEvents)
	}

	view, err := svc.Read(context.Background(), policyOperator, policyOrgID)
	if err != nil {
		t.Fatalf("read the organization policy: %v", err)
	}
	if view.PwMinLength != 8 || view.Overridden["pwMinLength"] {
		t.Errorf("the answer reads %+v, want the tenant default", view)
	}
}

// TestResetAnOrganizationWithoutAnOverrideChangesNothing covers the reset of a
// level that already inherits everything. It is the state the reset asks for,
// so it answers the same way and records nothing.
func TestResetAnOrganizationWithoutAnOverrideChangesNothing(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if err := svc.Reset(context.Background(), policyOperator, otherOrgID); err != nil {
		t.Fatalf("remove an override that is not there: %v", err)
	}
	if len(policyEvents) != 0 {
		t.Errorf("the reset recorded %+v, want nothing", policyEvents)
	}
}

// TestResetRefusesTheTenantDefault covers the level that cannot be reset. The
// tenant default is the bottom of the two levels, so removing it would leave
// nothing to inherit.
func TestResetRefusesTheTenantDefault(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if err := svc.Reset(context.Background(), policyOperator, ""); !errors.Is(err, ErrTenantScope) {
		t.Errorf("resetting the tenant default reads %v, want ErrTenantScope", err)
	}
	if len(removedOrgs) != 0 {
		t.Errorf("the refused reset removed %v, want nothing", removedOrgs)
	}
}
