package organization

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// admin is the person every service test acts as.
var admin = Actor{TenantID: testTenantID, UserID: testUserID, IP: "203.0.113.7", UserAgent: "a-browser"}

// TestListRefusesPersonWithoutAdminRole refuses a person who holds none of the
// four administrative roles. The bearer guard admits any token minted for the
// admin resource, so the roles decide here.
func TestListRefusesPersonWithoutAdminRole(t *testing.T) {
	svc := testService(t, deps{})

	_, _, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("err = %v, want ErrNotAdmin", err)
	}
}

// TestListMarksTheDefaultOrganization reads the page a tenant manager reads.
// The console badges the default organization and hides its delete, so the
// answer must say which one it is.
func TestListMarksTheDefaultOrganization(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Organization{
			{ID: testOrgID, TenantID: testTenantID, Name: "AlphaOmega", State: StateActive},
			{ID: otherOrgID, TenantID: testTenantID, Name: "Beta", State: StateInactive},
		},
	})

	views, total, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(views) != 2 {
		t.Fatalf("the page holds %d of %d rows, want 2 of 2", len(views), total)
	}
	if !views[0].IsDefault {
		t.Errorf("organization %s is the tenant default and must be marked", views[0].ID)
	}
	if views[1].IsDefault {
		t.Errorf("organization %s is not the tenant default", views[1].ID)
	}
	if views[1].Name != "Beta" || views[1].State != StateInactive {
		t.Errorf("the second view reads %+v, want Beta in the inactive state", views[1])
	}
}

// TestListAdmitsAnOrganizationManager reads the page an ORG_OWNER reads. The
// console shell already names every organization of the tenant, so the list is
// the whole tenant and the roles narrow the writes only.
func TestListAdmitsAnOrganizationManager(t *testing.T) {
	svc := testService(t, deps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgUserManager}}},
		rows:        []Organization{{ID: otherOrgID, TenantID: testTenantID, Name: "Beta"}},
	})

	views, _, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(views) != 1 || views[0].ID != otherOrgID {
		t.Fatalf("the page reads %+v, want the whole tenant", views)
	}
}

// TestFindReadsOneOrganization reads one organization by id, marked the same
// way the list marks it.
func TestFindReadsOneOrganization(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMAdmin},
		rows:        []Organization{{ID: testOrgID, TenantID: testTenantID, Name: "AlphaOmega", State: StateActive}},
	})

	view, err := svc.Find(context.Background(), admin, testOrgID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if view.ID != testOrgID || view.Name != "AlphaOmega" || !view.IsDefault {
		t.Errorf("the view reads %+v, want the marked default organization", view)
	}
}

// TestFindReportsAMiss answers ErrNotFound for an id nobody holds.
func TestFindReportsAMiss(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	_, err := svc.Find(context.Background(), admin, deadOrgID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestCreateRefusesAnOrganizationOwner refuses a person who administers one
// organization. A new organization belongs to nobody yet, so only a tenant
// manager makes one.
func TestCreateRefusesAnOrganizationOwner(t *testing.T) {
	svc := testService(t, deps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgOwner}}},
	})

	_, err := svc.Create(context.Background(), admin, "Gamma")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(written) != 0 {
		t.Errorf("a refused create wrote %+v", written)
	}
}

// TestCreateWritesTheOrganizationAndOneEvent creates one organization and
// records one audit event on the same transaction.
func TestCreateWritesTheOrganizationAndOneEvent(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	view, err := svc.Create(context.Background(), admin, "Gamma")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.ID == "" || view.Name != "Gamma" || view.State != StateActive {
		t.Errorf("the view reads %+v, want a new active Gamma", view)
	}
	if view.IsDefault {
		t.Error("a new organization is never the tenant default")
	}
	if len(written) != 1 || written[0].Name != "Gamma" || written[0].TenantID != testTenantID {
		t.Fatalf("the write wrote %+v, want one Gamma of the tenant", written)
	}
	wantOneEvent(t, audit.ActionOrgCreated, view.ID)
}

// TestUpdateAdmitsTheOrganizationOwner renames the organization the person
// owns, and records one event.
func TestUpdateAdmitsTheOrganizationOwner(t *testing.T) {
	svc := testService(t, deps{
		memberships: []Membership{{OrgID: otherOrgID, Roles: []string{RoleOrgOwner}}},
		rows:        []Organization{{ID: otherOrgID, TenantID: testTenantID, Name: "Beta", State: StateActive}},
	})

	view, err := svc.Update(context.Background(), admin, otherOrgID, "Beta Renamed")
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if view.Name != "Beta Renamed" {
		t.Errorf("the view reads %q, want the new name", view.Name)
	}
	if len(renamed) != 1 || renamed[0] != otherOrgID+"=Beta Renamed" {
		t.Fatalf("the write wrote %v, want one rename of %s", renamed, otherOrgID)
	}
	wantOneEvent(t, audit.ActionOrgUpdated, otherOrgID)
}

// TestUpdateRefusesAnotherOrganization refuses an ORG_OWNER who names an
// organization it does not own.
func TestUpdateRefusesAnotherOrganization(t *testing.T) {
	svc := testService(t, deps{
		memberships: []Membership{{OrgID: testOrgID, Roles: []string{RoleOrgOwner}}},
		rows:        []Organization{{ID: otherOrgID, TenantID: testTenantID, Name: "Beta"}},
	})

	_, err := svc.Update(context.Background(), admin, otherOrgID, "Taken")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(renamed) != 0 {
		t.Errorf("a refused update wrote %v", renamed)
	}
}

// TestUpdateRefusesAUserManager refuses an ORG_USER_MANAGER of the same
// organization. That role administers people, not the organization itself.
func TestUpdateRefusesAUserManager(t *testing.T) {
	svc := testService(t, deps{
		memberships: []Membership{{OrgID: otherOrgID, Roles: []string{RoleOrgUserManager}}},
		rows:        []Organization{{ID: otherOrgID, TenantID: testTenantID, Name: "Beta"}},
	})

	_, err := svc.Update(context.Background(), admin, otherOrgID, "Taken")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// TestDeleteSoftDeletesAndRecordsOneEvent removes one organization and records
// one event.
func TestDeleteSoftDeletesAndRecordsOneEvent(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Organization{{ID: otherOrgID, TenantID: testTenantID, Name: "Beta"}},
	})

	if err := svc.Delete(context.Background(), admin, otherOrgID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != otherOrgID {
		t.Fatalf("the write deleted %v, want %s", deleted, otherOrgID)
	}
	wantOneEvent(t, audit.ActionOrgDeleted, otherOrgID)
}

// TestDeleteRefusesTheDefaultOrganization keeps the organization
// self-registration points at. Removing it leaves a new person nowhere to land.
func TestDeleteRefusesTheDefaultOrganization(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Organization{{ID: testOrgID, TenantID: testTenantID, Name: "AlphaOmega"}},
	})

	err := svc.Delete(context.Background(), admin, testOrgID)
	if !errors.Is(err, ErrDefaultOrg) {
		t.Fatalf("err = %v, want ErrDefaultOrg", err)
	}
	if len(deleted) != 0 {
		t.Errorf("a refused delete removed %v", deleted)
	}
}

// TestDeleteRollsBackAFailedAuditWrite proves the change and the trail land
// together. A change nobody can audit is not allowed to stand.
func TestDeleteRollsBackAFailedAuditWrite(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Organization{{ID: otherOrgID, TenantID: testTenantID, Name: "Beta"}},
		auditFails:  true,
	})

	if err := svc.Delete(context.Background(), admin, otherOrgID); err == nil {
		t.Fatal("Delete answered no error, want the failed audit write")
	}
	if !rolledBack {
		t.Error("the transaction must roll the delete back")
	}
}

// wantOneEvent reads the audit trail of one test: exactly one event, of the
// action and the entity the write names.
func wantOneEvent(t *testing.T, action audit.Action, entityID string) {
	t.Helper()

	if len(events) != 1 {
		t.Fatalf("the write recorded %d events, want 1: %+v", len(events), events)
	}
	got := events[0]
	if got.Action != string(action) {
		t.Errorf("the event reads %q, want %q", got.Action, action)
	}
	if got.EntityType != audit.EntityOrganization || got.EntityID != entityID {
		t.Errorf("the event names %s %s, want %s %s",
			got.EntityType, got.EntityID, audit.EntityOrganization, entityID)
	}
	if got.TenantID != testTenantID || got.ActorID != testUserID {
		t.Errorf("the event reads tenant %s actor %s, want %s %s",
			got.TenantID, got.ActorID, testTenantID, testUserID)
	}
	if got.IP != admin.IP || got.UserAgent != admin.UserAgent {
		t.Errorf("the event reads %s %s, want the request of the actor", got.IP, got.UserAgent)
	}
}

// deps names what one test varies. Everything else takes a default below.
type deps struct {
	tenantRoles []string
	memberships []Membership
	rows        []Organization
	auditFails  bool
}

// What the writes of one test did. testService clears them, and the tests of
// one package run one after another, so each test reads its own writes.
var (
	written    []Organization
	renamed    []string
	deleted    []string
	events     []audit.Event
	rolledBack bool
)

func testService(t *testing.T, d deps) *Service {
	t.Helper()
	log, _ := logger.NewObserved()
	written, renamed, deleted, events, rolledBack = nil, nil, nil, nil, false

	record := func(_ context.Context, e audit.Event) error {
		if d.auditFails {
			return errors.New("the audit write failed")
		}
		events = append(events, e)
		return nil
	}

	return NewService(Deps{
		Insert: func(_ context.Context, row Organization) error {
			written = append(written, row)
			return nil
		},
		Rename: func(_ context.Context, _, orgID, name string) error {
			renamed = append(renamed, orgID+"="+name)
			return nil
		},
		Delete: func(_ context.Context, _, orgID string) error {
			deleted = append(deleted, orgID)
			return nil
		},
		// The unit of work either commits whole or leaves nothing behind, so a
		// failed step clears what the earlier steps wrote.
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			before := len(written) + len(renamed) + len(deleted)
			err := fn(ctx)
			if err != nil && len(written)+len(renamed)+len(deleted) != before {
				written, renamed, deleted, rolledBack = nil, nil, nil, true
			}
			return err
		},
		Audit: audit.NewRecorder(record, log),
		List: func(context.Context, string, Query) ([]Organization, int64, error) {
			return d.rows, int64(len(d.rows)), nil
		},
		Find: func(_ context.Context, _, orgID string) (Organization, error) {
			for _, row := range d.rows {
				if row.ID == orgID {
					return row, nil
				}
			}
			return Organization{}, ErrNotFound
		},
		Tenant: func(context.Context, string) (tenant.Tenant, error) {
			return tenant.Tenant{ID: testTenantID, DefaultOrgID: testOrgID}, nil
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) {
			return d.tenantRoles, nil
		},
		Memberships: func(context.Context, string, string) ([]Membership, error) {
			return d.memberships, nil
		},
		Log: log,
	})
}
