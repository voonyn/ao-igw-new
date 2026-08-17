package project

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
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

// TestListReadsTheWholeTenant reads the page a tenant manager reads. The
// console names every organization of the tenant already, so the list is the
// whole tenant and the roles narrow the writes only.
func TestListReadsTheWholeTenant(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Project{
			{ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID, Name: "Checkout", State: StateActive},
			{ID: otherProjectID, TenantID: testTenantID, OrgID: otherOrgID, Name: "Ledger", State: StateInactive},
		},
	})

	views, total, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(views) != 2 {
		t.Fatalf("the page holds %d of %d rows, want 2 of 2", len(views), total)
	}
	if views[1].Name != "Ledger" || views[1].OrgID != otherOrgID || views[1].State != StateInactive {
		t.Errorf("the second view reads %+v, want the inactive Ledger of %s", views[1], otherOrgID)
	}
}

// TestListAdmitsAnOrganizationManager reads the page an ORG_USER_MANAGER
// reads. That role administers no project, and it still reads the list.
func TestListAdmitsAnOrganizationManager(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows:        []Project{{ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID, Name: "Checkout"}},
	})

	views, _, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(views) != 1 || views[0].ID != testProjectID {
		t.Fatalf("the page reads %+v, want the whole tenant", views)
	}
}

// TestFindReadsOneProject reads one project by id, with the four settings the
// console renders.
func TestFindReadsOneProject(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMAdmin},
		rows: []Project{{
			ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID, Name: "Checkout",
			State: StateActive, RoleAssertion: true, PrivateLabeling: 2,
		}},
	})

	view, err := svc.Find(context.Background(), admin, testProjectID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if view.ID != testProjectID || view.Name != "Checkout" {
		t.Fatalf("the view reads %+v, want the seeded project", view)
	}
	if !view.RoleAssertion || view.RoleCheck || view.HasProjectCheck || view.PrivateLabeling != 2 {
		t.Errorf("the settings read %+v, want the stored four", view.Settings)
	}
}

// TestFindReportsAMiss answers ErrNotFound for an id nobody holds.
func TestFindReportsAMiss(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	_, err := svc.Find(context.Background(), admin, deadProjectID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestCreateAdmitsTheOrganizationOwner creates one project in the organization
// the person owns, stores the four settings, and records one event.
func TestCreateAdmitsTheOrganizationOwner(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	view, err := svc.Create(context.Background(), admin, CreateBody{
		OrgID:    testOrgID,
		Name:     "Checkout",
		Settings: Settings{RoleCheck: true, PrivateLabeling: 1},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.ID == "" || view.Name != "Checkout" || view.OrgID != testOrgID || view.State != StateActive {
		t.Errorf("the view reads %+v, want a new active Checkout of %s", view, testOrgID)
	}
	if len(written) != 1 {
		t.Fatalf("the write wrote %+v, want one project", written)
	}
	if !written[0].RoleCheck || written[0].PrivateLabeling != 1 || written[0].TenantID != testTenantID {
		t.Errorf("the row reads %+v, want the settings of the body", written[0])
	}
	wantOneEvent(t, audit.ActionProjectCreated, view.ID)
}

// TestCreateRefusesAnotherOrganization refuses an ORG_OWNER who names an
// organization it does not own. A project belongs to one organization, so the
// body decides which gate the write passes.
func TestCreateRefusesAnotherOrganization(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	_, err := svc.Create(context.Background(), admin, CreateBody{OrgID: otherOrgID, Name: "Ledger"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(written) != 0 {
		t.Errorf("a refused create wrote %+v", written)
	}
}

// TestUpdateWritesTheNameAndTheSettings renames one project and stores the four
// settings, as one write with one event.
func TestUpdateWritesTheNameAndTheSettings(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Project{{
			ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID, Name: "Checkout", State: StateActive,
		}},
	})

	view, err := svc.Update(context.Background(), admin, testProjectID, UpdateBody{
		Name:     "Checkout Renamed",
		Settings: Settings{HasProjectCheck: true, PrivateLabeling: 2},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if view.Name != "Checkout Renamed" || !view.HasProjectCheck || view.PrivateLabeling != 2 {
		t.Errorf("the view reads %+v, want the new name and settings", view)
	}
	if len(updated) != 1 || updated[0].ID != testProjectID || updated[0].Name != "Checkout Renamed" {
		t.Fatalf("the write wrote %+v, want one update of %s", updated, testProjectID)
	}
	if !updated[0].HasProjectCheck || updated[0].PrivateLabeling != 2 || updated[0].OrgID != testOrgID {
		t.Errorf("the row reads %+v, want the settings of the body and the organization of the row", updated[0])
	}
	wantOneEvent(t, audit.ActionProjectUpdated, testProjectID)
}

// TestUpdateRefusesAnotherOrganization refuses an ORG_OWNER who names a project
// of an organization it does not own.
func TestUpdateRefusesAnotherOrganization(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
		rows: []Project{{
			ID: otherProjectID, TenantID: testTenantID, OrgID: otherOrgID, Name: "Ledger",
		}},
	})

	_, err := svc.Update(context.Background(), admin, otherProjectID, UpdateBody{Name: "Taken"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(updated) != 0 {
		t.Errorf("a refused update wrote %+v", updated)
	}
}

// TestUpdateRefusesAUserManager refuses an ORG_USER_MANAGER of the same
// organization. That role administers people, not the projects of the
// organization.
func TestUpdateRefusesAUserManager(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows:        []Project{{ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID, Name: "Checkout"}},
	})

	_, err := svc.Update(context.Background(), admin, testProjectID, UpdateBody{Name: "Taken"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// TestDeleteSoftDeletesAndRecordsOneEvent removes one project and records one
// event.
func TestDeleteSoftDeletesAndRecordsOneEvent(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
		rows:        []Project{{ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID, Name: "Checkout"}},
	})

	if err := svc.Delete(context.Background(), admin, testProjectID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != testProjectID {
		t.Fatalf("the write deleted %v, want %s", deleted, testProjectID)
	}
	wantOneEvent(t, audit.ActionProjectDeleted, testProjectID)
}

// TestDeleteRollsBackAFailedAuditWrite proves the change and the trail land
// together. A change nobody can audit is not allowed to stand.
func TestDeleteRollsBackAFailedAuditWrite(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Project{{ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID, Name: "Checkout"}},
		auditFails:  true,
	})

	if err := svc.Delete(context.Background(), admin, testProjectID); err == nil {
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
	if got.EntityType != audit.EntityProject || got.EntityID != entityID {
		t.Errorf("the event names %s %s, want %s %s",
			got.EntityType, got.EntityID, audit.EntityProject, entityID)
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
	memberships []organization.Membership
	rows        []Project
	auditFails  bool
}

// What the writes of one test did. testService clears them, and the tests of
// one package run one after another, so each test reads its own writes.
var (
	written    []Project
	updated    []Project
	deleted    []string
	events     []audit.Event
	rolledBack bool
)

func testService(t *testing.T, d deps) *Service {
	t.Helper()
	log, _ := logger.NewObserved()
	written, updated, deleted, events, rolledBack = nil, nil, nil, nil, false

	record := func(_ context.Context, e audit.Event) error {
		if d.auditFails {
			return errors.New("the audit write failed")
		}
		events = append(events, e)
		return nil
	}

	return NewService(Deps{
		Insert: func(_ context.Context, row Project) error {
			written = append(written, row)
			return nil
		},
		Update: func(_ context.Context, row Project) error {
			updated = append(updated, row)
			return nil
		},
		Delete: func(_ context.Context, _, projectID string) error {
			deleted = append(deleted, projectID)
			return nil
		},
		// The unit of work either commits whole or leaves nothing behind, so a
		// failed step clears what the earlier steps wrote.
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			before := len(written) + len(updated) + len(deleted)
			err := fn(ctx)
			if err != nil && len(written)+len(updated)+len(deleted) != before {
				written, updated, deleted, rolledBack = nil, nil, nil, true
			}
			return err
		},
		Audit: audit.NewRecorder(record, log),
		List: func(context.Context, string, Query) ([]Project, int64, error) {
			return d.rows, int64(len(d.rows)), nil
		},
		Find: func(_ context.Context, _, projectID string) (Project, error) {
			for _, row := range d.rows {
				if row.ID == projectID {
					return row, nil
				}
			}
			return Project{}, ErrNotFound
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) {
			return d.tenantRoles, nil
		},
		Memberships: func(context.Context, string, string) ([]organization.Membership, error) {
			return d.memberships, nil
		},
		Log: log,
	})
}
