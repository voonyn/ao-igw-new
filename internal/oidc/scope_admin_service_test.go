package oidc

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// scopeOperator is the person every scope test acts as.
var scopeOperator = AdminActor{
	TenantID: grantTenantID, UserID: grantUserID, IP: "203.0.113.7", UserAgent: "a-browser",
}

// seededScopes is the registry every scope test starts from: one builtin scope
// and one the tenant wrote itself.
func seededScopes() []ScopeRow {
	return []ScopeRow{
		{
			ID: "s-email", TenantID: grantTenantID, Name: "email",
			DisplayName: "Email", Description: "Email address.",
			IsEnabled: true, IsDefault: true, IsBuiltin: true, MapperCount: 2,
		},
		{
			ID: "s-groups", TenantID: grantTenantID, Name: "groups",
			DisplayName: "Groups", IsEnabled: true, MapperCount: 1,
		},
		{
			ID: "s-teams", TenantID: grantTenantID, Name: "teams",
			DisplayName: "Teams", IsEnabled: true,
		},
	}
}

// What the writes of one test left behind.
var (
	insertedScopes []ScopeRow
	updatedScopes  []ScopeRow
	deletedScopes  []string
	scopeEvents    []audit.Event
)

func testScopeAdminService(t *testing.T, roles []string) *ScopeAdminService {
	t.Helper()
	log, _ := logger.NewObserved()
	insertedScopes, updatedScopes, deletedScopes, scopeEvents = nil, nil, nil, nil

	stored := seededScopes()
	find := func(id string) (ScopeRow, error) {
		for _, row := range stored {
			if row.ID == id {
				return row, nil
			}
		}
		return ScopeRow{}, fmt.Errorf("%w: %s", ErrScopeNotFound, id)
	}

	return NewScopeAdminService(ScopeAdminDeps{
		ListScopes: func(context.Context, string) ([]ScopeRow, error) { return stored, nil },
		FindScope:  func(_ context.Context, _, id string) (ScopeRow, error) { return find(id) },
		FindScopeByName: func(_ context.Context, _, name string) (ScopeRow, error) {
			for _, row := range stored {
				if row.Name == name {
					return row, nil
				}
			}
			return ScopeRow{}, fmt.Errorf("%w: %s", ErrScopeNotFound, name)
		},
		InsertScope: func(_ context.Context, row ScopeRow) error {
			insertedScopes = append(insertedScopes, row)
			return nil
		},
		UpdateScope: func(_ context.Context, row ScopeRow) error {
			updatedScopes = append(updatedScopes, row)
			return nil
		},
		DeleteScope: func(_ context.Context, _, id string) error {
			deletedScopes = append(deletedScopes, id)
			return nil
		},
		CountClientsWithScope: func(_ context.Context, _, name string) (int, error) {
			// One client still holds the groups scope. Nothing holds teams.
			if name == "groups" {
				return 1, nil
			}
			return 0, nil
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) { return roles, nil },
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			err := fn(ctx)
			if err != nil {
				insertedScopes, updatedScopes, deletedScopes = nil, nil, nil
			}
			return err
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			scopeEvents = append(scopeEvents, e)
			return nil
		}, log),
		Log: log,
	})
}

// TestListScopesRefusesAnybodyButTheOwner covers the gate of the registry. A
// scope decides which claims every client of the tenant can ask for, so only an
// IAM_OWNER reads it. A tenant administrator is not enough.
func TestListScopesRefusesAnybodyButTheOwner(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMAdmin})
	if _, err := svc.ListScopes(context.Background(), scopeOperator); !errors.Is(err, ErrForbidden) {
		t.Errorf("a tenant administrator reads %v, want ErrForbidden", err)
	}
}

// TestListScopesCarriesTheMapperCount covers what the scopes page renders. The
// list is bounded and is not paged, and each row names how many claims the scope
// releases and whether the seed wrote it.
func TestListScopesCarriesTheMapperCount(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMOwner})

	views, err := svc.ListScopes(context.Background(), scopeOperator)
	if err != nil {
		t.Fatalf("list the scopes: %v", err)
	}
	if len(views) != 3 {
		t.Fatalf("the tenant reads %d scopes, want 3", len(views))
	}
	if views[0].Name != "email" || !views[0].IsBuiltin || views[0].MapperCount != 2 {
		t.Errorf("the first scope reads %+v, want the builtin email scope", views[0])
	}
	if views[1].IsBuiltin {
		t.Errorf("the second scope reads %+v, want a scope the tenant wrote", views[1])
	}
}

// TestCreateScopeWritesACustomScope covers the create an operator makes. The
// scope is never builtin, whatever the body says, and one audit event records
// the write.
func TestCreateScopeWritesACustomScope(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMOwner})

	view, err := svc.CreateScope(context.Background(), scopeOperator, ScopeBody{
		Name: "roles", DisplayName: "Roles", Description: "The roles of the person.",
		IsEnabled: true, IsDefault: true,
	})
	if err != nil {
		t.Fatalf("create a scope: %v", err)
	}
	if len(insertedScopes) != 1 {
		t.Fatalf("the write inserted %d rows, want one", len(insertedScopes))
	}
	if insertedScopes[0].Name != "roles" || insertedScopes[0].IsBuiltin {
		t.Errorf("the row reads %+v, want a custom scope named roles", insertedScopes[0])
	}
	if insertedScopes[0].ID == "" || view.ID != insertedScopes[0].ID {
		t.Errorf("the answer reads id %q, want the id that was written", view.ID)
	}
	if !view.IsDefault || view.MapperCount != 0 {
		t.Errorf("the answer reads %+v, want a default scope with no claims yet", view)
	}

	if len(scopeEvents) != 1 {
		t.Fatalf("the write recorded %d events, want 1", len(scopeEvents))
	}
	if scopeEvents[0].Action != string(audit.ActionScopeCreated) ||
		scopeEvents[0].EntityType != audit.EntityScope ||
		scopeEvents[0].EntityID != view.ID {
		t.Errorf("the event reads %+v, want the created scope", scopeEvents[0])
	}
}

// TestCreateScopeRefusesANameTheTenantHolds covers the unique key on the table.
// Two scopes with one name would make an authorization request ambiguous, so the
// second write is refused by name and nothing is written.
func TestCreateScopeRefusesANameTheTenantHolds(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMOwner})

	_, err := svc.CreateScope(context.Background(), scopeOperator, ScopeBody{
		Name: "email", DisplayName: "Email again", IsEnabled: true,
	})
	if !errors.Is(err, ErrScopeNameTaken) {
		t.Errorf("a name the tenant holds reads %v, want ErrScopeNameTaken", err)
	}
	if len(insertedScopes) != 0 {
		t.Errorf("the refused write inserted %+v, want nothing", insertedScopes)
	}
}

// TestCreateScopeRefusesAnybodyButTheOwner covers the write gate.
func TestCreateScopeRefusesAnybodyButTheOwner(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMAdmin})

	_, err := svc.CreateScope(context.Background(), scopeOperator,
		ScopeBody{Name: "roles", IsEnabled: true})
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("a tenant administrator writes %v, want ErrForbidden", err)
	}
	if len(insertedScopes) != 0 {
		t.Errorf("the refused write inserted %+v, want nothing", insertedScopes)
	}
}

// TestUpdateScopeLocksTheNameOfABuiltinScope covers the one field a builtin
// scope does not give up. The seeded names are the names the protocol and the
// clients already use, so a rename would silently stop a client's request
// resolving. The words and the two switches are still writable.
func TestUpdateScopeLocksTheNameOfABuiltinScope(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMOwner})

	view, err := svc.UpdateScope(context.Background(), scopeOperator, "s-email", ScopeBody{
		Name: "e-mail", DisplayName: "Email address", Description: "New words.",
		IsEnabled: false, IsDefault: false,
	})
	if err != nil {
		t.Fatalf("write the builtin scope: %v", err)
	}
	if len(updatedScopes) != 1 {
		t.Fatalf("the write updated %d rows, want one", len(updatedScopes))
	}
	if updatedScopes[0].Name != "email" {
		t.Errorf("the row reads name %q, want the locked builtin name", updatedScopes[0].Name)
	}
	if view.DisplayName != "Email address" || view.IsEnabled {
		t.Errorf("the answer reads %+v, want the words and the switches written", view)
	}
	if !view.IsBuiltin {
		t.Errorf("the answer reads %+v, want a scope that stays builtin", view)
	}

	if len(scopeEvents) != 1 || scopeEvents[0].Action != string(audit.ActionScopeUpdated) {
		t.Errorf("the write recorded %+v, want one scope.updated event", scopeEvents)
	}
}

// TestUpdateScopeRenamesACustomScope covers the rename a custom scope allows,
// and the name it may not take.
func TestUpdateScopeRenamesACustomScope(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMOwner})

	if _, err := svc.UpdateScope(context.Background(), scopeOperator, "s-groups", ScopeBody{
		Name: "squads", DisplayName: "Squads", IsEnabled: true,
	}); err != nil {
		t.Fatalf("rename a custom scope: %v", err)
	}
	if len(updatedScopes) != 1 || updatedScopes[0].Name != "squads" {
		t.Errorf("the row reads %+v, want the new name", updatedScopes)
	}

	svc = testScopeAdminService(t, []string{tenant.RoleIAMOwner})
	_, err := svc.UpdateScope(context.Background(), scopeOperator, "s-groups", ScopeBody{
		Name: "email", IsEnabled: true,
	})
	if !errors.Is(err, ErrScopeNameTaken) {
		t.Errorf("a name another scope holds reads %v, want ErrScopeNameTaken", err)
	}
	if len(updatedScopes) != 0 {
		t.Errorf("the refused write updated %+v, want nothing", updatedScopes)
	}
}

// TestDeleteScopeRefusesABuiltinScope covers the scope the migration seeded. The
// protocol and every seeded claim mapper name it, so it stays.
func TestDeleteScopeRefusesABuiltinScope(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMOwner})

	err := svc.DeleteScope(context.Background(), scopeOperator, "s-email")
	if !errors.Is(err, ErrBuiltinScope) {
		t.Errorf("deleting a builtin scope reads %v, want ErrBuiltinScope", err)
	}
	if len(deletedScopes) != 0 {
		t.Errorf("the refused delete removed %v, want nothing", deletedScopes)
	}
}

// TestDeleteScopeRefusesAScopeAClientHolds covers the scope still on a client's
// allow-list. Removing it would refuse an authorization request the client makes
// today, and the client would report an invalid scope with nothing to point at.
func TestDeleteScopeRefusesAScopeAClientHolds(t *testing.T) {
	svc := testScopeAdminService(t, []string{tenant.RoleIAMOwner})

	err := svc.DeleteScope(context.Background(), scopeOperator, "s-groups")
	if !errors.Is(err, ErrScopeInUse) {
		t.Errorf("a scope a client holds reads %v, want ErrScopeInUse", err)
	}
	if len(deletedScopes) != 0 {
		t.Errorf("the refused delete removed %v, want nothing", deletedScopes)
	}

	svc = testScopeAdminService(t, []string{tenant.RoleIAMOwner})
	if err := svc.DeleteScope(context.Background(), scopeOperator, "s-teams"); err != nil {
		t.Fatalf("delete an unused custom scope: %v", err)
	}
	if len(deletedScopes) != 1 || deletedScopes[0] != "s-teams" {
		t.Errorf("the delete removed %v, want the custom scope", deletedScopes)
	}
	if len(scopeEvents) != 1 || scopeEvents[0].Action != string(audit.ActionScopeDeleted) {
		t.Errorf("the delete recorded %+v, want one scope.deleted event", scopeEvents)
	}
}
