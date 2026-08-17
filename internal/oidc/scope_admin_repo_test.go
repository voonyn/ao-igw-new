package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

// seedScopeRegistry writes the registry the repository tests read: one builtin
// scope with two claims, one custom scope with one claim, and one scope of
// another tenant that no read of this tenant answers.
//
// One client of the tenant holds the builtin scope on its allow-list, so the
// count that guards a delete has something to find.
func seedScopeRegistry(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	scope := func(id, tenantID, name string, builtin bool) {
		t.Helper()
		exec(`INSERT INTO oidc_scopes (id, tenant_id, name, display_name, description,
		        is_enabled, is_default, is_builtin)
		      VALUES (?, ?, ?, ?, 'Seeded.', 1, 0, ?)`, id, tenantID, name, name, builtin)
	}
	scope("s-email", grantTenantID, "email", true)
	scope("s-groups", grantTenantID, "groups", false)
	scope("s-foreign", otherTenantID, "groups", false)

	mapper := func(id, scopeID, claim string) {
		t.Helper()
		exec(`INSERT INTO oidc_claim_mappers (id, tenant_id, scope_id, claim_name,
		        source_type, source_key, in_id_token, in_userinfo, in_access_token)
		      VALUES (?, ?, ?, ?, 1, ?, 0, 1, 0)`, id, grantTenantID, scopeID, claim, claim)
	}
	mapper("m-email", "s-email", "email")
	mapper("m-verified", "s-email", "email_verified")
	mapper("m-groups", "s-groups", "groups")

	// A client of the tenant that still asks for the builtin scope.
	exec(`INSERT INTO applications (id, tenant_id, project_id, name, state, app_type)
	      VALUES ('app-1', ?, 'p-1', 'The console', 1, 1)`, grantTenantID)
	exec(`INSERT INTO application_oidc_configs (app_id, tenant_id, client_id, created_at,
	        scopes, redirect_uris, grant_types, response_types)
	      VALUES ('app-1', ?, 'client-1', NOW(3), 'openid profile email',
	              JSON_ARRAY(), JSON_ARRAY(), JSON_ARRAY())`, grantTenantID)
}

func testScopeRepo(t *testing.T) (*ScopeRepository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "oidc_scope_admin")
	seedScopeRegistry(t, bdb)
	return NewScopeRepository(bdb, logger.New()), context.Background()
}

// TestListScopesCountsTheClaimsOfEachScope covers the read behind the scopes
// page. A disabled scope is on the page, because an operator who cannot see it
// cannot switch it back on, and each row names how many claims it releases.
func TestListScopesCountsTheClaimsOfEachScope(t *testing.T) {
	repo, ctx := testScopeRepo(t)
	if _, err := repo.db.ExecContext(ctx,
		`UPDATE oidc_scopes SET is_enabled = 0 WHERE id = 's-groups'`); err != nil {
		t.Fatalf("disable the custom scope: %v", err)
	}

	rows, err := repo.ListScopes(ctx, grantTenantID)
	if err != nil {
		t.Fatalf("list the scopes: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("the tenant reads %d scopes, want 2", len(rows))
	}
	if rows[0].Name != "email" || rows[0].MapperCount != 2 || !rows[0].IsBuiltin {
		t.Errorf("the first scope reads %+v, want the builtin email scope with two claims", rows[0])
	}
	if rows[1].Name != "groups" || rows[1].IsEnabled || rows[1].MapperCount != 1 {
		t.Errorf("the second scope reads %+v, want the disabled custom scope", rows[1])
	}

	// The advertised read is the other half of this pair. It drops the disabled
	// scope, because a disabled scope is neither advertised nor granted.
	advertised, err := repo.List(ctx, grantTenantID)
	if err != nil {
		t.Fatalf("list the advertised scopes: %v", err)
	}
	if len(advertised) != 1 || advertised[0].Name != "email" {
		t.Errorf("the tenant advertises %+v, want the enabled scope alone", advertised)
	}
}

// TestFindScopeReadsOneTenantOnly covers the tenant clause of both reads. A
// scope of another tenant reads the way a scope nobody holds reads, so no path
// parameter can reach across a tenant boundary.
func TestFindScopeReadsOneTenantOnly(t *testing.T) {
	repo, ctx := testScopeRepo(t)

	row, err := repo.FindScope(ctx, grantTenantID, "s-groups")
	if err != nil {
		t.Fatalf("read one scope: %v", err)
	}
	if row.Name != "groups" || row.IsBuiltin {
		t.Errorf("the scope reads %+v, want the custom groups scope", row)
	}

	if _, err := repo.FindScope(ctx, grantTenantID, "s-foreign"); !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("a scope of another tenant reads %v, want ErrScopeNotFound", err)
	}

	// The name is unique per tenant, so both tenants hold a scope named groups
	// and each read answers its own.
	byName, err := repo.FindScopeByName(ctx, otherTenantID, "groups")
	if err != nil {
		t.Fatalf("read a scope by name: %v", err)
	}
	if byName.ID != "s-foreign" {
		t.Errorf("the read answers %q, want the scope of the other tenant", byName.ID)
	}
	if _, err := repo.FindScopeByName(ctx, grantTenantID, "nothing"); !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("a name nobody holds reads %v, want ErrScopeNotFound", err)
	}
}

// TestInsertAndUpdateScopeWriteTheWritableFields covers the whole writable
// surface of the table. is_builtin is not written by either statement, so a
// scope an operator wrote can always be deleted.
func TestInsertAndUpdateScopeWriteTheWritableFields(t *testing.T) {
	repo, ctx := testScopeRepo(t)

	err := repo.InsertScope(ctx, ScopeRow{
		ID: "s-roles", TenantID: grantTenantID, Name: "roles",
		DisplayName: "Roles", Description: "The roles of the person.",
		IsEnabled: true, IsDefault: true,
	})
	if err != nil {
		t.Fatalf("write a new scope: %v", err)
	}

	row, err := repo.FindScope(ctx, grantTenantID, "s-roles")
	if err != nil {
		t.Fatalf("read the new scope: %v", err)
	}
	if row.Name != "roles" || !row.IsDefault || row.IsBuiltin {
		t.Errorf("the row reads %+v, want a custom default scope", row)
	}
	if row.CreatedAt.IsZero() || row.UpdatedAt.IsZero() {
		t.Errorf("the row reads %+v, want both moments", row)
	}

	row.Name = "positions"
	row.Description = ""
	row.IsEnabled = false
	if err := repo.UpdateScope(ctx, row); err != nil {
		t.Fatalf("write the scope: %v", err)
	}

	row, err = repo.FindScope(ctx, grantTenantID, "s-roles")
	if err != nil {
		t.Fatalf("read the written scope: %v", err)
	}
	if row.Name != "positions" || row.IsEnabled || row.Description != "" {
		t.Errorf("the row reads %+v, want the written values", row)
	}
}

// TestDeleteScopeTakesItsClaimMappers covers the soft delete. The scope leaves
// every read, and so do the claims it released: a mapper left behind would
// release a claim for a scope nobody can grant.
//
// The name is freed by the delete, because the unique key counts the deletion
// moment, so an operator can write a new scope with the same name.
func TestDeleteScopeTakesItsClaimMappers(t *testing.T) {
	repo, ctx := testScopeRepo(t)

	if err := repo.DeleteScope(ctx, grantTenantID, "s-groups"); err != nil {
		t.Fatalf("delete a scope: %v", err)
	}
	if _, err := repo.FindScope(ctx, grantTenantID, "s-groups"); !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("the deleted scope reads %v, want ErrScopeNotFound", err)
	}

	count, err := repo.CountMappers(ctx, grantTenantID, "s-groups")
	if err != nil {
		t.Fatalf("count the claims of the deleted scope: %v", err)
	}
	if count != 0 {
		t.Errorf("the deleted scope holds %d claims, want none", count)
	}

	err = repo.InsertScope(ctx, ScopeRow{
		ID: "s-groups-2", TenantID: grantTenantID, Name: "groups", IsEnabled: true,
	})
	if err != nil {
		t.Errorf("write the freed name: %v", err)
	}
}

// TestCountClientsWithScopeReadsTheAllowList covers the guard on a scope delete.
// The column holds the scope names of one client as one space-separated string,
// so the read has to match a whole name and never a prefix.
func TestCountClientsWithScopeReadsTheAllowList(t *testing.T) {
	repo, ctx := testScopeRepo(t)

	count, err := repo.CountClientsWithScope(ctx, grantTenantID, "email")
	if err != nil {
		t.Fatalf("count the clients: %v", err)
	}
	if count != 1 {
		t.Errorf("the email scope reads %d clients, want 1", count)
	}

	// "mail" is a prefix of no name on the list, and "profile email" is not one
	// name at all.
	for _, name := range []string{"mail", "groups", "profile email"} {
		count, err := repo.CountClientsWithScope(ctx, grantTenantID, name)
		if err != nil {
			t.Fatalf("count the clients of %q: %v", name, err)
		}
		if count != 0 {
			t.Errorf("the scope %q reads %d clients, want none", name, count)
		}
	}

	// The count is of one tenant. A client of another tenant never holds a scope
	// of this one.
	count, err = repo.CountClientsWithScope(ctx, otherTenantID, "email")
	if err != nil {
		t.Fatalf("count the clients of the other tenant: %v", err)
	}
	if count != 0 {
		t.Errorf("the other tenant reads %d clients, want none", count)
	}
}

// TestClaimMapperWritesRoundTrip covers the four mapper statements, and the JSON
// column a static mapper carries.
func TestClaimMapperWritesRoundTrip(t *testing.T) {
	repo, ctx := testScopeRepo(t)

	err := repo.InsertMapper(ctx, ClaimMapperRow{
		ID: "m-tier", TenantID: grantTenantID, ScopeID: "s-groups",
		ClaimName: "tier", SourceType: SourceStatic,
		SourceValue: `["gold","silver"]`, InUserInfo: true,
	})
	if err != nil {
		t.Fatalf("write a static claim mapper: %v", err)
	}

	row, err := repo.FindMapper(ctx, grantTenantID, "m-tier")
	if err != nil {
		t.Fatalf("read the claim mapper: %v", err)
	}
	if row.ClaimName != "tier" || row.SourceKey != "" || !row.InUserInfo {
		t.Errorf("the row reads %+v, want the static tier claim", row)
	}
	if row.SourceValue != `["gold", "silver"]` && row.SourceValue != `["gold","silver"]` {
		t.Errorf("the row stores %s, want the JSON that was written", row.SourceValue)
	}

	row.SourceType = SourceBag
	row.SourceKey = "tier"
	row.SourceValue = ""
	row.InIDToken = true
	if err := repo.UpdateMapper(ctx, row); err != nil {
		t.Fatalf("write the claim mapper: %v", err)
	}

	rows, err := repo.ListMappers(ctx, grantTenantID, "s-groups")
	if err != nil {
		t.Fatalf("list the claim mappers: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("the scope reads %d claims, want 2", len(rows))
	}
	written := rows[0]
	if written.ClaimName != "groups" {
		written = rows[1]
	}
	if written.ClaimName == "tier" && (written.SourceKey != "tier" || len(written.SourceValue) != 0) {
		t.Errorf("the row reads %+v, want the source value cleared", written)
	}

	if err := repo.DeleteMapper(ctx, grantTenantID, "m-tier"); err != nil {
		t.Fatalf("delete the claim mapper: %v", err)
	}
	if _, err := repo.FindMapper(ctx, grantTenantID, "m-tier"); !errors.Is(err, ErrMapperNotFound) {
		t.Errorf("the deleted claim reads %v, want ErrMapperNotFound", err)
	}

	// A claim mapper of another tenant reads the way one nobody holds reads.
	if _, err := repo.FindMapper(ctx, otherTenantID, "m-groups"); !errors.Is(err, ErrMapperNotFound) {
		t.Errorf("a claim of another tenant reads %v, want ErrMapperNotFound", err)
	}
}
