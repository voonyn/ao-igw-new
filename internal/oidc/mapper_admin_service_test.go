package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/tenant"
)

// seededMappers is the claim set every mapper test starts from: the two claims
// the migration seeded on the builtin email scope, and one the tenant wrote on
// its own scope.
func seededMappers() []ClaimMapperRow {
	return []ClaimMapperRow{
		{
			ID: "m-email", TenantID: grantTenantID, ScopeID: "s-email",
			ClaimName: "email", SourceType: SourceStandard, SourceKey: "email",
			InUserInfo: true,
		},
		{
			ID: "m-verified", TenantID: grantTenantID, ScopeID: "s-email",
			ClaimName: "email_verified", SourceType: SourceStandard, SourceKey: "email_verified",
			InUserInfo: true,
		},
		{
			ID: "m-groups", TenantID: grantTenantID, ScopeID: "s-groups",
			ClaimName: "groups", SourceType: SourceBag, SourceKey: "groups",
			InUserInfo: true, InIDToken: true,
		},
	}
}

// What the mapper writes of one test left behind.
var (
	insertedMappers []ClaimMapperRow
	updatedMappers  []ClaimMapperRow
	deletedMappers  []string
	mapperCount     int
)

func testMapperAdminService(t *testing.T, roles []string) *ScopeAdminService {
	t.Helper()
	insertedMappers, updatedMappers, deletedMappers, scopeEvents = nil, nil, nil, nil
	mapperCount = 1

	svc := testScopeAdminService(t, roles)
	stored := seededMappers()

	svc.deps.ListMappers = func(_ context.Context, _, scopeID string) ([]ClaimMapperRow, error) {
		var out []ClaimMapperRow
		for _, row := range stored {
			if row.ScopeID == scopeID {
				out = append(out, row)
			}
		}
		return out, nil
	}
	svc.deps.FindMapper = func(_ context.Context, _, id string) (ClaimMapperRow, error) {
		for _, row := range stored {
			if row.ID == id {
				return row, nil
			}
		}
		return ClaimMapperRow{}, fmt.Errorf("%w: %s", ErrMapperNotFound, id)
	}
	svc.deps.CountMappers = func(context.Context, string, string) (int, error) {
		return mapperCount, nil
	}
	svc.deps.InsertMapper = func(_ context.Context, row ClaimMapperRow) error {
		insertedMappers = append(insertedMappers, row)
		return nil
	}
	svc.deps.UpdateMapper = func(_ context.Context, row ClaimMapperRow) error {
		updatedMappers = append(updatedMappers, row)
		return nil
	}
	svc.deps.DeleteMapper = func(_ context.Context, _, id string) error {
		deletedMappers = append(deletedMappers, id)
		return nil
	}
	svc.deps.InTx = func(ctx context.Context, fn func(context.Context) error) error {
		err := fn(ctx)
		if err != nil {
			insertedMappers, updatedMappers, deletedMappers = nil, nil, nil
		}
		return err
	}
	return svc
}

// TestListMappersReadsTheClaimsOfOneScope covers the claim mappers tab. The list
// is bounded by the limit this service enforces, so it is not paged, and it
// answers the claims of the named scope alone.
func TestListMappersReadsTheClaimsOfOneScope(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	views, err := svc.ListMappers(context.Background(), scopeOperator, "s-groups")
	if err != nil {
		t.Fatalf("list the claim mappers: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("the scope reads %d claims, want 1", len(views))
	}
	if views[0].ClaimName != "groups" || views[0].ScopeID != "s-groups" {
		t.Errorf("the claim reads %+v, want the groups claim", views[0])
	}
	if !views[0].InIDToken || !views[0].InUserInfo || views[0].InAccessToken {
		t.Errorf("the claim reads %+v, want the two seeded delivery flags", views[0])
	}

	svc = testMapperAdminService(t, []string{tenant.RoleIAMAdmin})
	if _, err := svc.ListMappers(context.Background(), scopeOperator, "s-groups"); !errors.Is(err, ErrForbidden) {
		t.Errorf("a tenant administrator reads %v, want ErrForbidden", err)
	}
}

// TestListMappersRefusesAScopeTheTenantDoesNotHold covers the path parameter. A
// scope of another tenant reads the way a scope nobody holds reads.
func TestListMappersRefusesAScopeTheTenantDoesNotHold(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	_, err := svc.ListMappers(context.Background(), scopeOperator, "s-elsewhere")
	if !errors.Is(err, ErrScopeNotFound) {
		t.Errorf("a scope the tenant does not hold reads %v, want ErrScopeNotFound", err)
	}
}

// TestCreateMapperWritesAClaim covers the write an operator makes, and the audit
// event that records it. The scope the claim belongs to is in the metadata,
// because the trail is searched by the scope an operator names.
func TestCreateMapperWritesAClaim(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	view, err := svc.CreateMapper(context.Background(), scopeOperator, "s-groups", MapperBody{
		ClaimName: "department", SourceType: SourceBag, SourceKey: "department",
		InUserInfo: true,
	})
	if err != nil {
		t.Fatalf("create a claim mapper: %v", err)
	}
	if len(insertedMappers) != 1 {
		t.Fatalf("the write inserted %d rows, want one", len(insertedMappers))
	}
	if insertedMappers[0].ClaimName != "department" || insertedMappers[0].ScopeID != "s-groups" {
		t.Errorf("the row reads %+v, want the department claim on the groups scope", insertedMappers[0])
	}
	if view.ID != insertedMappers[0].ID || view.ID == "" {
		t.Errorf("the answer reads id %q, want the id that was written", view.ID)
	}

	if len(scopeEvents) != 1 {
		t.Fatalf("the write recorded %d events, want 1", len(scopeEvents))
	}
	event := scopeEvents[0]
	if event.Action != string(audit.ActionMapperCreated) || event.EntityType != audit.EntityClaimMapper {
		t.Errorf("the event reads %+v, want the created claim mapper", event)
	}
	if !strings.Contains(event.Metadata, "s-groups") || !strings.Contains(event.Metadata, "department") {
		t.Errorf("the event carries %s, want the scope and the claim", event.Metadata)
	}
}

// TestCreateMapperRefusesAProtectedClaim covers the claim names this API does
// not write. A protocol claim is built by the token issuer, so a mapper naming
// one would be overwritten or would corrupt the token. A trust claim states what
// the gateway verified, so it is released by the seeded mapper alone and never
// by a rule an operator points at any column.
func TestCreateMapperRefusesAProtectedClaim(t *testing.T) {
	for _, claim := range []string{"sub", "iss", "aud", "exp", "nonce", "email_verified"} {
		svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

		_, err := svc.CreateMapper(context.Background(), scopeOperator, "s-groups", MapperBody{
			ClaimName: claim, SourceType: SourceBag, SourceKey: "anything", InUserInfo: true,
		})
		if !errors.Is(err, ErrProtectedClaim) {
			t.Errorf("the claim %q reads %v, want ErrProtectedClaim", claim, err)
		}
		if len(insertedMappers) != 0 {
			t.Errorf("the refused write inserted %+v, want nothing", insertedMappers)
		}
	}
}

// TestCreateMapperRefusesAClaimTheScopeAlreadyReleases covers the unique key on
// the table. One scope releases one claim once, because a second rule for the
// same key would make the value of the claim depend on the read order.
func TestCreateMapperRefusesAClaimTheScopeAlreadyReleases(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	_, err := svc.CreateMapper(context.Background(), scopeOperator, "s-groups", MapperBody{
		ClaimName: "groups", SourceType: SourceBag, SourceKey: "teams", InUserInfo: true,
	})
	if !errors.Is(err, ErrClaimTaken) {
		t.Errorf("a claim the scope releases reads %v, want ErrClaimTaken", err)
	}
	if len(insertedMappers) != 0 {
		t.Errorf("the refused write inserted %+v, want nothing", insertedMappers)
	}
}

// TestCreateMapperRefusesTooManyClaims covers the limit on one scope. Every
// mapper of a granted scope is resolved on every token build and on every
// UserInfo read, so an unbounded set is a cost the tenant pays per request.
func TestCreateMapperRefusesTooManyClaims(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})
	mapperCount = MaxMappersPerScope

	_, err := svc.CreateMapper(context.Background(), scopeOperator, "s-groups", MapperBody{
		ClaimName: "department", SourceType: SourceBag, SourceKey: "department", InUserInfo: true,
	})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("the claim past the limit reads %v, want ErrLimitExceeded", err)
	}
	if len(insertedMappers) != 0 {
		t.Errorf("the refused write inserted %+v, want nothing", insertedMappers)
	}
}

// TestCreateMapperRefusesAnOversizedStaticValue covers the second limit. A
// static value is copied into every token the scope is granted on, so a large
// one inflates every token of the tenant.
func TestCreateMapperRefusesAnOversizedStaticValue(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	_, err := svc.CreateMapper(context.Background(), scopeOperator, "s-groups", MapperBody{
		ClaimName: "banner", SourceType: SourceStatic, InUserInfo: true,
		SourceValue: strings.Repeat("a", MaxSourceValueBytes),
	})
	if !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("the oversized value reads %v, want ErrLimitExceeded", err)
	}
	if len(insertedMappers) != 0 {
		t.Errorf("the refused write inserted %+v, want nothing", insertedMappers)
	}
}

// TestCreateMapperStoresAStaticValueAsJSON covers the one source type that
// carries a value instead of a key. The console sends whatever JSON the operator
// typed, and the column stores it as JSON so the token releases the same shape.
func TestCreateMapperStoresAStaticValueAsJSON(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	view, err := svc.CreateMapper(context.Background(), scopeOperator, "s-groups", MapperBody{
		ClaimName: "tier", SourceType: SourceStatic, InUserInfo: true,
		SourceValue: []any{"gold", "silver"},
	})
	if err != nil {
		t.Fatalf("create a static claim mapper: %v", err)
	}
	if insertedMappers[0].SourceValue != `["gold","silver"]` {
		t.Errorf("the row stores %s, want the JSON the operator wrote", insertedMappers[0].SourceValue)
	}
	values, ok := view.SourceValue.([]any)
	if !ok || len(values) != 2 || values[0] != "gold" {
		t.Errorf("the answer reads %v, want the value back as JSON", view.SourceValue)
	}
}

// TestUpdateMapperWritesTheClaim covers the write an operator makes on a claim
// that already exists, and the delivery flags it changes.
func TestUpdateMapperWritesTheClaim(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	view, err := svc.UpdateMapper(context.Background(), scopeOperator, "m-groups", MapperBody{
		ClaimName: "groups", SourceType: SourceBag, SourceKey: "teams",
		InUserInfo: true, InIDToken: false, InAccessToken: true,
	})
	if err != nil {
		t.Fatalf("write a claim mapper: %v", err)
	}
	if len(updatedMappers) != 1 || updatedMappers[0].SourceKey != "teams" {
		t.Errorf("the row reads %+v, want the new source key", updatedMappers)
	}
	if view.InIDToken || !view.InAccessToken {
		t.Errorf("the answer reads %+v, want the delivery flags that were written", view)
	}
	if len(scopeEvents) != 1 || scopeEvents[0].Action != string(audit.ActionMapperUpdated) {
		t.Errorf("the write recorded %+v, want one claim_mapper.updated event", scopeEvents)
	}
}

// TestWritingASeededTrustClaimIsRefused covers the mapper the migration locked.
// email_verified states what the gateway verified, so neither a rewrite nor a
// delete of the rule that releases it is served.
func TestWritingASeededTrustClaimIsRefused(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	_, err := svc.UpdateMapper(context.Background(), scopeOperator, "m-verified", MapperBody{
		ClaimName: "email_verified", SourceType: SourceBag, SourceKey: "trusted", InUserInfo: true,
	})
	if !errors.Is(err, ErrProtectedClaim) {
		t.Errorf("a rewrite of the trust claim reads %v, want ErrProtectedClaim", err)
	}

	svc = testMapperAdminService(t, []string{tenant.RoleIAMOwner})
	if err := svc.DeleteMapper(context.Background(), scopeOperator, "m-verified"); !errors.Is(err, ErrProtectedClaim) {
		t.Errorf("a delete of the trust claim reads %v, want ErrProtectedClaim", err)
	}
	if len(deletedMappers) != 0 {
		t.Errorf("the refused delete removed %v, want nothing", deletedMappers)
	}
}

// TestDeleteMapperRemovesTheClaim covers the delete, and the claim that no
// longer exists.
func TestDeleteMapperRemovesTheClaim(t *testing.T) {
	svc := testMapperAdminService(t, []string{tenant.RoleIAMOwner})

	if err := svc.DeleteMapper(context.Background(), scopeOperator, "m-groups"); err != nil {
		t.Fatalf("delete a claim mapper: %v", err)
	}
	if len(deletedMappers) != 1 || deletedMappers[0] != "m-groups" {
		t.Errorf("the delete removed %v, want the groups claim", deletedMappers)
	}
	if len(scopeEvents) != 1 || scopeEvents[0].Action != string(audit.ActionMapperDeleted) {
		t.Errorf("the delete recorded %+v, want one claim_mapper.deleted event", scopeEvents)
	}

	svc = testMapperAdminService(t, []string{tenant.RoleIAMOwner})
	if err := svc.DeleteMapper(context.Background(), scopeOperator, "m-elsewhere"); !errors.Is(err, ErrMapperNotFound) {
		t.Errorf("a claim the tenant does not hold reads %v, want ErrMapperNotFound", err)
	}
}
