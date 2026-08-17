package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// providerOperator is the person every provider test acts as.
var providerOperator = AdminActor{
	TenantID: grantTenantID, UserID: grantUserID, IP: "203.0.113.7", UserAgent: "a-browser",
}

// seededProvider is the row every provider test starts from. The resource
// indicators carry the admin identifier, because the token this operator holds
// was minted for it.
func seededProvider() ProviderConfig {
	refresh := 2592000
	return ProviderConfig{
		TenantID:                      grantTenantID,
		Issuer:                        "https://auth.acme.com",
		State:                         providerStateActive,
		RequirePKCE:                   true,
		RefreshTokenRotation:          false,
		AuthorizationCodeLifetimeSecs: 60,
		AccessTokenType:               AccessTokenTypeJWT,
		AccessTokenLifetimeSecs:       900,
		IDTokenLifetimeSecs:           900,
		RefreshTokenLifetimeSecs:      &refresh,
		ResourceIndicators:            SeedResourceIndicators,
	}
}

// What the writes of one test left behind.
var (
	patched        []ProviderConfigBody
	providerEvents []audit.Event
)

func testAdminService(t *testing.T, roles []string, keys []Key) *AdminService {
	t.Helper()
	log, _ := logger.NewObserved()
	patched, providerEvents = nil, nil

	// The stored row, so the read that follows a write answers what the write
	// left behind.
	stored := seededProvider()

	return NewAdminService(AdminDeps{
		Provider: func(context.Context, string) (ProviderConfig, error) { return stored, nil },
		Update: func(_ context.Context, _ string, body ProviderConfigBody) error {
			patched = append(patched, body)
			if body.AccessTokenLifetime != nil {
				stored.AccessTokenLifetimeSecs = *body.AccessTokenLifetime
			}
			if body.RefreshRotation != nil {
				stored.RefreshTokenRotation = *body.RefreshRotation
			}
			if body.RequirePKCE != nil {
				stored.RequirePKCE = *body.RequirePKCE
			}
			return nil
		},
		Keys:        func(context.Context, string) ([]Key, error) { return keys, nil },
		TenantRoles: func(context.Context, string, string) ([]string, error) { return roles, nil },
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			err := fn(ctx)
			if err != nil {
				patched = nil
			}
			return err
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			providerEvents = append(providerEvents, e)
			return nil
		}, log),
		Log: log,
	})
}

// TestReadProviderRefusesAnybodyButATenantManager covers the read gate. The
// provider config is the protocol behaviour of the whole tenant, so an
// organization manager does not read it.
func TestReadProviderRefusesAnybodyButATenantManager(t *testing.T) {
	svc := testAdminService(t, []string{"ORG_OWNER"}, nil)
	if _, err := svc.ReadProvider(context.Background(), providerOperator); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner reads %v, want ErrForbidden", err)
	}

	svc = testAdminService(t, []string{tenant.RoleIAMAdmin}, nil)
	if _, err := svc.ReadProvider(context.Background(), providerOperator); err != nil {
		t.Errorf("a tenant administrator reads %v, want the provider config", err)
	}
}

// TestReadProviderNamesTheAccessTokenFormat covers the view the provider screen
// renders. The access token type is stored as a number and read as the name the
// console prints, and the resource identifiers are read only.
func TestReadProviderNamesTheAccessTokenFormat(t *testing.T) {
	svc := testAdminService(t, []string{tenant.RoleIAMOwner}, nil)

	view, err := svc.ReadProvider(context.Background(), providerOperator)
	if err != nil {
		t.Fatalf("read the provider config: %v", err)
	}
	if view.AccessTokenType != AccessTokenNameJWT {
		t.Errorf("the access token reads %q, want %q", view.AccessTokenType, AccessTokenNameJWT)
	}
	if view.Issuer != "https://auth.acme.com" || view.State != providerStateActive {
		t.Errorf("the view reads %+v, want the seeded issuer and state", view)
	}
	if len(view.ResourceIndicators) != 2 || view.ResourceIndicators[0] != ResourceAdminAPI {
		t.Errorf("the view carries %v, want the seeded resource identifiers", view.ResourceIndicators)
	}
	if view.RefreshTokenLifetime == nil || *view.RefreshTokenLifetime != 2592000 {
		t.Errorf("the refresh lifetime reads %v, want the seeded value", view.RefreshTokenLifetime)
	}
}

// TestUpdateProviderRefusesAnybodyButTheOwner covers the write gate. The
// settings decide how every token of the tenant is issued, so only an IAM_OWNER
// writes them.
func TestUpdateProviderRefusesAnybodyButTheOwner(t *testing.T) {
	svc := testAdminService(t, []string{tenant.RoleIAMAdmin}, nil)
	lifetime := 600

	_, err := svc.UpdateProvider(context.Background(), providerOperator,
		ProviderConfigBody{AccessTokenLifetime: &lifetime})
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("a tenant administrator writes %v, want ErrForbidden", err)
	}
	if len(patched) != 0 {
		t.Errorf("the refused write patched %+v, want nothing", patched)
	}
}

// TestUpdateProviderWritesTheChangedFields covers the write an operator makes.
// An omitted field is left alone, so the body carries only what changed, and one
// audit event records the change.
func TestUpdateProviderWritesTheChangedFields(t *testing.T) {
	svc := testAdminService(t, []string{tenant.RoleIAMOwner}, nil)
	lifetime, rotation := 600, true

	view, err := svc.UpdateProvider(context.Background(), providerOperator,
		ProviderConfigBody{AccessTokenLifetime: &lifetime, RefreshRotation: &rotation})
	if err != nil {
		t.Fatalf("write the provider config: %v", err)
	}
	if len(patched) != 1 {
		t.Fatalf("the write patched %d times, want once", len(patched))
	}
	if patched[0].AccessTokenLifetime == nil || *patched[0].AccessTokenLifetime != 600 {
		t.Errorf("the patch carries %v, want the new access token lifetime", patched[0].AccessTokenLifetime)
	}
	if patched[0].IDTokenLifetime != nil || patched[0].RequirePKCE != nil {
		t.Errorf("the patch carries %+v, want the omitted fields left alone", patched[0])
	}

	// The answer is the row as it now stands, so the console renders the saved
	// state without a second read.
	if view.AccessTokenLifetime != 600 || !view.RefreshRotation {
		t.Errorf("the answer reads %+v, want the values that were written", view)
	}

	if len(providerEvents) != 1 {
		t.Fatalf("the write recorded %d events, want 1", len(providerEvents))
	}
	if providerEvents[0].Action != string(audit.ActionProviderUpdated) ||
		providerEvents[0].EntityType != audit.EntityProviderConfig ||
		providerEvents[0].EntityID != grantTenantID {
		t.Errorf("the event reads %+v, want the provider config of the tenant", providerEvents[0])
	}
}

// TestUpdateProviderRefusesAnOpaqueAccessToken covers the guard on the one
// writable field that can take the tenant off the air. The protocol engine
// refuses to build a provider that issues opaque access tokens, so a tenant that
// stored the value would answer nothing at all, and no admin token could be
// minted to put it back.
func TestUpdateProviderRefusesAnOpaqueAccessToken(t *testing.T) {
	svc := testAdminService(t, []string{tenant.RoleIAMOwner}, nil)
	opaque := AccessTokenNameOpaque

	_, err := svc.UpdateProvider(context.Background(), providerOperator,
		ProviderConfigBody{AccessTokenType: &opaque})
	if !errors.Is(err, ErrOpaqueAccessToken) {
		t.Errorf("an opaque access token reads %v, want ErrOpaqueAccessToken", err)
	}
	if len(patched) != 0 {
		t.Errorf("the refused write patched %+v, want nothing", patched)
	}
}

// TestUpdateProviderLeavesTheResourceIndicators covers the read-only field. The
// admin resource identifier decides which audiences a client may ask for, and
// the admin guard admits that value alone: an operator who removed it could not
// mint another admin token, and no console route could put it back.
func TestUpdateProviderLeavesTheResourceIndicators(t *testing.T) {
	svc := testAdminService(t, []string{tenant.RoleIAMOwner}, nil)
	pkce := false

	view, err := svc.UpdateProvider(context.Background(), providerOperator,
		ProviderConfigBody{RequirePKCE: &pkce})
	if err != nil {
		t.Fatalf("write the provider config: %v", err)
	}
	if len(view.ResourceIndicators) != 2 || view.ResourceIndicators[0] != ResourceAdminAPI {
		t.Errorf("the answer carries %v, want the resource identifiers untouched", view.ResourceIndicators)
	}
	if view.Issuer != "https://auth.acme.com" {
		t.Errorf("the answer reads issuer %q, want the stored issuer", view.Issuer)
	}
}

// TestListKeysRefusesAnybodyButATenantManager covers the key gate. A key signs
// every token of the tenant, so only a tenant manager reads the set.
func TestListKeysRefusesAnybodyButATenantManager(t *testing.T) {
	svc := testAdminService(t, []string{"ORG_OWNER"}, nil)
	if _, err := svc.ListKeys(context.Background(), providerOperator); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner reads %v, want ErrForbidden", err)
	}
}

// TestListKeysCarriesNoPrivateMaterial covers what the console reads on the keys
// page. The private half never leaves the gateway, at any level and in any
// environment, so the view carries the lifecycle columns alone. A key with no
// rotation window reads null and not a zero date.
func TestListKeysCarriesNoPrivateMaterial(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	svc := testAdminService(t, []string{tenant.RoleIAMOwner}, []Key{
		{
			ID: "k1", TenantID: grantTenantID, KeyUse: keyUseSig, Algorithm: "RS256",
			State: KeyStateActive, PublicKey: []byte(`{"kty":"RSA"}`), PrivateKey: []byte("sealed"),
			ActiveAt: at, ExpiresAt: at.Add(time.Hour), CreatedAt: at, UpdatedAt: at,
		},
		{
			ID: "k2", TenantID: grantTenantID, KeyUse: keyUseSig, Algorithm: "ES256",
			State: KeyStateRetired, CreatedAt: at, UpdatedAt: at,
		},
	})

	views, err := svc.ListKeys(context.Background(), providerOperator)
	if err != nil {
		t.Fatalf("list the keys: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("the tenant reads %d keys, want 2", len(views))
	}
	if views[0].ID != "k1" || views[0].Alg != "RS256" || views[0].State != KeyStateActive {
		t.Errorf("the first key reads %+v, want the active key", views[0])
	}
	if views[0].ActiveAt == nil || !views[0].ActiveAt.Equal(at) {
		t.Errorf("the first key signs from %v, want the seeded moment", views[0].ActiveAt)
	}
	if views[1].ExpiresAt != nil || views[1].ActiveAt != nil {
		t.Errorf("the retired key reads %+v, want no rotation window", views[1])
	}
}
