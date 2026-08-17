package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

// seedProvider writes one active provider config and three keys: an active one,
// an inactive one, and a retired one.
func seedProvider(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO oidc_provider_configs
	        (tenant_id, issuer, state, require_pkce, refresh_token_rotation,
	         authorization_code_lifetime_secs, access_token_type,
	         access_token_lifetime_secs, id_token_lifetime_secs,
	         refresh_token_lifetime_secs, resource_indicators)
	      VALUES (?, 'https://auth.acme.com', 1, 1, 0, 60, 1, 900, 900, 2592000,
	              JSON_ARRAY('urn:alphaomega:admin-api', 'urn:alphaomega:account-api'))`,
		grantTenantID)

	key := func(id string, state int, alg string) {
		t.Helper()
		exec(`INSERT INTO oidc_keys (id, tenant_id, key_use, algorithm, state, public_key, private_key)
		      VALUES (?, ?, 1, ?, ?, '{"kty":"RSA"}', 'sealed')`, id, grantTenantID, alg, state)
	}
	key("k-active", KeyStateActive, "RS256")
	key("k-inactive", KeyStateInactive, "RS256")
	key("k-retired", KeyStateRetired, "ES256")

	// A key of another tenant, which no read of this tenant answers.
	exec(`INSERT INTO oidc_keys (id, tenant_id, key_use, algorithm, state, public_key, private_key)
	      VALUES ('k-foreign', ?, 1, 'RS256', 1, '{"kty":"RSA"}', 'sealed')`, otherTenantID)
}

func testProviderRepo(t *testing.T) (*ProviderRepository, *KeyRepository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "oidc_admin")
	seedProvider(t, bdb)
	log := logger.New()
	return NewProviderRepository(bdb, log), NewKeyRepository(bdb, log), context.Background()
}

// TestUpdateProviderWritesOnlyTheNamedColumns covers the whole writable surface
// of the table. The issuer, the state, and the resource identifiers are read
// only, so a write that names two lifetimes must leave all three untouched.
func TestUpdateProviderWritesOnlyTheNamedColumns(t *testing.T) {
	repo, _, ctx := testProviderRepo(t)
	lifetime, rotation := 600, true

	err := repo.Update(ctx, grantTenantID, ProviderConfigBody{
		AccessTokenLifetime: &lifetime,
		RefreshRotation:     &rotation,
	})
	if err != nil {
		t.Fatalf("write the provider config: %v", err)
	}

	cfg, err := repo.ReadByTenant(ctx, grantTenantID)
	if err != nil {
		t.Fatalf("read the provider config: %v", err)
	}
	if cfg.AccessTokenLifetimeSecs != 600 || !cfg.RefreshTokenRotation {
		t.Errorf("the row reads %+v, want the two written values", cfg)
	}
	if cfg.IDTokenLifetimeSecs != 900 || !cfg.RequirePKCE {
		t.Errorf("the row reads %+v, want the omitted fields left alone", cfg)
	}
	if cfg.Issuer != "https://auth.acme.com" || cfg.State != providerStateActive {
		t.Errorf("the row reads issuer %q state %d, want them untouched", cfg.Issuer, cfg.State)
	}
	if len(cfg.ResourceIndicators) != 2 || cfg.ResourceIndicators[0] != ResourceAdminAPI {
		t.Errorf("the row carries %v, want the resource identifiers untouched", cfg.ResourceIndicators)
	}
}

// TestUpdateProviderWithNothingToWriteIsNotAnError covers the console sending a
// form nobody changed. An UPDATE with no assignment is not valid SQL, so the
// write must stop before it reaches the database.
func TestUpdateProviderWithNothingToWriteIsNotAnError(t *testing.T) {
	repo, _, ctx := testProviderRepo(t)

	if err := repo.Update(ctx, grantTenantID, ProviderConfigBody{}); err != nil {
		t.Errorf("an empty body reads %v, want no error", err)
	}
}

// TestReadByTenantReadsAnInactiveProvider covers the read behind the provider
// screen. The screen renders the state, so a tenant whose provider is switched
// off must still read its row. The protocol read answers nothing for it, which
// is what stops a request.
func TestReadByTenantReadsAnInactiveProvider(t *testing.T) {
	repo, _, ctx := testProviderRepo(t)
	if _, err := repo.db.ExecContext(ctx,
		`UPDATE oidc_provider_configs SET state = 2 WHERE tenant_id = ?`, grantTenantID); err != nil {
		t.Fatalf("switch the provider off: %v", err)
	}

	cfg, err := repo.ReadByTenant(ctx, grantTenantID)
	if err != nil {
		t.Fatalf("read the inactive provider: %v", err)
	}
	if cfg.State != 2 {
		t.Errorf("the row reads state %d, want the inactive state", cfg.State)
	}

	if _, err := repo.FindByTenant(ctx, grantTenantID); !errors.Is(err, ErrProviderConfigNotFound) {
		t.Errorf("the protocol read answers %v, want ErrProviderConfigNotFound", err)
	}
}

// TestListKeysCarriesTheRetiredKeys covers the read behind the console's key
// page. The published set holds the active and the inactive keys, and the page
// holds the retired ones too: a rotation that happened is what the operator came
// to see.
func TestListKeysCarriesTheRetiredKeys(t *testing.T) {
	_, keys, ctx := testProviderRepo(t)

	rows, err := keys.ListKeys(ctx, grantTenantID)
	if err != nil {
		t.Fatalf("list the keys: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("the tenant reads %d keys, want 3", len(rows))
	}
	if rows[0].ID != "k-active" || rows[2].ID != "k-retired" {
		t.Errorf("the page reads %s first and %s last, want the active key first",
			rows[0].ID, rows[2].ID)
	}
	if rows[0].CreatedAt.IsZero() || rows[0].UpdatedAt.IsZero() {
		t.Errorf("the first key reads %+v, want both moments", rows[0])
	}

	published, err := keys.ListSigningKeys(ctx, grantTenantID)
	if err != nil {
		t.Fatalf("list the published keys: %v", err)
	}
	if len(published) != 2 {
		t.Errorf("the published set holds %d keys, want the active and the inactive one", len(published))
	}
}
