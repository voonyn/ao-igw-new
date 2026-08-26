package application

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	testTenantID   = "11111111-1111-1111-1111-111111111111"
	testOrgID      = "22222222-2222-2222-2222-222222222222"
	testUserID     = "33333333-3333-3333-3333-333333333333"
	otherOrgID     = "44444444-4444-4444-4444-444444444444"
	testProjectID  = "55555555-5555-5555-5555-555555555555"
	otherProjectID = "66666666-6666-6666-6666-666666666666"
	testAppID      = "77777777-7777-7777-7777-777777777777"
	otherAppID     = "88888888-8888-8888-8888-888888888888"
	deadAppID      = "99999999-9999-9999-9999-999999999999"
	testClientID   = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

// seed writes one tenant with two projects in two organizations, and three
// applications: one OIDC with a client, one SAML without, and one soft-deleted.
func seed(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO projects (id, tenant_id, org_id, name, state)
	      VALUES (?, ?, ?, 'Checkout', 1)`, testProjectID, testTenantID, testOrgID)
	exec(`INSERT INTO projects (id, tenant_id, org_id, name, state)
	      VALUES (?, ?, ?, 'Ledger', 1)`, otherProjectID, testTenantID, otherOrgID)

	exec(`INSERT INTO applications (id, tenant_id, project_id, name, app_type, state)
	      VALUES (?, ?, ?, 'Checkout SPA', 1, 1)`, testAppID, testTenantID, testProjectID)
	exec(`INSERT INTO applications (id, tenant_id, project_id, name, app_type, state)
	      VALUES (?, ?, ?, 'Ledger SAML', 2, 1)`, otherAppID, testTenantID, otherProjectID)
	exec(`INSERT INTO applications (id, tenant_id, project_id, name, app_type, state, deleted_at)
	      VALUES (?, ?, ?, 'Closed', 1, 1, NOW(6))`, deadAppID, testTenantID, testProjectID)

	exec(`INSERT INTO application_oidc_configs
	        (app_id, tenant_id, client_id, created_at, token_authn_method, subject_type,
	         scopes, redirect_uris, grant_types, response_types)
	      VALUES (?, ?, ?, NOW(3), 'client_secret_basic', 'public', 'openid profile',
	              '["https://app.example.com/callback"]', '["authorization_code"]', '["code"]')`,
		testAppID, testTenantID, testClientID)
}

func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "application")
	seed(t, bdb)
	return NewRepository(bdb, logger.New()), context.Background()
}

// TestListPagesTheWholeTenant covers the admin list: the soft-deleted row
// excluded, the project joined, the window the pager asks for, the search, and
// the organization filter the console sends.
func TestListPagesTheWholeTenant(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.List(ctx, testTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the applications: %v", err)
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
	if len(page) != 1 || page[0].Name != "Ledger SAML" {
		t.Fatalf("the second page by name reads %+v, want the Ledger application", page)
	}
	if page[0].ProjectName != "Ledger" || page[0].OrgID != otherOrgID {
		t.Errorf("the row reads %+v, want the project and the organization joined", page[0])
	}

	found, _, err := repo.List(ctx, testTenantID, Query{Search: "Checkout", Limit: 20})
	if err != nil {
		t.Fatalf("search the applications: %v", err)
	}
	if len(found) != 1 || found[0].ID != testAppID {
		t.Fatalf("the search reads %+v, want the Checkout application", found)
	}

	mine, _, err := repo.List(ctx, testTenantID, Query{OrgID: otherOrgID, Limit: 20})
	if err != nil {
		t.Fatalf("filter the applications by organization: %v", err)
	}
	if len(mine) != 1 || mine[0].ID != otherAppID {
		t.Fatalf("the filtered page reads %+v, want the application of %s", mine, otherOrgID)
	}
}

// TestConfigsReadsTheClientsOfAPage covers the client read one page makes: the
// application that holds a client, and the one that holds none.
func TestConfigsReadsTheClientsOfAPage(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, err := repo.Configs(ctx, testTenantID, []string{testAppID, otherAppID})
	if err != nil {
		t.Fatalf("read the clients: %v", err)
	}
	if len(rows) != 1 || rows[0].AppID != testAppID || rows[0].ClientID != testClientID {
		t.Fatalf("the read answers %+v, want the one client of %s", rows, testAppID)
	}
	if rows[0].Scopes != "openid profile" || len(rows[0].RedirectURIs) != 1 {
		t.Errorf("the client reads %+v, want the seeded scopes and redirect URI", rows[0])
	}
}

// TestWriteOneApplication covers the writes: the insert of an application and
// its client, the update of both, the secret rotation, and the soft delete that
// takes the client with it.
func TestWriteOneApplication(t *testing.T) {
	repo, ctx := testRepo(t)

	const newAppID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	const newClientID = "cccccccc-cccc-cccc-cccc-cccccccccccc"

	row := Application{
		ID: newAppID, TenantID: testTenantID, ProjectID: testProjectID,
		Name: "Billing API", AppType: TypeAPI, State: StateActive, CreatedAt: time.Now().UTC(),
	}
	if err := repo.Insert(ctx, row); err != nil {
		t.Fatalf("write the application: %v", err)
	}

	cfg := oidc.Client{
		AppID: newAppID, TenantID: testTenantID, ClientID: newClientID, CreatedAt: time.Now().UTC(),
		TokenAuthnMethod: "client_secret_basic", SubjectType: "public", Scopes: "openid",
		RedirectURIs: []string{}, GrantTypes: []string{"client_credentials"}, ResponseTypes: []string{},
	}
	if err := repo.InsertConfig(ctx, cfg); err != nil {
		t.Fatalf("write the client: %v", err)
	}

	row.Name = "Billing Renamed"
	if err := repo.Update(ctx, row); err != nil {
		t.Fatalf("update the application: %v", err)
	}

	cfg.TokenAuthnMethod = "private_key_jwt"
	cfg.ParRequired = true
	cfg.Scopes = "openid profile"
	cfg.RedirectURIs = []string{"https://billing.example.com/callback"}
	if err := repo.UpdateConfig(ctx, cfg); err != nil {
		t.Fatalf("update the client: %v", err)
	}

	if err := repo.SetSecret(ctx, testTenantID, newAppID, "a-bcrypt-hash"); err != nil {
		t.Fatalf("rotate the secret: %v", err)
	}

	read, err := repo.FindByID(ctx, testTenantID, newAppID)
	if err != nil {
		t.Fatalf("read the application: %v", err)
	}
	if read.Name != "Billing Renamed" || read.ProjectName != "Checkout" || read.OrgID != testOrgID {
		t.Errorf("the application reads %+v, want the new name and the joined project", read)
	}

	clients, err := repo.Configs(ctx, testTenantID, []string{newAppID})
	if err != nil {
		t.Fatalf("read the client: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("the read answers %+v, want one client", clients)
	}
	if clients[0].TokenAuthnMethod != "private_key_jwt" || !clients[0].ParRequired {
		t.Errorf("the client reads %+v, want the updated settings", clients[0])
	}
	if clients[0].ClientID != newClientID {
		t.Errorf("the client id reads %q, want %q: an update never writes it", clients[0].ClientID, newClientID)
	}
	if clients[0].Secret != "a-bcrypt-hash" || len(clients[0].RedirectURIs) != 1 {
		t.Errorf("the client reads %+v, want the rotated secret and the new redirect URI", clients[0])
	}

	if err := repo.SoftDelete(ctx, testTenantID, newAppID); err != nil {
		t.Fatalf("delete the application: %v", err)
	}
	if _, err := repo.FindByID(ctx, testTenantID, newAppID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound after the delete", err)
	}
	gone, err := repo.Configs(ctx, testTenantID, []string{newAppID})
	if err != nil {
		t.Fatalf("read the deleted client: %v", err)
	}
	if len(gone) != 0 {
		t.Errorf("the client reads %+v, want it deleted with its application", gone)
	}
	if err := repo.SoftDelete(ctx, testTenantID, newAppID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound on a second delete", err)
	}
}

// TestDeleteOfASAMLApplicationHoldsNoClient covers the delete of an application
// that never had a client. No client row is the normal answer, not a failure.
func TestDeleteOfASAMLApplicationHoldsNoClient(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.SoftDelete(ctx, testTenantID, otherAppID); err != nil {
		t.Fatalf("delete the SAML application: %v", err)
	}
	if _, err := repo.FindByID(ctx, testTenantID, otherAppID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound after the delete", err)
	}
}

// TestFindByIDMisses covers an id nobody holds and the soft-deleted row.
func TestFindByIDMisses(t *testing.T) {
	repo, ctx := testRepo(t)

	if _, err := repo.FindByID(ctx, testTenantID, deadAppID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for a soft-deleted application", err)
	}
	if _, err := repo.FindByID(ctx, "no-such-tenant", testAppID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound for another tenant", err)
	}
}
