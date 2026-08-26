package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest/observer"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/project"
	"alphaomega/identitygateway/internal/tenant"
)

// admin is the person every service test acts as.
var admin = Actor{TenantID: testTenantID, UserID: testUserID, IP: "203.0.113.7", UserAgent: "a-browser"}

// oidcBody is the nine-field OIDC body a create and an update carry.
func oidcBody() *OidcBody {
	return &OidcBody{
		ClientID:         testClientID,
		TokenAuthnMethod: "client_secret_basic",
		SubjectType:      "public",
		ParRequired:      true,
		RedirectUris:     []string{"https://app.example.com/callback"},
		PostLogoutUris:   []string{"https://app.example.com/signed-out"},
		GrantTypes:       []string{"authorization_code", "refresh_token"},
		ResponseTypes:    []string{"code"},
		ScopeIDs:         []string{"openid", "profile"},
	}
}

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

// TestListReadsTheWholeTenant reads the page a tenant manager reads, with the
// project of each application and the client of the one that holds one.
func TestListReadsTheWholeTenant(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Application{
			{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID, ProjectName: "Checkout",
				OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC, State: StateActive},
			{ID: otherAppID, TenantID: testTenantID, ProjectID: otherProjectID, ProjectName: "Ledger",
				OrgID: otherOrgID, Name: "Ledger SAML", AppType: TypeSAML, State: StateInactive},
		},
		configs: []oidc.Client{{
			AppID: testAppID, TenantID: testTenantID, ClientID: testClientID,
			TokenAuthnMethod: "client_secret_basic", Secret: "a-bcrypt-hash",
			Scopes: "openid profile", RedirectURIs: []string{"https://app.example.com/callback"},
		}},
	})

	views, total, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(views) != 2 {
		t.Fatalf("the page holds %d of %d rows, want 2 of 2", len(views), total)
	}
	if views[0].ProjectName != "Checkout" || views[0].OrgID != testOrgID {
		t.Errorf("the first view reads %+v, want the project and the organization joined", views[0])
	}
	if views[0].OIDC == nil {
		t.Fatalf("the first view carries no client, want the client of %s", testAppID)
	}
	if views[0].OIDC.ClientID != testClientID || !views[0].OIDC.SecretSet {
		t.Errorf("the client reads %+v, want %s with a secret set", views[0].OIDC, testClientID)
	}
	if len(views[0].OIDC.ScopeIDs) != 2 || views[0].OIDC.ScopeIDs[0] != "openid" {
		t.Errorf("the scopes read %v, want the two stored names", views[0].OIDC.ScopeIDs)
	}
	if views[1].OIDC != nil {
		t.Errorf("the SAML application carries %+v, want no client", views[1].OIDC)
	}
}

// TestViewNeverCarriesTheStoredSecret proves the bcrypt hash stays in the
// database. The console reads whether a secret is set, never the value.
func TestViewNeverCarriesTheStoredSecret(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMAdmin},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC, State: StateActive}},
		configs: []oidc.Client{{AppID: testAppID, TenantID: testTenantID, ClientID: testClientID,
			Secret: "a-bcrypt-hash"}},
	})

	view, err := svc.Find(context.Background(), admin, testAppID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", view), "a-bcrypt-hash") {
		t.Fatalf("the view reads %+v, want no stored secret in it", view)
	}
}

// TestFindReportsAMiss answers ErrNotFound for an id nobody holds.
func TestFindReportsAMiss(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	_, err := svc.Find(context.Background(), admin, deadAppID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestCreateWritesTheApplicationAndItsClient creates one OIDC application. The
// application row and the client row land on one transaction, with one event.
func TestCreateWritesTheApplicationAndItsClient(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	view, err := svc.Create(context.Background(), admin, CreateBody{
		ProjectID: testProjectID,
		Name:      "Checkout SPA",
		AppType:   TypeOIDC,
		OIDC:      oidcBody(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.ID == "" || view.State != StateActive || view.OrgID != testOrgID {
		t.Errorf("the view reads %+v, want a new active application of %s", view, testOrgID)
	}
	if len(written) != 1 || written[0].Name != "Checkout SPA" || written[0].TenantID != testTenantID {
		t.Fatalf("the write wrote %+v, want one application", written)
	}
	if len(writtenConfigs) != 1 {
		t.Fatalf("the write wrote %+v, want one client", writtenConfigs)
	}
	cfg := writtenConfigs[0]
	if cfg.AppID != written[0].ID || cfg.ClientID != testClientID || cfg.TokenAuthnMethod != "client_secret_basic" {
		t.Errorf("the client reads %+v, want the client of the body", cfg)
	}
	if cfg.Scopes != "openid profile" || !cfg.ParRequired || len(cfg.RedirectURIs) != 1 {
		t.Errorf("the client reads %+v, want the nine fields of the body", cfg)
	}
	if cfg.Secret != "" {
		t.Errorf("the create stored a secret, want none until a rotation")
	}
	wantOneEvent(t, audit.ActionAppCreated, view.ID)
}

// TestCreateMintsAClientIDWhenTheBodyOmitsIt covers the optional clientId. A
// client without an id cannot be reached, so the service mints one.
func TestCreateMintsAClientIDWhenTheBodyOmitsIt(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	body := oidcBody()
	body.ClientID = ""
	view, err := svc.Create(context.Background(), admin, CreateBody{
		ProjectID: testProjectID, Name: "Checkout SPA", AppType: TypeOIDC, OIDC: body,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.OIDC == nil || view.OIDC.ClientID == "" {
		t.Fatalf("the view reads %+v, want a minted client id", view.OIDC)
	}
	if writtenConfigs[0].ClientID != view.OIDC.ClientID {
		t.Errorf("the row holds %q and the view reads %q, want one client id",
			writtenConfigs[0].ClientID, view.OIDC.ClientID)
	}
}

// TestCreateOfASAMLApplicationWritesNoClient covers the one application type
// that holds no OIDC client.
func TestCreateOfASAMLApplicationWritesNoClient(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	view, err := svc.Create(context.Background(), admin, CreateBody{
		ProjectID: testProjectID, Name: "Ledger SAML", AppType: TypeSAML,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.OIDC != nil {
		t.Errorf("the view carries %+v, want no client", view.OIDC)
	}
	if len(writtenConfigs) != 0 {
		t.Errorf("the write wrote %+v, want no client row", writtenConfigs)
	}
}

// TestCreateRefusesAnotherOrganization refuses an ORG_OWNER who names a project
// of an organization it does not own. The project decides the organization the
// gate reads, so the project is read before the gate.
func TestCreateRefusesAnotherOrganization(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	_, err := svc.Create(context.Background(), admin, CreateBody{
		ProjectID: otherProjectID, Name: "Ledger", AppType: TypeOIDC, OIDC: oidcBody(),
	})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(written) != 0 || len(writtenConfigs) != 0 {
		t.Errorf("a refused create wrote %+v and %+v", written, writtenConfigs)
	}
}

// TestUpdateWritesTheNameAndTheClient renames one application and writes the
// nine client fields, as one transaction with one event.
func TestUpdateWritesTheNameAndTheClient(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC, State: StateActive}},
		configs: []oidc.Client{{AppID: testAppID, TenantID: testTenantID, ClientID: testClientID,
			TokenAuthnMethod: "none", Secret: "a-bcrypt-hash"}},
	})

	body := oidcBody()
	body.TokenAuthnMethod = "client_secret_post"
	view, err := svc.Update(context.Background(), admin, testAppID, UpdateBody{
		Name: "Checkout Renamed", OIDC: body,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if view.Name != "Checkout Renamed" || view.OIDC.AuthnMethod != "client_secret_post" {
		t.Errorf("the view reads %+v, want the new name and the new authn method", view)
	}
	if len(updated) != 1 || updated[0].Name != "Checkout Renamed" {
		t.Fatalf("the write wrote %+v, want one update of %s", updated, testAppID)
	}
	if len(updatedConfigs) != 1 || updatedConfigs[0].TokenAuthnMethod != "client_secret_post" {
		t.Fatalf("the write wrote %+v, want one client update", updatedConfigs)
	}
	if updatedConfigs[0].Secret != "" {
		t.Errorf("the update wrote a secret, want the stored one untouched")
	}
	wantOneEvent(t, audit.ActionAppUpdated, testAppID)
}

// TestUpdateRefusesAUserManager refuses an ORG_USER_MANAGER of the same
// organization. That role administers people, not the applications of the
// organization.
func TestUpdateRefusesAUserManager(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC}},
	})

	_, err := svc.Update(context.Background(), admin, testAppID, UpdateBody{Name: "Taken", OIDC: oidcBody()})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(updated) != 0 {
		t.Errorf("a refused update wrote %+v", updated)
	}
}

// TestDeleteRemovesTheApplicationAndItsClient soft deletes both rows and
// records one event. A client that outlived its application would still mint
// tokens.
func TestDeleteRemovesTheApplicationAndItsClient(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC}},
	})

	if err := svc.Delete(context.Background(), admin, testAppID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != testAppID {
		t.Fatalf("the write deleted %v, want %s", deleted, testAppID)
	}
	wantOneEvent(t, audit.ActionAppDeleted, testAppID)
}

// TestDeleteRollsBackAFailedAuditWrite proves the change and the trail land
// together. A change nobody can audit is not allowed to stand.
func TestDeleteRollsBackAFailedAuditWrite(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC}},
		auditFails: true,
	})

	if err := svc.Delete(context.Background(), admin, testAppID); err == nil {
		t.Fatal("Delete answered no error, want the failed audit write")
	}
	if !rolledBack {
		t.Error("the transaction must roll the delete back")
	}
}

// TestRotateSecretAnswersTheSecretOnceAndStoresAHash is the whole rotation
// rule: the answer carries the secret, the row carries a bcrypt hash of it, and
// no log line carries either.
func TestRotateSecretAnswersTheSecretOnceAndStoresAHash(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC}},
		configs: []oidc.Client{{AppID: testAppID, TenantID: testTenantID, ClientID: testClientID,
			TokenAuthnMethod: "client_secret_basic"}},
	})

	got, err := svc.RotateSecret(context.Background(), admin, testAppID)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if got.ClientID != testClientID || got.Secret == "" {
		t.Fatalf("the answer reads %+v, want the client id and one new secret", got)
	}
	if len(secrets) != 1 {
		t.Fatalf("the write wrote %v, want one secret", secrets)
	}
	if secrets[0] == got.Secret {
		t.Fatal("the row stores the secret itself, want a bcrypt hash of it")
	}
	if err := crypto.VerifyPassword(secrets[0], got.Secret); err != nil {
		t.Fatalf("the stored hash does not verify the answered secret: %v", err)
	}
	wantNoSecretInTheLog(t, got.Secret)
	wantOneEvent(t, audit.ActionAppSecretRotated, testAppID)
}

// TestRotateSecretRefusesAnApplicationWithoutAClient covers a SAML application.
// It holds no client, so it holds no secret to rotate.
func TestRotateSecretRefusesAnApplicationWithoutAClient(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Ledger SAML", AppType: TypeSAML}},
	})

	if _, err := svc.RotateSecret(context.Background(), admin, testAppID); !errors.Is(err, ErrNoClient) {
		t.Fatalf("err = %v, want ErrNoClient", err)
	}
	if len(secrets) != 0 {
		t.Errorf("a refused rotation wrote %v", secrets)
	}
}

// TestRotateSecretRefusesAPublicClient covers a client that authenticates with
// PKCE alone. A secret it never presents is a secret nobody can use.
func TestRotateSecretRefusesAPublicClient(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []Application{{ID: testAppID, TenantID: testTenantID, ProjectID: testProjectID,
			OrgID: testOrgID, Name: "Checkout SPA", AppType: TypeOIDC}},
		configs: []oidc.Client{{AppID: testAppID, TenantID: testTenantID, ClientID: testClientID,
			TokenAuthnMethod: "none"}},
	})

	if _, err := svc.RotateSecret(context.Background(), admin, testAppID); !errors.Is(err, ErrPublicClient) {
		t.Fatalf("err = %v, want ErrPublicClient", err)
	}
}

// wantNoSecretInTheLog reads every line the service logged, at every level, and
// fails if the secret reached one of them.
func wantNoSecretInTheLog(t *testing.T, secret string) {
	t.Helper()

	for _, entry := range logs.All() {
		line := entry.Message + fmt.Sprint(entry.ContextMap())
		if strings.Contains(line, secret) {
			t.Fatalf("the log line %q carries the new secret", line)
		}
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
	if got.EntityType != audit.EntityApplication || got.EntityID != entityID {
		t.Errorf("the event names %s %s, want %s %s",
			got.EntityType, got.EntityID, audit.EntityApplication, entityID)
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
	rows        []Application
	configs     []oidc.Client
	auditFails  bool
}

// What the writes of one test did. testService clears them, and the tests of
// one package run one after another, so each test reads its own writes.
var (
	written        []Application
	writtenConfigs []oidc.Client
	updated        []Application
	updatedConfigs []oidc.Client
	deleted        []string
	secrets        []string
	events         []audit.Event
	rolledBack     bool
	logs           *observer.ObservedLogs
)

func testService(t *testing.T, d deps) *Service {
	t.Helper()
	var log logger.Logger
	log, logs = logger.NewObserved()
	written, writtenConfigs, updated, updatedConfigs = nil, nil, nil, nil
	deleted, secrets, events, rolledBack = nil, nil, nil, false

	record := func(_ context.Context, e audit.Event) error {
		if d.auditFails {
			return errors.New("the audit write failed")
		}
		events = append(events, e)
		return nil
	}
	countWrites := func() int {
		return len(written) + len(writtenConfigs) + len(updated) +
			len(updatedConfigs) + len(deleted) + len(secrets)
	}

	return NewService(Deps{
		Insert: func(_ context.Context, row Application) error {
			written = append(written, row)
			return nil
		},
		InsertConfig: func(_ context.Context, row oidc.Client) error {
			writtenConfigs = append(writtenConfigs, row)
			return nil
		},
		Update: func(_ context.Context, row Application) error {
			updated = append(updated, row)
			return nil
		},
		UpdateConfig: func(_ context.Context, row oidc.Client) error {
			updatedConfigs = append(updatedConfigs, row)
			return nil
		},
		Delete: func(_ context.Context, _, appID string) error {
			deleted = append(deleted, appID)
			return nil
		},
		SetSecret: func(_ context.Context, _, _, hash string) error {
			secrets = append(secrets, hash)
			return nil
		},
		// The unit of work either commits whole or leaves nothing behind, so a
		// failed step clears what the earlier steps wrote.
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			before := countWrites()
			err := fn(ctx)
			if err != nil && countWrites() != before {
				written, writtenConfigs, updated, updatedConfigs = nil, nil, nil, nil
				deleted, secrets, rolledBack = nil, nil, true
			}
			return err
		},
		Audit: audit.NewRecorder(record, log),
		List: func(context.Context, string, Query) ([]Application, int64, error) {
			return d.rows, int64(len(d.rows)), nil
		},
		Find: func(_ context.Context, _, appID string) (Application, error) {
			for _, row := range d.rows {
				if row.ID == appID {
					return row, nil
				}
			}
			return Application{}, ErrNotFound
		},
		Configs: func(_ context.Context, _ string, appIDs []string) ([]oidc.Client, error) {
			var out []oidc.Client
			for _, row := range d.configs {
				for _, id := range appIDs {
					if row.AppID == id {
						out = append(out, row)
					}
				}
			}
			return out, nil
		},
		Project: func(_ context.Context, _, projectID string) (project.Project, error) {
			switch projectID {
			case testProjectID:
				return project.Project{ID: testProjectID, TenantID: testTenantID, OrgID: testOrgID}, nil
			case otherProjectID:
				return project.Project{ID: otherProjectID, TenantID: testTenantID, OrgID: otherOrgID}, nil
			}
			return project.Project{}, project.ErrNotFound
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
