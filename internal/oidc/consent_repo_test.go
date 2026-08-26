package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	consentAppID     = "55555555-5555-5555-5555-555555555555"
	consentClientID  = "the-portal-client"
	dormantClientID  = "a-client-that-is-dormant"
	undatedClientID  = "a-client-with-an-undated-grant"
	consentUserID    = "66666666-6666-6666-6666-666666666666"
	consentOtherUser = "77777777-7777-7777-7777-777777777777"
)

// consentSeedTime is when the seeded consents were given. A fixed moment keeps
// the order of the answer the same on every run.
var consentSeedTime = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

// seedConsents writes one application, five consents, and four grants. The
// consents cover three shapes of connection, plus the consent of another person
// and the consent of another tenant.
func seedConsents(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO applications (id, tenant_id, project_id, name, app_type)
	      VALUES (?, ?, '00000000-0000-0000-0000-000000000009', 'The Portal', 1)`,
		consentAppID, grantTenantID)
	exec(`INSERT INTO application_oidc_configs
	        (app_id, tenant_id, client_id, created_at, redirect_uris, grant_types, response_types)
	      VALUES (?, ?, ?, NOW(3), '[]', '[]', '[]')`, consentAppID, grantTenantID, consentClientID)

	consent := func(id, tenantID, userID, clientID, scopes string, created time.Time) {
		t.Helper()
		exec(`INSERT INTO oidc_user_consents
		        (id, tenant_id, user_id, client_id, scopes, created_at, updated_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, tenantID, userID, clientID, scopes, created, created)
	}

	consent("d0000000-0000-0000-0000-000000000001", grantTenantID, consentUserID,
		consentClientID, "openid profile", consentSeedTime)
	consent("d0000000-0000-0000-0000-000000000002", grantTenantID, consentUserID,
		goneClientID, "openid", consentSeedTime.Add(-time.Hour))
	consent("d0000000-0000-0000-0000-000000000003", grantTenantID, consentUserID,
		dormantClientID, "openid email", consentSeedTime.Add(-2*time.Hour))
	consent("d0000000-0000-0000-0000-000000000006", grantTenantID, consentUserID,
		undatedClientID, "openid", consentSeedTime.Add(-3*time.Hour))
	consent("d0000000-0000-0000-0000-000000000004", grantTenantID, consentOtherUser,
		consentClientID, "openid", consentSeedTime)
	consent("d0000000-0000-0000-0000-000000000005", otherTenantID, consentUserID,
		consentClientID, "openid", consentSeedTime)

	grant := func(id, tenantID, clientID, subject string, expires time.Time) {
		t.Helper()
		exec(`INSERT INTO oidc_grants
		        (id, tenant_id, client_id, subject, data, expires_at, created_at)
		      VALUES (?, ?, ?, ?, 'sealed', ?, NOW(3))`,
			id, tenantID, clientID, subject, expires)
	}

	// One live grant of the person, and one that expired. The dormant client
	// therefore proves the expiry predicate of the read.
	grant("e0000000-0000-0000-0000-000000000001", grantTenantID, consentClientID,
		consentUserID, time.Now().Add(time.Hour))
	grant("e0000000-0000-0000-0000-000000000002", grantTenantID, dormantClientID,
		consentUserID, consentSeedTime)

	// A grant with no expiry at all. The column holds the refresh token expiry,
	// so a NULL says that no deadline passed, and the connection reads live.
	exec(`INSERT INTO oidc_grants
	        (id, tenant_id, client_id, subject, data, expires_at, created_at)
	      VALUES (?, ?, ?, ?, 'sealed', NULL, NOW(3))`,
		"e0000000-0000-0000-0000-000000000005", grantTenantID, undatedClientID, consentUserID)

	// A live grant of another person, and one of another tenant. Neither may
	// make a connection of this person read live.
	grant("e0000000-0000-0000-0000-000000000003", grantTenantID, goneClientID,
		consentOtherUser, time.Now().Add(time.Hour))
	grant("e0000000-0000-0000-0000-000000000004", otherTenantID, goneClientID,
		consentUserID, time.Now().Add(time.Hour))
}

func testConsentRepo(t *testing.T) (*ConsentRepository, *StorageRepository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "oidc_consent")
	seedGrants(t, bdb)
	seedConsents(t, bdb)
	log := logger.New()
	return NewConsentRepository(bdb, log), NewStorageRepository(bdb, nil, log), context.Background()
}

// TestListBySubject covers the connected applications page: the consents of the
// caller alone, the application named, a client that is gone still listed, and
// the live grant reported per connection.
func TestListBySubject(t *testing.T) {
	repo, _, ctx := testConsentRepo(t)

	rows, err := repo.ListBySubject(ctx, grantTenantID, consentUserID)
	if err != nil {
		t.Fatalf("list the connections of one person: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("the list reads %+v, want the four connections of this person", rows)
	}

	// Newest first, so the live application leads.
	live := rows[0]
	if live.ClientID != consentClientID || live.AppName != "The Portal" {
		t.Errorf("the connection reads %q named %q, want the client and its application",
			live.ClientID, live.AppName)
	}
	if live.Scopes != "openid profile" {
		t.Errorf("the connection allows %q, want %q", live.Scopes, "openid profile")
	}
	if !live.HasGrant {
		t.Error("the connection holds no live grant, want one")
	}
	if !live.CreatedAt.Equal(consentSeedTime) || !live.UpdatedAt.Equal(consentSeedTime) {
		t.Errorf("the connection was made at %s and changed at %s, want %s",
			live.CreatedAt, live.UpdatedAt, consentSeedTime)
	}

	// An application whose record is gone still lists, named by its client
	// identifier. Another person holds a live grant of it, and that grant must
	// not make this connection read live.
	gone := rows[1]
	if gone.ClientID != goneClientID || gone.AppName != "" {
		t.Errorf("the gone connection reads %q named %q, want the client id and no name",
			gone.ClientID, gone.AppName)
	}
	if gone.HasGrant {
		t.Error("the gone connection reads a live grant, want none: it belongs to another person")
	}

	// The only grant of this client expired, so the connection is dormant.
	if dormant := rows[2]; dormant.ClientID != dormantClientID || dormant.HasGrant {
		t.Errorf("the dormant connection reads %q with a live grant of %v, want %q and none",
			dormant.ClientID, dormant.HasGrant, dormantClientID)
	}

	// The grant of this client carries no expiry, so no deadline passed and the
	// connection reads live.
	if undated := rows[3]; undated.ClientID != undatedClientID || !undated.HasGrant {
		t.Errorf("the undated connection reads %q with a live grant of %v, want %q and one",
			undated.ClientID, undated.HasGrant, undatedClientID)
	}
}

// TestListBySubjectNarrows proves the tenant predicate and the subject predicate:
// no consent of another person and none of another tenant is reachable.
func TestListBySubjectNarrows(t *testing.T) {
	repo, _, ctx := testConsentRepo(t)

	rows, err := repo.ListBySubject(ctx, grantTenantID, consentOtherUser)
	if err != nil {
		t.Fatalf("list the connections of the other person: %v", err)
	}
	if len(rows) != 1 || rows[0].ClientID != consentClientID {
		t.Fatalf("the other person reads %+v, want their one connection", rows)
	}

	rows, err = repo.ListBySubject(ctx, otherTenantID, consentUserID)
	if err != nil {
		t.Fatalf("list the connections in the other tenant: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("the other tenant reads %+v, want the one consent of that tenant", rows)
	}

	// An empty subject must read nothing, and never every consent of the tenant.
	rows, err = repo.ListBySubject(ctx, grantTenantID, "")
	if err != nil || len(rows) != 0 {
		t.Errorf("an empty subject read %+v with %v, want nothing and no error", rows, err)
	}
}

// TestDeleteForSubject covers the withdraw half of a disconnect: the consent is
// soft deleted, it leaves the list, and the same person consents to the same
// client again without colliding with the withdrawn row.
func TestDeleteForSubject(t *testing.T) {
	repo, _, ctx := testConsentRepo(t)

	if err := repo.DeleteForSubject(ctx, grantTenantID, consentUserID, consentClientID); err != nil {
		t.Fatalf("withdraw the consent: %v", err)
	}

	rows, err := repo.ListBySubject(ctx, grantTenantID, consentUserID)
	if err != nil {
		t.Fatalf("list the connections after the withdraw: %v", err)
	}
	if len(rows) != 3 || rows[0].ClientID != goneClientID {
		t.Fatalf("the list reads %+v, want the withdrawn connection gone", rows)
	}

	// The unique key is functional over deleted_at, so a re-consent inserts a
	// new live row instead of colliding with the withdrawn one.
	if err := repo.Save(ctx, grantTenantID, consentUserID, consentClientID, []string{"openid"}); err != nil {
		t.Fatalf("consent to the same client again: %v", err)
	}
	rows, err = repo.ListBySubject(ctx, grantTenantID, consentUserID)
	if err != nil {
		t.Fatalf("list the connections after the re-consent: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("the list reads %+v, want the connection back", rows)
	}

	// The consent of the other tenant is a separate row, and withdrawing it
	// leaves the connection of the other person untouched.
	if err := repo.DeleteForSubject(ctx, otherTenantID, consentUserID, consentClientID); err != nil {
		t.Errorf("withdraw the consent of the other tenant: %v", err)
	}
	other, err := repo.ListBySubject(ctx, grantTenantID, consentOtherUser)
	if err != nil || len(other) != 1 {
		t.Errorf("the other person reads %+v with %v, want their connection untouched", other, err)
	}
}

// TestDeleteForSubjectRefuses proves that a person cannot withdraw on behalf of
// anybody else. A consent of another person and a client nobody connected read
// alike, so the answer never says which applications another person connected.
func TestDeleteForSubjectRefuses(t *testing.T) {
	repo, _, ctx := testConsentRepo(t)

	cases := map[string][3]string{
		// The other person asking for a client only the caller connected. The
		// pair exists in the table under a different owner, so the refusal is
		// the subject predicate and not an absent row.
		"another person":  {grantTenantID, consentOtherUser, dormantClientID},
		"another tenant":  {otherTenantID, consentUserID, dormantClientID},
		"no such client":  {grantTenantID, consentUserID, "a-client-nobody-connected"},
		"an empty person": {grantTenantID, "", consentClientID},
	}
	for name, args := range cases {
		if err := repo.DeleteForSubject(ctx, args[0], args[1], args[2]); !errors.Is(err, ErrConsentNotFound) {
			t.Errorf("withdrawing on behalf of %s answered %v, want ErrConsentNotFound", name, err)
		}
	}
}

// TestDeleteGrantsBySubjectClient covers the grant half of a disconnect: the
// grants of that person for that client go, and nothing else does.
func TestDeleteGrantsBySubjectClient(t *testing.T) {
	_, storage, ctx := testConsentRepo(t)

	count, err := storage.DeleteGrantsBySubjectClient(ctx, grantTenantID, consentUserID, consentClientID)
	if err != nil {
		t.Fatalf("delete the grants of one connection: %v", err)
	}
	if count != 1 {
		t.Errorf("the disconnect deleted %d grants, want 1", count)
	}

	// The grants of the other person and of the other tenant survive, and so do
	// the grants seeded for the other person of this tenant.
	left, _, err := storage.ListGrants(ctx, grantTenantID, GrantQuery{Limit: 20})
	if err != nil {
		t.Fatalf("list the grants: %v", err)
	}
	if len(left) != 6 {
		t.Fatalf("the tenant reads %d grants, want the other six untouched", len(left))
	}

	// The other tenant, the other person, and an empty argument each reach
	// nothing.
	for name, args := range map[string][3]string{
		"another tenant": {otherTenantID, consentUserID, dormantClientID},
		"another person": {grantTenantID, consentOtherUser, dormantClientID},
		"no subject":     {grantTenantID, "", consentClientID},
		"no client":      {grantTenantID, consentUserID, ""},
	} {
		count, err := storage.DeleteGrantsBySubjectClient(ctx, args[0], args[1], args[2])
		if err != nil || count != 0 {
			t.Errorf("the disconnect of %s deleted %d grants with %v, want none and no error",
				name, count, err)
		}
	}
}
