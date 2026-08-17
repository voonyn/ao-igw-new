package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	grantTenantID = "11111111-1111-1111-1111-111111111111"
	otherTenantID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	grantAppID    = "22222222-2222-2222-2222-222222222222"
	grantClientID = "the-console-client"
	goneClientID  = "a-client-that-is-gone"

	grantUserID   = "33333333-3333-3333-3333-333333333333"
	grantSessions = "b0000000-0000-0000-0000-000000000001"

	codeGrantID    = "c0000000-0000-0000-0000-000000000001"
	refreshGrantID = "c0000000-0000-0000-0000-000000000002"
	machineGrantID = "c0000000-0000-0000-0000-000000000003"
	foreignGrantID = "c0000000-0000-0000-0000-000000000004"
)

// grantSeedTime is when the seeded grants were issued. A fixed moment keeps the
// order of the page the same on every run.
var grantSeedTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// seedGrants writes one application, one person, and four grants: an
// authorization code, a refresh token of the same sign-in, a client-credentials
// grant, and one of another tenant.
func seedGrants(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO applications (id, tenant_id, project_id, name, app_type)
	      VALUES (?, ?, '00000000-0000-0000-0000-000000000009', 'The Console', 1)`,
		grantAppID, grantTenantID)
	exec(`INSERT INTO application_oidc_configs
	        (app_id, tenant_id, client_id, created_at, redirect_uris, grant_types, response_types)
	      VALUES (?, ?, ?, NOW(3), '[]', '[]', '[]')`, grantAppID, grantTenantID, grantClientID)

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, '44444444-4444-4444-4444-444444444444', 'owner', 1, 1)`,
		grantUserID, grantTenantID)
	exec(`INSERT INTO user_humans (user_id, tenant_id, display_name, email)
	      VALUES (?, ?, 'The Owner', 'owner@acme.com')`, grantUserID, grantTenantID)

	insert := func(id, tenantID, clientID, subject, sessionID, refreshHash string, created time.Time) {
		t.Helper()
		exec(`INSERT INTO oidc_grants
		        (id, tenant_id, client_id, subject, login_session_id, refresh_token_hash,
		         data, expires_at, created_at)
		      VALUES (?, ?, ?, ?, ?, ?, 'sealed', ?, ?)`,
			id, tenantID, clientID, nullable(subject), nullable(sessionID), nullable(refreshHash),
			created.Add(time.Hour), created)
	}

	insert(codeGrantID, grantTenantID, grantClientID, grantUserID, grantSessions, "", grantSeedTime)
	insert(refreshGrantID, grantTenantID, grantClientID, grantUserID, grantSessions, "a-digest",
		grantSeedTime.Add(time.Second))
	insert(machineGrantID, grantTenantID, goneClientID, "", "", "", grantSeedTime.Add(2*time.Second))
	insert(foreignGrantID, otherTenantID, grantClientID, grantUserID, grantSessions, "", grantSeedTime)

	exec(`INSERT INTO oidc_superseded_refresh_tokens
	        (tenant_id, token_hash, grant_id, expires_at)
	      VALUES (?, 'an-old-digest', ?, NOW(3) + INTERVAL 1 DAY)`, grantTenantID, refreshGrantID)
}

// nullable turns an empty value into a NULL, so the seeded column reads the way
// the protocol engine writes it.
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func testGrantRepo(t *testing.T) (*StorageRepository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "oidc")
	seedGrants(t, bdb)
	return NewStorageRepository(bdb, nil, logger.New()), context.Background()
}

// TestListGrants covers the grants page of the console: newest first, the client
// named, the subject named, and the kind of each grant derived.
func TestListGrants(t *testing.T) {
	repo, ctx := testGrantRepo(t)

	rows, total, err := repo.ListGrants(ctx, grantTenantID, GrantQuery{Limit: 20})
	if err != nil {
		t.Fatalf("list the grants: %v", err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("the page holds %d of %d rows, want 3 of 3: %+v", len(rows), total, rows)
	}

	// Newest first, so the client-credentials grant leads.
	if rows[0].ID != machineGrantID || rows[2].ID != codeGrantID {
		t.Fatalf("the page reads %s then %s, want the newest grant first", rows[0].ID, rows[2].ID)
	}

	code := rows[2]
	if code.ClientID != grantClientID || code.AppName != "The Console" {
		t.Errorf("the grant reads %q named %q, want the client and its application",
			code.ClientID, code.AppName)
	}
	if code.Subject != grantUserID || code.SubjectName != "The Owner" {
		t.Errorf("the grant reads subject %q named %q, want the person", code.Subject, code.SubjectName)
	}
	if code.LoginSessionID != grantSessions {
		t.Errorf("the grant names sign-in %q, want %q", code.LoginSessionID, grantSessions)
	}
	if code.HasRefreshToken {
		t.Error("the grant carries a refresh token, want none")
	}
	if !code.CreatedAt.Equal(grantSeedTime) {
		t.Errorf("the grant was issued at %s, want %s", code.CreatedAt, grantSeedTime)
	}

	if !rows[1].HasRefreshToken {
		t.Error("the second grant carries no refresh token, want one")
	}

	// A client-credentials grant names nobody, and its client is gone.
	machine := rows[0]
	if machine.Subject != "" || machine.SubjectName != "" {
		t.Errorf("the machine grant names %q, want nobody", machine.Subject)
	}
	if machine.ClientID != goneClientID || machine.AppName != "" {
		t.Errorf("the machine grant reads %q named %q, want the client id and no name",
			machine.ClientID, machine.AppName)
	}
}

// TestListGrantsNarrowsAndPages covers the subject filter and the window the
// pager asks for.
func TestListGrantsNarrowsAndPages(t *testing.T) {
	repo, ctx := testGrantRepo(t)

	rows, total, err := repo.ListGrants(ctx, grantTenantID, GrantQuery{UserID: grantUserID, Limit: 20})
	if err != nil {
		t.Fatalf("list the grants of one person: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Fatalf("the grants of one person read %+v, want two", rows)
	}

	rows, total, err = repo.ListGrants(ctx, grantTenantID, GrantQuery{Sort: "expires", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("list the second page: %v", err)
	}
	if total != 3 {
		t.Errorf("the total reads %d, want 3 on every page", total)
	}
	// Oldest deadline first, so the second page holds the refresh grant.
	if len(rows) != 1 || rows[0].ID != refreshGrantID {
		t.Fatalf("the second page by expiry reads %+v, want the refresh grant", rows)
	}
}

// TestDeleteGrantsByLoginSession covers what an administrative revoke of one
// session takes: every grant of that sign-in, and the superseded digests that
// belonged to them.
func TestDeleteGrantsByLoginSession(t *testing.T) {
	repo, ctx := testGrantRepo(t)

	count, err := repo.DeleteGrantsByLoginSession(ctx, grantTenantID, grantSessions)
	if err != nil {
		t.Fatalf("revoke the grants of one sign-in: %v", err)
	}
	if count != 2 {
		t.Errorf("the revoke ended %d grants, want 2", count)
	}

	rows, _, err := repo.ListGrants(ctx, grantTenantID, GrantQuery{Limit: 20})
	if err != nil {
		t.Fatalf("list the grants: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != machineGrantID {
		t.Fatalf("the tenant reads %+v, want only the client-credentials grant", rows)
	}

	left, err := repo.db.NewSelect().Model((*SupersededRefreshToken)(nil)).
		Where("tenant_id = ?", grantTenantID).Count(ctx)
	if err != nil {
		t.Fatalf("count the superseded digests: %v", err)
	}
	if left != 0 {
		t.Errorf("%d superseded digests survived the revoke, want none", left)
	}

	// An empty session id names no sign-in, and must not read every grant of
	// the tenant.
	count, err = repo.DeleteGrantsByLoginSession(ctx, grantTenantID, "")
	if err != nil || count != 0 {
		t.Errorf("an empty sign-in ended %d grants with %v, want none and no error", count, err)
	}
}

// TestDeleteGrantsBySubject covers the force-logout half: every grant the person
// holds goes, whatever sign-in produced it, so no refresh token survives.
func TestDeleteGrantsBySubject(t *testing.T) {
	repo, ctx := testGrantRepo(t)

	count, err := repo.DeleteGrantsBySubject(ctx, grantTenantID, grantUserID)
	if err != nil {
		t.Fatalf("revoke the grants of one person: %v", err)
	}
	if count != 2 {
		t.Errorf("the force-logout ended %d grants, want 2", count)
	}

	// A person with nothing left is not an error.
	count, err = repo.DeleteGrantsBySubject(ctx, grantTenantID, grantUserID)
	if err != nil || count != 0 {
		t.Errorf("a second force-logout ended %d grants with %v, want none and no error", count, err)
	}

	// An empty subject names nobody, and must not read every grant of the
	// tenant.
	count, err = repo.DeleteGrantsBySubject(ctx, grantTenantID, "")
	if err != nil || count != 0 {
		t.Errorf("an empty subject ended %d grants with %v, want none and no error", count, err)
	}
}
