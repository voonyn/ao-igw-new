package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	adminTenantID = "11111111-1111-1111-1111-111111111111"
	otherTenantID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	adminOrgID = "22222222-2222-2222-2222-222222222222"
	otherOrgID = "44444444-4444-4444-4444-444444444444"

	ownerUserID  = "33333333-3333-3333-3333-333333333333"
	secondUserID = "66666666-6666-6666-6666-666666666666"

	liveSessionID       = "b0000000-0000-0000-0000-000000000001"
	terminatedSessionID = "b0000000-0000-0000-0000-000000000002"
	brokenSessionID     = "b0000000-0000-0000-0000-000000000003"
	foreignSessionID    = "b0000000-0000-0000-0000-000000000004"
)

// seedTime is when the seeded sessions began. A fixed moment keeps the order of
// the page the same on every run.
var seedTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// adminSession is one seeded login session, sealed the way the login steps seal
// one.
func adminSession(id, userID string, created time.Time) LoginSession {
	return LoginSession{
		ID:        id,
		TenantID:  adminTenantID,
		UserID:    userID,
		Email:     "person@example.com",
		IP:        "203.0.113.7",
		UserAgent: "a-browser",
		Factors:   map[string]time.Time{FactorPassword: created},
		CreatedAt: created,
		ExpiresAt: created.Add(12 * time.Hour),
	}
}

// seedAdmin writes two people and four login sessions: one live, one
// terminated, one whose seal cannot be opened, and one of another tenant.
func seedAdmin(t *testing.T, bdb *bun.DB, cipher *aocrypto.Cipher) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'owner', 1, 1)`, ownerUserID, adminTenantID, adminOrgID)
	exec(`INSERT INTO user_humans (user_id, tenant_id, display_name, email)
	      VALUES (?, ?, 'The Owner', 'owner@acme.com')`, ownerUserID, adminTenantID)
	exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
	      VALUES (?, ?, ?, 'second', 1, 1)`, secondUserID, adminTenantID, otherOrgID)

	insert := func(row Row, created time.Time) {
		t.Helper()
		exec(`INSERT INTO login_sessions
		        (id, tenant_id, user_id, state, token_hash, data, expires_at, created_at)
		      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			row.ID, row.TenantID, row.UserID, row.State, row.TokenHash, row.Data,
			row.ExpiresAt, created)
	}

	live, err := seal(adminSession(liveSessionID, ownerUserID, seedTime), "digest-live", cipher)
	if err != nil {
		t.Fatalf("seal the live session: %v", err)
	}
	insert(live, seedTime)

	ended, err := seal(adminSession(terminatedSessionID, secondUserID, seedTime.Add(time.Second)),
		"digest-ended", cipher)
	if err != nil {
		t.Fatalf("seal the terminated session: %v", err)
	}
	ended.State = StateTerminated
	insert(ended, seedTime.Add(time.Second))

	// A row nothing can open. The page must still carry it, because an operator
	// investigating an account needs to see that the session exists.
	broken := Row{
		ID: brokenSessionID, TenantID: adminTenantID, UserID: ownerUserID,
		State: StateActive, TokenHash: "digest-broken", Data: []byte("not a sealed session"),
		ExpiresAt: seedTime.Add(12 * time.Hour),
	}
	insert(broken, seedTime.Add(2*time.Second))

	foreign, err := seal(LoginSession{
		ID: foreignSessionID, TenantID: otherTenantID, UserID: ownerUserID,
		CreatedAt: seedTime, ExpiresAt: seedTime.Add(12 * time.Hour),
	}, "digest-foreign", cipher)
	if err != nil {
		t.Fatalf("seal the foreign session: %v", err)
	}
	insert(foreign, seedTime)

	exec(`INSERT INTO login_session_links
	        (tenant_id, login_session_id, protocol, protocol_ref, client_id)
	      VALUES (?, ?, 1, 'authn-1', 'client-1')`, adminTenantID, liveSessionID)
	exec(`INSERT INTO login_session_links
	        (tenant_id, login_session_id, protocol, protocol_ref, client_id)
	      VALUES (?, ?, 1, 'authn-2', 'client-2')`, adminTenantID, liveSessionID)
}

func testAdminRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "session")
	cipher := testCipher(t)
	seedAdmin(t, bdb, cipher)
	return NewRepository(bdb, cipher, logger.New()), context.Background()
}

// TestListSessions covers the sessions page of the console: newest first, the
// person named, the organization joined, and the protocol links counted.
func TestListSessions(t *testing.T) {
	repo, ctx := testAdminRepo(t)

	rows, total, err := repo.ListSessions(ctx, adminTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the login sessions: %v", err)
	}
	if total != 3 || len(rows) != 3 {
		t.Fatalf("the page holds %d of %d rows, want 3 of 3: %+v", len(rows), total, rows)
	}

	// Newest first, so the broken row leads and the live one closes the page.
	if rows[0].ID != brokenSessionID || rows[2].ID != liveSessionID {
		t.Fatalf("the page reads %s then %s, want the newest session first",
			rows[0].ID, rows[2].ID)
	}

	live := rows[2]
	if live.UserName != "The Owner" || live.OrgID != adminOrgID {
		t.Errorf("the live session reads %q in %q, want the display name and the organization",
			live.UserName, live.OrgID)
	}
	if live.IP != "203.0.113.7" || live.UserAgent != "a-browser" {
		t.Errorf("the live session reads %q and %q, want the sealed address and agent",
			live.IP, live.UserAgent)
	}
	if _, ok := live.Factors[FactorPassword]; !ok {
		t.Errorf("the live session carries %v, want the password factor", live.Factors)
	}
	if len(live.Links) != 2 {
		t.Errorf("the live session carries %d protocol links, want 2", len(live.Links))
	}
	if live.Links[0].AppID != "client-1" || live.Links[0].Ref != "authn-1" {
		t.Errorf("the first link reads %+v, want the seeded flow", live.Links[0])
	}
	if !live.CreatedAt.Equal(seedTime) || !live.ExpiresAt.Equal(seedTime.Add(12*time.Hour)) {
		t.Errorf("the live session runs %s to %s, want the seeded window",
			live.CreatedAt, live.ExpiresAt)
	}

	// A person with no profile is named by the username, the same way the member
	// roster names one.
	ended := rows[1]
	if ended.UserName != "second" || ended.State != StateTerminated {
		t.Errorf("the terminated session reads %q at state %d, want the username and state 2",
			ended.UserName, ended.State)
	}

	// A row nothing can open still reaches the page, and says nothing rather
	// than failing the read.
	broken := rows[0]
	if broken.IP != "" || broken.UserAgent != "" || len(broken.Factors) != 0 {
		t.Errorf("the unreadable session reads %+v, want empty context", broken)
	}
	if broken.UserName != "The Owner" {
		t.Errorf("the unreadable session is named %q, want the joined display name", broken.UserName)
	}
}

// TestListSessionsNarrows covers the three filters the console sends: one
// person, one organization, and one state.
func TestListSessionsNarrows(t *testing.T) {
	repo, ctx := testAdminRepo(t)

	rows, total, err := repo.ListSessions(ctx, adminTenantID, Query{UserID: secondUserID, Limit: 20})
	if err != nil {
		t.Fatalf("list the sessions of one person: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].ID != terminatedSessionID {
		t.Fatalf("the sessions of one person read %+v, want the terminated one", rows)
	}

	rows, _, err = repo.ListSessions(ctx, adminTenantID, Query{OrgID: adminOrgID, Limit: 20})
	if err != nil {
		t.Fatalf("list the sessions of one organization: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("the sessions of one organization read %+v, want the two of the owner", rows)
	}

	rows, _, err = repo.ListSessions(ctx, adminTenantID, Query{State: StateTerminated, Limit: 20})
	if err != nil {
		t.Fatalf("list the terminated sessions: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != terminatedSessionID {
		t.Fatalf("the terminated sessions read %+v, want one row", rows)
	}
}

// TestListSessionsPages reads the window the pager asks for, and reports the
// total behind it. The console renders page numbers from that total.
func TestListSessionsPages(t *testing.T) {
	repo, ctx := testAdminRepo(t)

	rows, total, err := repo.ListSessions(ctx, adminTenantID,
		Query{Sort: "created", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("list the second page: %v", err)
	}
	if total != 3 {
		t.Errorf("the total reads %d, want 3 on every page", total)
	}
	// Oldest first, so the second page holds the terminated session.
	if len(rows) != 1 || rows[0].ID != terminatedSessionID {
		t.Fatalf("the second page reads %+v, want the terminated session", rows)
	}

	rows, _, err = repo.ListSessions(ctx, adminTenantID, Query{Sort: "state", Desc: true, Limit: 1})
	if err != nil {
		t.Fatalf("list by state: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != terminatedSessionID {
		t.Fatalf("the page by state reads %+v, want the terminated session first", rows)
	}
}

// TestDeleteSession covers the administrative revoke: the row goes, and the
// token digest comes back so the cache entry can go with it.
func TestDeleteSession(t *testing.T) {
	repo, ctx := testAdminRepo(t)

	revoked, err := repo.DeleteSession(ctx, adminTenantID, liveSessionID)
	if err != nil {
		t.Fatalf("revoke the login session: %v", err)
	}
	if revoked.TokenHash != "digest-live" || revoked.UserID != ownerUserID {
		t.Errorf("the revoke answers %+v, want the digest and the owner of the session", revoked)
	}

	rows, total, err := repo.ListSessions(ctx, adminTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the login sessions: %v", err)
	}
	if total != 2 || len(rows) != 2 {
		t.Errorf("the tenant holds %d sessions, want 2 after the revoke", total)
	}

	// A row that is already gone is not revoked twice.
	if _, err := repo.DeleteSession(ctx, adminTenantID, liveSessionID); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("a second revoke answers %v, want ErrNoSuchSession", err)
	}

	// The session of another tenant is not reachable through this one.
	if _, err := repo.DeleteSession(ctx, adminTenantID, foreignSessionID); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("the revoke of a foreign session answers %v, want ErrNoSuchSession", err)
	}
}

// TestDeleteUserSessions covers the force-logout: every session of one person
// goes, and nobody else's does.
func TestDeleteUserSessions(t *testing.T) {
	repo, ctx := testAdminRepo(t)

	revoked, err := repo.DeleteUserSessions(ctx, adminTenantID, ownerUserID)
	if err != nil {
		t.Fatalf("revoke the sessions of one person: %v", err)
	}
	if len(revoked) != 2 {
		t.Fatalf("the force-logout ended %d sessions, want 2: %+v", len(revoked), revoked)
	}

	rows, _, err := repo.ListSessions(ctx, adminTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the login sessions: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != terminatedSessionID {
		t.Fatalf("the tenant reads %+v, want only the session of the other person", rows)
	}

	// A person with nothing signed in is not an error. The answer is that
	// nothing of theirs is live, which is what the operator asked for.
	revoked, err = repo.DeleteUserSessions(ctx, adminTenantID, ownerUserID)
	if err != nil || len(revoked) != 0 {
		t.Errorf("a second force-logout answers %+v and %v, want nothing and no error", revoked, err)
	}
}
