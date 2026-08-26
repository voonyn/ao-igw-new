package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// owner is the person every self-service test acts as. It is the subject of the
// caller's own token, because the account API has no other subject.
var owner = Actor{
	TenantID:  adminTenantID,
	UserID:    ownerUserID,
	IP:        "203.0.113.7",
	UserAgent: "a-browser",
}

// What one self-service test read and wrote.
type accountSpy struct {
	// narrowedTo is the query the list read with, and revokedOwner is the person
	// the single delete narrowed to. The ownership rule is that both name the
	// caller, so the tests read them back.
	narrowedTo   Query
	revokedOwner string
	spared       string

	revokedSessions []string
	revokedGrantsOf []string
	events          []audit.Event
}

// accountService stands the self-service session service up on closures. rows is
// every login session the tenant holds, and each closure narrows it the way the
// repository query does. A fake that ignored the narrowing would prove nothing,
// because the narrowing is the whole ownership rule.
func accountService(t *testing.T, rows []Record) (*AccountService, *accountSpy) {
	t.Helper()
	log, _ := logger.NewObserved()
	spy := &accountSpy{}

	svc := NewAccountService(AccountDeps{
		List: func(_ context.Context, _ string, q Query) ([]Record, int64, error) {
			spy.narrowedTo = q
			var mine []Record
			for _, row := range rows {
				if row.UserID == q.UserID {
					mine = append(mine, row)
				}
			}
			return mine, int64(len(mine)), nil
		},
		Revoke: func(_ context.Context, _, ownerID, sessionID string) (Revoked, error) {
			spy.revokedOwner = ownerID
			for _, row := range rows {
				if row.ID == sessionID && (ownerID == "" || row.UserID == ownerID) {
					spy.revokedSessions = append(spy.revokedSessions, sessionID)
					return Revoked{SessionID: sessionID, UserID: row.UserID, TokenHash: "a-digest"}, nil
				}
			}
			return Revoked{}, ErrNoSuchSession
		},
		RevokeOthers: func(_ context.Context, _, userID, exceptID string) ([]Revoked, error) {
			spy.spared = exceptID
			var revoked []Revoked
			for _, row := range rows {
				if row.UserID != userID || row.ID == exceptID {
					continue
				}
				spy.revokedSessions = append(spy.revokedSessions, row.ID)
				revoked = append(revoked, Revoked{SessionID: row.ID, UserID: row.UserID})
			}
			return revoked, nil
		},
		RevokeGrants: func(_ context.Context, _, sessionID string) (int, error) {
			spy.revokedGrantsOf = append(spy.revokedGrantsOf, sessionID)
			return 2, nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			return fn(ctx)
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			spy.events = append(spy.events, e)
			return nil
		}, log),
		Log: log,
	})
	return svc, spy
}

// ownRows is one live session of the caller, one more of the caller, and one of
// a different person. The third is what every ownership assertion turns on.
func ownRows() []Record {
	at := time.Now().Add(-time.Hour)
	return []Record{
		{
			ID: liveSessionID, TenantID: adminTenantID, UserID: ownerUserID,
			State: StateActive, CreatedAt: at, ExpiresAt: at.Add(12 * time.Hour),
			IP: "203.0.113.7", UserAgent: "a-browser",
			Factors: map[string]time.Time{FactorPassword: at},
		},
		{
			ID: brokenSessionID, TenantID: adminTenantID, UserID: ownerUserID,
			State: StateActive, CreatedAt: at, ExpiresAt: at.Add(12 * time.Hour),
			IP: "198.51.100.4", UserAgent: "a-phone",
		},
		{
			ID: foreignSessionID, TenantID: adminTenantID, UserID: secondUserID,
			State: StateActive, CreatedAt: at, ExpiresAt: at.Add(12 * time.Hour),
		},
	}
}

// TestAccountListReadsOnlyTheCallersSessions covers the ownership rule of the
// read. The list narrows to the subject of the token, and the session of another
// person is not in the answer.
func TestAccountListReadsOnlyTheCallersSessions(t *testing.T) {
	svc, spy := accountService(t, ownRows())

	views, err := svc.List(context.Background(), owner)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if spy.narrowedTo.UserID != ownerUserID {
		t.Errorf("the read narrowed to user %q, want %q", spy.narrowedTo.UserID, ownerUserID)
	}
	if spy.narrowedTo.State != StateActive {
		t.Errorf("the read narrowed to state %d, want %d", spy.narrowedTo.State, StateActive)
	}
	if len(views) != 2 {
		t.Fatalf("the caller reads %d sessions, want their own 2", len(views))
	}
	for _, v := range views {
		if v.ID == foreignSessionID {
			t.Errorf("the caller reads session %s, which belongs to somebody else", v.ID)
		}
	}
}

// TestAccountListNeverNamesTheCallersOwnSession covers what the answer leaves
// out. The access token carries no session identifier, so the gateway cannot say
// which row the caller is using. The portal reads sid from the ID token it holds
// and marks the row itself.
func TestAccountListNeverNamesTheCallersOwnSession(t *testing.T) {
	svc, _ := accountService(t, ownRows())

	views, err := svc.List(context.Background(), owner)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	// Each row carries what tells one device from another, and nothing that
	// names the person or the tenant behind it.
	for _, v := range views {
		if v.ID == "" || v.CreatedAt.IsZero() || v.ExpiresAt.IsZero() {
			t.Errorf("session %+v is missing what the portal renders", v)
		}
	}
	if views[0].IP != "203.0.113.7" || views[0].UserAgent != "a-browser" {
		t.Errorf("session %+v does not carry where it signed in from", views[0])
	}
}

// TestAccountListDropsAnExpiredSession covers what a person can act on. An
// operator must read a session that ended, and a person must not, because they
// cannot end it a second time.
func TestAccountListDropsAnExpiredSession(t *testing.T) {
	rows := ownRows()
	rows[1].ExpiresAt = time.Now().Add(-time.Minute)
	svc, _ := accountService(t, rows)

	views, err := svc.List(context.Background(), owner)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(views) != 1 || views[0].ID != liveSessionID {
		t.Errorf("the caller reads %d sessions, want only the live one", len(views))
	}
}

// TestAccountRevokeEndsTheSessionAndItsGrants covers the write. The grants of
// that sign-in go with the session, so no refresh token of the device survives
// the sign-out the person clicked.
func TestAccountRevokeEndsTheSessionAndItsGrants(t *testing.T) {
	svc, spy := accountService(t, ownRows())

	out, err := svc.Revoke(context.Background(), owner, liveSessionID)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if out.Sessions != 1 || out.Grants != 2 {
		t.Errorf("the revoke ended %+v, want 1 session and 2 grants", out)
	}
	if len(spy.revokedSessions) != 1 || spy.revokedSessions[0] != liveSessionID {
		t.Errorf("the revoke ended %v, want only %s", spy.revokedSessions, liveSessionID)
	}
	if len(spy.revokedGrantsOf) != 1 || spy.revokedGrantsOf[0] != liveSessionID {
		t.Errorf("the revoke ended the grants of %v, want only %s", spy.revokedGrantsOf, liveSessionID)
	}
	if len(spy.events) != 1 || spy.events[0].EntityID != liveSessionID {
		t.Errorf("the revoke recorded %d events, want one naming the session", len(spy.events))
	}
}

// TestAccountRevokeNarrowsTheDeleteToTheCaller covers where the ownership rule
// lives. It is the delete itself, not a read taken before it, so no page of a
// list can bound what the caller proves.
func TestAccountRevokeNarrowsTheDeleteToTheCaller(t *testing.T) {
	svc, spy := accountService(t, ownRows())

	if _, err := svc.Revoke(context.Background(), owner, liveSessionID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if spy.revokedOwner != ownerUserID {
		t.Errorf("the delete narrowed to owner %q, want %q", spy.revokedOwner, ownerUserID)
	}
}

// TestAccountRevokeRefusesSomebodyElsesSession covers the ownership rule of the
// write, and the shape of the refusal. A session of another person and a session
// that does not exist read alike, so the answer never says which sessions
// another person holds.
func TestAccountRevokeRefusesSomebodyElsesSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   string
	}{
		{"a session of another person", foreignSessionID},
		{"a session that does not exist", "b0000000-0000-0000-0000-00000000ffff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc, spy := accountService(t, ownRows())

			_, err := svc.Revoke(context.Background(), owner, tc.id)
			if !errors.Is(err, ErrNoSuchSession) {
				t.Fatalf("the revoke answered %v, want ErrNoSuchSession", err)
			}
			if len(spy.revokedSessions) != 0 || len(spy.revokedGrantsOf) != 0 {
				t.Errorf("the refused revoke still ended %v and the grants of %v",
					spy.revokedSessions, spy.revokedGrantsOf)
			}
			if len(spy.events) != 0 {
				t.Errorf("the refused revoke recorded %d audit events, want none", len(spy.events))
			}
		})
	}
}

// TestAccountRevokeRefusesATokenThatNamesNobody covers the guard at the trust
// boundary. An empty owner reaches every person in the tenant at the repository,
// so an empty subject must never get that far.
func TestAccountRevokeRefusesATokenThatNamesNobody(t *testing.T) {
	svc, spy := accountService(t, ownRows())
	nobody := Actor{TenantID: adminTenantID}

	if _, err := svc.Revoke(context.Background(), nobody, liveSessionID); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("the revoke answered %v, want ErrNoSuchSession", err)
	}
	if _, err := svc.RevokeOthers(context.Background(), nobody, ""); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("the bulk revoke answered %v, want ErrNoSuchSession", err)
	}
	if len(spy.revokedSessions) != 0 {
		t.Errorf("a token that names nobody ended %v, want nothing", spy.revokedSessions)
	}
}

// TestAccountRevokeOthersKeepsTheNamedSession covers the exception. The session
// the caller is using survives, and every other one of theirs ends with its
// grants.
func TestAccountRevokeOthersKeepsTheNamedSession(t *testing.T) {
	svc, spy := accountService(t, ownRows())

	out, err := svc.RevokeOthers(context.Background(), owner, liveSessionID)
	if err != nil {
		t.Fatalf("RevokeOthers: %v", err)
	}

	if spy.spared != liveSessionID {
		t.Errorf("the delete spared %q, want %q", spy.spared, liveSessionID)
	}
	if out.Sessions != 1 || out.Grants != 2 {
		t.Errorf("the bulk revoke ended %+v, want 1 session and 2 grants", out)
	}
	if len(spy.revokedSessions) != 1 || spy.revokedSessions[0] != brokenSessionID {
		t.Errorf("the bulk revoke ended %v, want only %s", spy.revokedSessions, brokenSessionID)
	}
	if len(spy.revokedGrantsOf) != 1 || spy.revokedGrantsOf[0] != brokenSessionID {
		t.Errorf("the bulk revoke ended the grants of %v, want only %s",
			spy.revokedGrantsOf, brokenSessionID)
	}
	if len(spy.events) != 1 || spy.events[0].EntityID != ownerUserID {
		t.Errorf("the bulk revoke recorded %d events, want one naming the person", len(spy.events))
	}
}

// TestAccountRevokeOthersWithNoExceptionEndsEverything covers the
// sign-out-everywhere control. With no session named, the caller's own browser
// goes with the rest, and the session of another person still does not.
func TestAccountRevokeOthersWithNoExceptionEndsEverything(t *testing.T) {
	svc, spy := accountService(t, ownRows())

	out, err := svc.RevokeOthers(context.Background(), owner, "")
	if err != nil {
		t.Fatalf("RevokeOthers: %v", err)
	}

	if out.Sessions != 2 || out.Grants != 4 {
		t.Errorf("the bulk revoke ended %+v, want 2 sessions and 4 grants", out)
	}
	for _, id := range spy.revokedSessions {
		if id == foreignSessionID {
			t.Errorf("the bulk revoke ended session %s, which belongs to somebody else", id)
		}
	}
	if len(spy.revokedSessions) != 2 {
		t.Errorf("the bulk revoke ended %v, want both sessions of the caller", spy.revokedSessions)
	}
}

// TestAccountRevokeOthersEndsNothingWhenOnlyTheCallerIsSignedIn covers the empty
// answer. A person with one device asked a real question, zero is the true
// answer to it, and no fact happened for the audit trail to hold.
func TestAccountRevokeOthersEndsNothingWhenOnlyTheCallerIsSignedIn(t *testing.T) {
	svc, spy := accountService(t, ownRows()[:1])

	out, err := svc.RevokeOthers(context.Background(), owner, liveSessionID)
	if err != nil {
		t.Fatalf("RevokeOthers: %v", err)
	}
	if out.Sessions != 0 || out.Grants != 0 {
		t.Errorf("the bulk revoke ended %+v, want nothing", out)
	}
	if len(spy.revokedSessions) != 0 {
		t.Errorf("the bulk revoke ended %v, want nothing", spy.revokedSessions)
	}
	if len(spy.events) != 0 {
		t.Errorf("the bulk revoke recorded %d audit events, want none", len(spy.events))
	}
}
