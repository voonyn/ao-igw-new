package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// operator is the person every administrative test acts as.
var operator = Actor{
	TenantID:  adminTenantID,
	UserID:    ownerUserID,
	IP:        "203.0.113.9",
	UserAgent: "the-console",
}

// adminDeps is what one administrative test stands the service up with.
type adminDeps struct {
	roles []string
	rows  []Record

	sessionGrants int
	userGrants    int

	revokeFails bool
	auditFails  bool
}

// What the writes of one test did. testAdminService clears them, and the tests
// of one package run one after another, so each test reads its own writes.
var (
	revokedSessions []string
	revokedUsers    []string
	revokedGrantsOf []string
	adminEvents     []audit.Event
)

func testAdminService(t *testing.T, d adminDeps) *AdminService {
	t.Helper()
	log, _ := logger.NewObserved()
	revokedSessions, revokedUsers, revokedGrantsOf, adminEvents = nil, nil, nil, nil

	return NewAdminService(AdminDeps{
		List: func(context.Context, string, Query) ([]Record, int64, error) {
			return d.rows, int64(len(d.rows)), nil
		},
		Revoke: func(_ context.Context, _, sessionID string) (Revoked, error) {
			if d.revokeFails {
				return Revoked{}, ErrNoSuchSession
			}
			revokedSessions = append(revokedSessions, sessionID)
			return Revoked{SessionID: sessionID, UserID: secondUserID, TokenHash: "a-digest"}, nil
		},
		RevokeUser: func(_ context.Context, _, userID string) ([]Revoked, error) {
			revokedUsers = append(revokedUsers, userID)
			return []Revoked{
				{SessionID: liveSessionID, UserID: userID},
				{SessionID: brokenSessionID, UserID: userID},
			}, nil
		},
		RevokeGrants: func(_ context.Context, _, sessionID string) (int, error) {
			revokedGrantsOf = append(revokedGrantsOf, sessionID)
			return d.sessionGrants, nil
		},
		RevokeUserGrants: func(_ context.Context, _, userID string) (int, error) {
			revokedGrantsOf = append(revokedGrantsOf, userID)
			return d.userGrants, nil
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) {
			return d.roles, nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			return fn(ctx)
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			if d.auditFails {
				return errors.New("the audit write failed")
			}
			adminEvents = append(adminEvents, e)
			return nil
		}, log),
		Log: log,
	})
}

// TestListRefusesAnybodyButATenantManager covers the gate. An organization
// owner administers people, and reads no session of the tenant.
func TestListRefusesAnybodyButATenantManager(t *testing.T) {
	svc := testAdminService(t, adminDeps{roles: nil})

	if _, _, err := svc.List(context.Background(), operator, Query{Limit: 20}); !errors.Is(err, ErrForbidden) {
		t.Errorf("a person with no tenant role reads %v, want ErrForbidden", err)
	}

	svc = testAdminService(t, adminDeps{roles: []string{tenant.RoleIAMAdmin}})
	if _, _, err := svc.List(context.Background(), operator, Query{Limit: 20}); err != nil {
		t.Errorf("a tenant administrator reads %v, want the page", err)
	}
}

// TestListAnswersTheConsoleView covers what one row carries: the person, the
// organization, the factors in a stable order, and the protocol links.
func TestListAnswersTheConsoleView(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	svc := testAdminService(t, adminDeps{
		roles: []string{tenant.RoleIAMOwner},
		rows: []Record{{
			ID: liveSessionID, TenantID: adminTenantID, UserID: ownerUserID,
			UserName: "The Owner", OrgID: adminOrgID, State: StateActive,
			CreatedAt: at, ExpiresAt: at.Add(12 * time.Hour),
			IP: "203.0.113.7", UserAgent: "a-browser",
			Factors: map[string]time.Time{FactorPassword: at},
			Links:   []Link{{Protocol: 1, Ref: "authn-1", AppID: "client-1"}},
		}},
	})

	views, total, err := svc.List(context.Background(), operator, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the login sessions: %v", err)
	}
	if total != 1 || len(views) != 1 {
		t.Fatalf("the page holds %d of %d rows, want 1 of 1", len(views), total)
	}

	view := views[0]
	if view.UserName != "The Owner" || view.OrgID != adminOrgID {
		t.Errorf("the row reads %+v, want the person and the organization", view)
	}
	if len(view.Factors) != 1 || view.Factors[0].AMR != FactorPassword || !view.Factors[0].Time.Equal(at) {
		t.Errorf("the row carries %+v, want the password factor", view.Factors)
	}
	if len(view.Links) != 1 || view.Links[0].AppID != "client-1" || view.Links[0].Ref != "authn-1" {
		t.Errorf("the row carries %+v, want the seeded protocol link", view.Links)
	}
}

// TestListAnswersEmptyCollections covers a session nothing can open. The console
// iterates both collections without a guard, so the answer carries [] and never
// null.
func TestListAnswersEmptyCollections(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{tenant.RoleIAMOwner},
		rows:  []Record{{ID: brokenSessionID, TenantID: adminTenantID}},
	})

	views, _, err := svc.List(context.Background(), operator, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the login sessions: %v", err)
	}
	if views[0].Factors == nil || views[0].Links == nil {
		t.Errorf("the row reads %+v, want empty collections and never null", views[0])
	}
}

// TestRevokeEndsTheSessionAndItsGrants covers the administrative revoke. The
// session goes, its grants go with it, and one event records both.
func TestRevokeEndsTheSessionAndItsGrants(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles:         []string{tenant.RoleIAMOwner},
		sessionGrants: 3,
	})

	view, err := svc.Revoke(context.Background(), operator, liveSessionID)
	if err != nil {
		t.Fatalf("revoke the login session: %v", err)
	}
	if view.Sessions != 1 || view.Grants != 3 {
		t.Errorf("the revoke answers %+v, want one session and three grants", view)
	}
	if len(revokedSessions) != 1 || revokedSessions[0] != liveSessionID {
		t.Errorf("the revoke ended %v, want the named session", revokedSessions)
	}
	if len(revokedGrantsOf) != 1 || revokedGrantsOf[0] != liveSessionID {
		t.Errorf("the revoke ended the grants of %v, want the named session", revokedGrantsOf)
	}

	if len(adminEvents) != 1 {
		t.Fatalf("the revoke recorded %d events, want 1", len(adminEvents))
	}
	event := adminEvents[0]
	if event.Action != string(audit.ActionSessionRevoked) || event.EntityType != audit.EntitySession {
		t.Errorf("the event reads %s on %s, want session.revoked on the login session",
			event.Action, event.EntityType)
	}
	if event.EntityID != liveSessionID || event.ActorID != ownerUserID {
		t.Errorf("the event names %s by %s, want the session and the operator",
			event.EntityID, event.ActorID)
	}
}

// TestRevokeRefusesAnybodyButATenantManager covers the gate of the write. A
// refused revoke ends nothing.
func TestRevokeRefusesAnybodyButATenantManager(t *testing.T) {
	svc := testAdminService(t, adminDeps{roles: []string{"ORG_OWNER"}})

	if _, err := svc.Revoke(context.Background(), operator, liveSessionID); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner revokes with %v, want ErrForbidden", err)
	}
	if len(revokedSessions) != 0 || len(adminEvents) != 0 {
		t.Errorf("a refused revoke wrote %v and %d events, want nothing", revokedSessions, len(adminEvents))
	}
}

// TestRevokeAnswersAMissingSession covers a session that is already gone. The
// answer is 404 and not a success, so an operator is never told that a revoke
// worked when no row was there.
func TestRevokeAnswersAMissingSession(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles:       []string{tenant.RoleIAMOwner},
		revokeFails: true,
	})

	if _, err := svc.Revoke(context.Background(), operator, liveSessionID); !errors.Is(err, ErrNoSuchSession) {
		t.Errorf("the revoke of a missing session answers %v, want ErrNoSuchSession", err)
	}
	if len(revokedGrantsOf) != 0 {
		t.Errorf("a failed revoke ended the grants of %v, want nothing", revokedGrantsOf)
	}
}

// TestRevokeForUserTakesTheGrantsToo covers the force-logout. Every session of
// the person goes, and every grant they hold goes with them, so no refresh token
// survives.
func TestRevokeForUserTakesTheGrantsToo(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles:      []string{tenant.RoleIAMOwner},
		userGrants: 5,
	})

	view, err := svc.RevokeForUser(context.Background(), operator, secondUserID)
	if err != nil {
		t.Fatalf("sign the person out everywhere: %v", err)
	}
	if view.Sessions != 2 || view.Grants != 5 {
		t.Errorf("the force-logout answers %+v, want two sessions and five grants", view)
	}
	if len(revokedUsers) != 1 || revokedUsers[0] != secondUserID {
		t.Errorf("the force-logout ended the sessions of %v, want the named person", revokedUsers)
	}

	if len(adminEvents) != 1 {
		t.Fatalf("the force-logout recorded %d events, want 1", len(adminEvents))
	}
	event := adminEvents[0]
	if event.EntityType != audit.EntityUser || event.EntityID != secondUserID {
		t.Errorf("the event reads %s %s, want the person the force-logout named",
			event.EntityType, event.EntityID)
	}
}

// TestRevokeFailsWhenTheAuditWriteFails covers the rule that a revoke nobody can
// audit is not allowed to stand. The transaction carries both, so neither
// happens.
func TestRevokeFailsWhenTheAuditWriteFails(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles:      []string{tenant.RoleIAMOwner},
		auditFails: true,
	})

	if _, err := svc.Revoke(context.Background(), operator, liveSessionID); err == nil {
		t.Error("the revoke succeeded with no audit row, want the failure")
	}
}
