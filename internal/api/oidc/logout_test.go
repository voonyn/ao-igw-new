package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// signedOut records the login sessions one logout ended. It stands in for the
// session service, which needs a database.
type signedOut struct {
	tenants  []string
	sessions []string
}

func (s *signedOut) Terminate(_ context.Context, tenantID, sessionID string) error {
	s.tenants = append(s.tenants, tenantID)
	s.sessions = append(s.sessions, sessionID)
	return nil
}

// sessionGrants is the grant store of one login session, held in memory. saved
// records what the policy wrote back.
type sessionGrants struct {
	held  []*goidc.Grant
	saved []*goidc.Grant
}

func (g *sessionGrants) List(_ context.Context, _, _ string) ([]*goidc.Grant, error) {
	return g.held, nil
}

func (g *sessionGrants) Save(_ context.Context, grant *goidc.Grant) error {
	g.saved = append(g.saved, grant)
	return nil
}

// testLogoutDeps binds one logout policy to the fakes above. A zero
// sessionGrants value means the login session produced no grant.
func testLogoutDeps(t *testing.T, ended *signedOut, grants *sessionGrants) LogoutDeps {
	t.Helper()

	log, _ := logger.NewObserved()
	return LogoutDeps{
		Terminate: ended.Terminate,
		Grants:    grants.List,
		Revoke:    grants.Save,
		Log:       log,
	}
}

// logoutSession is what goidc hands the policy: one logout request whose ID
// token hint names a login session.
func logoutSession(sessionID string) *goidc.LogoutSession {
	return &goidc.LogoutSession{
		ID:       "logout-1",
		Status:   goidc.StatusPending,
		ClientID: "client-1",
		IDTokenHintClaims: &goidc.IDToken{
			Subject:          "user-1",
			AdditionalClaims: map[string]any{"sid": sessionID},
		},
		LogoutParameters: goidc.LogoutParameters{IDTokenHint: "an.id.token"},
	}
}

// TestLogoutPolicy_EndsTheLoginSession covers the logout an ID token hint
// names. The sid claim names the login session, and the policy ends it.
func TestLogoutPolicy_EndsTheLoginSession(t *testing.T) {
	ended := &signedOut{}
	policy := LogoutPolicy("tenant-1", testLogoutDeps(t, ended, &sessionGrants{}))

	req := httptest.NewRequest(http.MethodGet, "/oidc/v1/logout", nil)
	status, err := policy.Logout(httptest.NewRecorder(), req, logoutSession("session-1"))
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if status != goidc.StatusSuccess {
		t.Errorf("status is %q, want %q", status, goidc.StatusSuccess)
	}

	if len(ended.sessions) != 1 || ended.sessions[0] != "session-1" {
		t.Errorf("ended sessions are %v, want [session-1]", ended.sessions)
	}
	if len(ended.tenants) != 1 || ended.tenants[0] != "tenant-1" {
		t.Errorf("ended tenants are %v, want [tenant-1]", ended.tenants)
	}
}

// TestLogoutPolicy_RevokesTheGrantsOfTheSession covers the tokens one sign-in
// produced. The login session ends, so every grant it produced ends with it,
// and a grant that is already revoked is left alone.
func TestLogoutPolicy_RevokesTheGrantsOfTheSession(t *testing.T) {
	ended := &signedOut{}
	grants := &sessionGrants{held: []*goidc.Grant{
		{ID: "grant-1", ClientID: "client-1", Subject: "user-1"},
		{ID: "grant-2", ClientID: "client-2", Subject: "user-1", RevokedAt: 1700000000},
	}}
	policy := LogoutPolicy("tenant-1", testLogoutDeps(t, ended, grants))

	req := httptest.NewRequest(http.MethodGet, "/oidc/v1/logout", nil)
	if _, err := policy.Logout(httptest.NewRecorder(), req, logoutSession("session-1")); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if len(grants.saved) != 1 {
		t.Fatalf("saved %d grants, want 1", len(grants.saved))
	}
	if grants.saved[0].ID != "grant-1" {
		t.Errorf("saved grant is %q, want %q", grants.saved[0].ID, "grant-1")
	}
	if grants.saved[0].RevokedAt == 0 {
		t.Error("the saved grant carries no revocation time")
	}
}

// TestLogoutPolicy_RecordsTheLogout covers the audit trail of one logout. The
// row names the person, the login session, and the client that asked.
func TestLogoutPolicy_RecordsTheLogout(t *testing.T) {
	ended := &signedOut{}
	log, _ := logger.NewObserved()

	var events []audit.Event
	recorder := audit.NewRecorder(func(_ context.Context, event audit.Event) error {
		events = append(events, event)
		return nil
	}, log)

	deps := testLogoutDeps(t, ended, &sessionGrants{})
	deps.Audit = recorder
	policy := LogoutPolicy("tenant-1", deps)

	req := httptest.NewRequest(http.MethodGet, "/oidc/v1/logout", nil)
	if _, err := policy.Logout(httptest.NewRecorder(), req, logoutSession("session-1")); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	event := events[0]
	if event.Action != string(audit.ActionLogoutSucceeded) {
		t.Errorf("action is %q, want %q", event.Action, audit.ActionLogoutSucceeded)
	}
	if event.EntityID != "session-1" {
		t.Errorf("entity id is %q, want %q", event.EntityID, "session-1")
	}
	if event.ActorID != "user-1" {
		t.Errorf("actor id is %q, want %q", event.ActorID, "user-1")
	}
	if !strings.Contains(event.Metadata, "client-1") {
		t.Errorf("metadata is %q, want the client id", event.Metadata)
	}
}

// TestDefaultPostLogout covers a logout request that names no
// post_logout_redirect_uri. The browser has nowhere to go, so it lands on the
// login UI.
func TestDefaultPostLogout(t *testing.T) {
	log, _ := logger.NewObserved()
	handle := DefaultPostLogout("https://login.example.com", log)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oidc/v1/logout", nil)
	if err := handle(rec, req, logoutSession("session-1")); err != nil {
		t.Fatalf("handle the post logout: %v", err)
	}

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status is %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if location := rec.Header().Get("Location"); location != "https://login.example.com" {
		t.Errorf("location is %q, want %q", location, "https://login.example.com")
	}
}

// TestLogoutPolicy_RefusesWithoutIDTokenHint covers a logout request that names
// no ID token. Nothing says which login session to end, so the request fails
// and no session is touched.
func TestLogoutPolicy_RefusesWithoutIDTokenHint(t *testing.T) {
	ended := &signedOut{}
	policy := LogoutPolicy("tenant-1", testLogoutDeps(t, ended, &sessionGrants{}))

	ls := logoutSession("session-1")
	ls.IDTokenHint = ""
	ls.IDTokenHintClaims = nil

	req := httptest.NewRequest(http.MethodGet, "/oidc/v1/logout", nil)
	status, err := policy.Logout(httptest.NewRecorder(), req, ls)
	if status != goidc.StatusFailure {
		t.Errorf("status is %q, want %q", status, goidc.StatusFailure)
	}
	if err == nil {
		t.Fatal("logout answered no error")
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("error is %v, want a goidc error", err)
	}
	if oidcErr.Code != goidc.ErrorCodeInvalidRequest {
		t.Errorf("error code is %q, want %q", oidcErr.Code, goidc.ErrorCodeInvalidRequest)
	}
	if len(ended.sessions) != 0 {
		t.Errorf("ended sessions are %v, want none", ended.sessions)
	}
}

// TestLogoutPolicy_RefusesWithoutSessionClaim covers an ID token that carries no
// sid claim. Every token this gateway mints carries one, so a token without it
// names no login session and the request fails.
func TestLogoutPolicy_RefusesWithoutSessionClaim(t *testing.T) {
	ended := &signedOut{}
	policy := LogoutPolicy("tenant-1", testLogoutDeps(t, ended, &sessionGrants{}))

	ls := logoutSession("session-1")
	ls.IDTokenHintClaims.AdditionalClaims = nil

	req := httptest.NewRequest(http.MethodGet, "/oidc/v1/logout", nil)
	status, err := policy.Logout(httptest.NewRecorder(), req, ls)
	if status != goidc.StatusFailure {
		t.Errorf("status is %q, want %q", status, goidc.StatusFailure)
	}
	if err == nil {
		t.Fatal("logout answered no error")
	}
	if len(ended.sessions) != 0 {
		t.Errorf("ended sessions are %v, want none", ended.sessions)
	}
}
