package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/audit"
	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// sessions is the authn session store, held in memory. It stands in for the
// storage repository, which needs a database.
type sessions struct {
	held map[string]*goidc.AuthnSession
}

func newSessions(held ...*goidc.AuthnSession) *sessions {
	store := &sessions{held: make(map[string]*goidc.AuthnSession, len(held))}
	for _, session := range held {
		store.held[session.ID] = session
	}
	return store
}

func (s *sessions) Find(_ context.Context, _, id string) (*goidc.AuthnSession, error) {
	session, ok := s.held[id]
	if !ok {
		return nil, aooidc.ErrSessionNotFound
	}
	return session, nil
}

func (s *sessions) Save(_ context.Context, _ string, session *goidc.AuthnSession) error {
	s.held[session.ID] = session
	return nil
}

// consents stands in for the consent service. needed is what the screen must
// ask for, and answered holds what the person replied.
type consents struct {
	needed   []string
	answered []audit.Action
}

func (c *consents) Decide(_ context.Context, _, _, _ string, _ []string, _ bool) ([]string, error) {
	return c.needed, nil
}

func (c *consents) Approve(context.Context, aooidc.Consent) error {
	c.answered = append(c.answered, audit.ActionConsentGranted)
	return nil
}

func (c *consents) Deny(context.Context, aooidc.Consent) error {
	c.answered = append(c.answered, audit.ActionConsentDenied)
	return nil
}

func testCompleter(t *testing.T, store *sessions) Completer {
	t.Helper()
	return testConsentCompleter(t, store, &consents{})
}

// testConsentCompleter builds the completer over one consent answer. A zero
// consents value needs no screen, which is what every step before S10 assumed.
func testConsentCompleter(t *testing.T, store *sessions, given *consents) Completer {
	t.Helper()

	log, _ := logger.NewObserved()
	return NewCompleter(CompleterDeps{
		PathPrefix: "/oidc/v1",
		Find:       store.Find,
		Save:       store.Save,
		Decide:     given.Decide,
		Approve:    given.Approve,
		Deny:       given.Deny,
		Log:        log,
	})
}

// pending is the authn session the authorization endpoint left behind: a
// request in flight that names no person yet.
func pending(id string) *goidc.AuthnSession {
	return &goidc.AuthnSession{
		ID:        id,
		ClientID:  "console",
		Status:    goidc.StatusPending,
		CreatedAt: int(time.Now().Add(-time.Minute).Unix()),
		AuthorizationParameters: goidc.AuthorizationParameters{
			Scopes: "openid profile",
		},
	}
}

func completion(id, subject string) Completion {
	return Completion{
		TenantID:      "tenant-1",
		Issuer:        "https://auth.example.com",
		AuthRequestID: id,
		Subject:       subject,
		AuthTime:      time.Now(),
	}
}

// TestComplete covers the finalize step: the authn session learns the person
// and the scopes, and the caller learns where to send the browser back.
func TestComplete(t *testing.T) {
	store := newSessions(pending("session-1"))
	complete := testCompleter(t, store)

	out, err := complete(context.Background(), completion("session-1", "user-1"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	want := "https://auth.example.com/oidc/v1/authorize/session-1"
	if out.RedirectTo != want {
		t.Errorf("the resume URL is %q, want %q", out.RedirectTo, want)
	}
	saved := store.held["session-1"]
	if saved.Subject != "user-1" {
		t.Errorf("the saved session names %q, want %q", saved.Subject, "user-1")
	}
	if saved.GrantedScopes != "openid profile" {
		t.Errorf("the granted scopes are %q, want the requested ones", saved.GrantedScopes)
	}
}

// TestComplete_CarriesTheLoginSession covers the sid the granted request keeps.
// goidc copies the store of the authn session onto the grant, and the ID token
// then publishes it, so a later logout can name the login session to end.
func TestComplete_CarriesTheLoginSession(t *testing.T) {
	store := newSessions(pending("session-1"))
	complete := testCompleter(t, store)

	done := completion("session-1", "user-1")
	done.SessionID = "login-1"
	if _, err := complete(context.Background(), done); err != nil {
		t.Fatalf("complete: %v", err)
	}

	saved := store.held["session-1"]
	if got, _ := saved.Store["sid"].(string); got != "login-1" {
		t.Errorf("the saved session carries sid %q, want %q", got, "login-1")
	}
}

// TestComplete_ConsentRequired covers a third-party client the person never
// approved. The finalize step asks for the screen instead of granting, and it
// writes nothing: the request stays in flight until the person answers.
func TestComplete_ConsentRequired(t *testing.T) {
	store := newSessions(pending("session-1"))
	complete := testConsentCompleter(t, store, &consents{needed: []string{"openid", "profile"}})

	out, err := complete(context.Background(), completion("session-1", "user-1"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if !out.ConsentRequired {
		t.Fatal("the finalize step granted without consent")
	}
	if out.ClientID != "console" {
		t.Errorf("the screen names client %q, want %q", out.ClientID, "console")
	}
	if !reflect.DeepEqual(out.Scopes, []string{"openid", "profile"}) {
		t.Errorf("the screen asks for %v, want the requested scopes", out.Scopes)
	}
	if out.RedirectTo != "" {
		t.Errorf("the browser is sent to %q, want the consent screen first", out.RedirectTo)
	}

	saved := store.held["session-1"]
	if saved.Subject != "" || saved.GrantedScopes != "" {
		t.Errorf("the session granted %q to %q before the answer", saved.GrantedScopes, saved.Subject)
	}
}

// TestComplete_ConsentApproved covers the answer the person gives. The consent
// is recorded, and the request then grants what it asked for.
func TestComplete_ConsentApproved(t *testing.T) {
	store := newSessions(pending("session-1"))
	given := &consents{needed: []string{"openid", "profile"}}
	complete := testConsentCompleter(t, store, given)

	approved := true
	done := completion("session-1", "user-1")
	done.Consent = &approved

	out, err := complete(context.Background(), done)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if out.RedirectTo != "https://auth.example.com/oidc/v1/authorize/session-1" {
		t.Errorf("the resume URL is %q, want the authorize callback", out.RedirectTo)
	}
	if !reflect.DeepEqual(given.answered, []audit.Action{audit.ActionConsentGranted}) {
		t.Errorf("the consent service saw %v, want one approval", given.answered)
	}
	if saved := store.held["session-1"]; saved.GrantedScopes != "openid profile" {
		t.Errorf("the granted scopes are %q, want the requested ones", saved.GrantedScopes)
	}
}

// TestComplete_ConsentDenied covers a refusal. The refusal is recorded, and the
// marker carries access_denied back to the client through the engine.
func TestComplete_ConsentDenied(t *testing.T) {
	store := newSessions(pending("session-1"))
	given := &consents{needed: []string{"openid", "profile"}}
	complete := testConsentCompleter(t, store, given)

	approved := false
	done := completion("session-1", "user-1")
	done.Consent = &approved

	out, err := complete(context.Background(), done)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if out.RedirectTo != "https://auth.example.com/oidc/v1/authorize/session-1" {
		t.Errorf("the resume URL is %q, want the authorize callback", out.RedirectTo)
	}
	if !reflect.DeepEqual(given.answered, []audit.Action{audit.ActionConsentDenied}) {
		t.Errorf("the consent service saw %v, want one refusal", given.answered)
	}

	saved := store.held["session-1"]
	if saved.Store[storeErrorKey] != string(goidc.ErrorCodeAccessDenied) {
		t.Errorf("the marker is %v, want %q", saved.Store, goidc.ErrorCodeAccessDenied)
	}
	if saved.Subject != "" || saved.GrantedScopes != "" {
		t.Errorf("a refusal granted %q to %q", saved.GrantedScopes, saved.Subject)
	}
}

// TestComplete_ConsentPromptNone covers a silent request that needs consent. It
// must never reach a rendered page, so the marker carries consent_required back
// to the client through the engine.
func TestComplete_ConsentPromptNone(t *testing.T) {
	session := pending("session-1")
	session.Prompt = goidc.PromptTypeNone
	store := newSessions(session)
	given := &consents{needed: []string{"openid", "profile"}}
	complete := testConsentCompleter(t, store, given)

	out, err := complete(context.Background(), completion("session-1", "user-1"))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if out.ConsentRequired {
		t.Fatal("a silent request asked for the consent screen")
	}
	if out.RedirectTo != "https://auth.example.com/oidc/v1/authorize/session-1" {
		t.Errorf("the resume URL is %q, want the authorize callback", out.RedirectTo)
	}

	saved := store.held["session-1"]
	if saved.Store[storeErrorKey] != string(errorCodeConsentRequired) {
		t.Errorf("the marker is %v, want %q", saved.Store, errorCodeConsentRequired)
	}
	if len(given.answered) != 0 {
		t.Errorf("the consent service saw %v, want no answer", given.answered)
	}
}

// TestComplete_UnknownRequest covers an authorization request nobody holds.
func TestComplete_UnknownRequest(t *testing.T) {
	complete := testCompleter(t, newSessions())

	if _, err := complete(context.Background(), completion("session-9", "user-1")); !errors.Is(err, aooidc.ErrSessionNotFound) {
		t.Errorf("complete gave %v, want %v", err, aooidc.ErrSessionNotFound)
	}
}

// TestComplete_NoSubject covers a caller with no signed-in person. The person
// must sign in first, so the request stays in flight.
func TestComplete_NoSubject(t *testing.T) {
	store := newSessions(pending("session-1"))
	complete := testCompleter(t, store)

	if _, err := complete(context.Background(), completion("session-1", "")); !errors.Is(err, ErrInteractionRequired) {
		t.Fatalf("complete gave %v, want %v", err, ErrInteractionRequired)
	}
	if store.held["session-1"].Subject != "" {
		t.Error("a completion without a person named one")
	}
}

// TestComplete_PromptLogin covers prompt=login. The person signed in before the
// request arrived, and the client demands a new sign-in.
func TestComplete_PromptLogin(t *testing.T) {
	session := pending("session-1")
	session.Prompt = goidc.PromptTypeLogin
	complete := testCompleter(t, newSessions(session))

	done := completion("session-1", "user-1")
	done.AuthTime = time.Unix(int64(session.CreatedAt), 0).Add(-time.Hour)

	if _, err := complete(context.Background(), done); !errors.Is(err, ErrInteractionRequired) {
		t.Errorf("complete gave %v, want %v", err, ErrInteractionRequired)
	}
}

// TestComplete_PromptLoginAfterANewSignIn covers the second pass of
// prompt=login: the person signed in again, so the request completes.
func TestComplete_PromptLoginAfterANewSignIn(t *testing.T) {
	session := pending("session-1")
	session.Prompt = goidc.PromptTypeLogin
	complete := testCompleter(t, newSessions(session))

	if _, err := complete(context.Background(), completion("session-1", "user-1")); err != nil {
		t.Errorf("complete: %v", err)
	}
}

// TestComplete_MaxAgeExceeded covers max_age. The sign-in is older than the
// client accepts.
func TestComplete_MaxAgeExceeded(t *testing.T) {
	session := pending("session-1")
	maxAge := 60
	session.MaxAuthnAgeSecs = &maxAge
	complete := testCompleter(t, newSessions(session))

	done := completion("session-1", "user-1")
	done.AuthTime = time.Now().Add(-2 * time.Hour)

	if _, err := complete(context.Background(), done); !errors.Is(err, ErrInteractionRequired) {
		t.Errorf("complete gave %v, want %v", err, ErrInteractionRequired)
	}
}

// TestComplete_PromptNoneWithoutAPerson covers the silent request. It must
// never render a page, so the marker goes onto the authn session and the
// browser returns to the provider, which answers the client with the error.
func TestComplete_PromptNoneWithoutAPerson(t *testing.T) {
	session := pending("session-1")
	session.Prompt = goidc.PromptTypeNone
	store := newSessions(session)
	complete := testCompleter(t, store)

	out, err := complete(context.Background(), completion("session-1", ""))
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if out.RedirectTo != "https://auth.example.com/oidc/v1/authorize/session-1" {
		t.Errorf("the resume URL is %q, want the authorize callback", out.RedirectTo)
	}
	if store.held["session-1"].Store[storeErrorKey] != string(goidc.ErrorCodeLoginRequired) {
		t.Errorf("the marker is %v, want %q", store.held["session-1"].Store, goidc.ErrorCodeLoginRequired)
	}
}

// TestComplete_ClearsTheMarkerOnASignIn covers the second pass of a silent
// request. The first pass marked it login_required, the person then signed in,
// and the request must succeed. The policy reads the marker before the subject,
// so a marker that outlives its own pass fails the request forever.
func TestComplete_ClearsTheMarkerOnASignIn(t *testing.T) {
	session := pending("session-1")
	session.Prompt = goidc.PromptTypeNone
	store := newSessions(session)
	complete := testCompleter(t, store)

	if _, err := complete(context.Background(), completion("session-1", "")); err != nil {
		t.Fatalf("the silent pass: %v", err)
	}
	if _, err := complete(context.Background(), completion("session-1", "user-1")); err != nil {
		t.Fatalf("the sign-in pass: %v", err)
	}

	saved := store.held["session-1"]
	if _, marked := saved.Store[storeErrorKey]; marked {
		t.Errorf("the marker survived the sign-in: %v", saved.Store)
	}

	status, err, _ := runPolicy(t, saved)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if status != goidc.StatusSuccess {
		t.Errorf("the status is %q, want %q", status, goidc.StatusSuccess)
	}
}

// TestTokenAudit covers the token.issued record. The engine hands every token
// it mints to the handler, and the trail then names the client, the grant, and
// the scopes the token carries, and never the token itself.
func TestTokenAudit(t *testing.T) {
	var written []audit.Event
	log, _ := logger.NewObserved()
	recorder := audit.NewRecorder(func(_ context.Context, event audit.Event) error {
		written = append(written, event)
		return nil
	}, log)

	grant := &goidc.Grant{
		ID:       "grant-1",
		ClientID: "console",
		Subject:  "user-1",
		Scopes:   "openid profile email",
	}
	// The token carries less than the grant allows. The trail records what the
	// token got, so the narrower set is the one that must appear.
	token := &goidc.Token{
		ID:       "token-1",
		GrantID:  "grant-1",
		ClientID: "console",
		Subject:  "user-1",
		Scopes:   "openid",
	}
	if err := tokenAudit("tenant-1", recorder)(context.Background(), token, grant); err != nil {
		t.Fatalf("token audit: %v", err)
	}

	if len(written) != 1 {
		t.Fatalf("the trail holds %d events, want 1", len(written))
	}
	event := written[0]
	if event.Action != string(audit.ActionTokenIssued) {
		t.Errorf("the action is %q, want %q", event.Action, audit.ActionTokenIssued)
	}
	if event.TenantID != "tenant-1" || event.ActorID != "user-1" || event.EntityID != "grant-1" {
		t.Errorf("the event is %+v, want the grant of user-1 in tenant-1", event)
	}
	metadata := string(event.Metadata)
	for _, want := range []string{"console", "grant-1", "openid"} {
		if !strings.Contains(metadata, want) {
			t.Errorf("the metadata %s does not carry %q", metadata, want)
		}
	}
	if strings.Contains(metadata, "email") {
		t.Errorf("the metadata %s records the scopes of the grant, want the scopes of the token", metadata)
	}
	if strings.Contains(metadata, "token-1") {
		t.Errorf("the metadata %s names the token", metadata)
	}
}

// TestTokenAuditFailsTheRequest covers a failed audit write. The handler runs
// before the engine returns the token, so returning the error means the client
// never receives one: a token nobody can audit is not allowed to stand.
func TestTokenAuditFailsTheRequest(t *testing.T) {
	log, _ := logger.NewObserved()
	broken := errors.New("the audit table is unreachable")
	recorder := audit.NewRecorder(func(context.Context, audit.Event) error { return broken }, log)

	err := tokenAudit("tenant-1", recorder)(
		context.Background(),
		&goidc.Token{ID: "token-1", GrantID: "grant-1"},
		&goidc.Grant{ID: "grant-1", ClientID: "console"})
	if !errors.Is(err, broken) {
		t.Errorf("token audit gave %v, want %v", err, broken)
	}
}

// TestAuthPolicyWithoutALoginURL covers a tenant with no login UI configured.
// The handoff cannot be built, so the stub answers login_required rather than
// sending the browser to an empty URL.
func TestAuthPolicyWithoutALoginURL(t *testing.T) {
	log, _ := logger.NewObserved()
	policy := authPolicy(Deps{LoginURL: "", Log: log})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/v1/authorize", nil)
	status, err := policy.Authenticate(recorder, request, pending("session-1"), &goidc.Client{ID: "console"})

	if status != goidc.StatusFailure {
		t.Errorf("the status is %q, want %q", status, goidc.StatusFailure)
	}
	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("authenticate gave %v, want a protocol error", err)
	}
	if oidcErr.Code != goidc.ErrorCodeLoginRequired {
		t.Errorf("the error code is %q, want %q", oidcErr.Code, goidc.ErrorCodeLoginRequired)
	}
	if location := recorder.Header().Get("Location"); location != "" {
		t.Errorf("the stub sent the browser to %q, want no redirect", location)
	}
}

// TestAuthPolicyWithALoginURL covers the configured tenant. The handoff is
// built, so the browser reaches the login UI.
func TestAuthPolicyWithALoginURL(t *testing.T) {
	log, _ := logger.NewObserved()
	policy := authPolicy(Deps{LoginURL: "https://login.example.com", Log: log})

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/v1/authorize", nil)
	status, err := policy.Authenticate(recorder, request, pending("session-1"), &goidc.Client{ID: "console"})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if status != goidc.StatusPending {
		t.Errorf("the status is %q, want %q", status, goidc.StatusPending)
	}

	want := "https://login.example.com/identifier?authRequest=session-1"
	if got := recorder.Header().Get("Location"); got != want {
		t.Errorf("the browser is sent to %q, want %q", got, want)
	}
}

func testPolicy(t *testing.T) goidc.AuthnPolicy {
	t.Helper()

	log, _ := logger.NewObserved()
	return LoginPolicy("https://login.example.com", log)
}

// runPolicy runs the authentication step of the policy against one session.
func runPolicy(t *testing.T, session *goidc.AuthnSession) (goidc.Status, error, *httptest.ResponseRecorder) {
	t.Helper()

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/v1/authorize", nil)
	status, err := testPolicy(t).Authenticate(recorder, request, session, &goidc.Client{ID: "console"})
	return status, err, recorder
}

// TestLoginPolicy_RedirectsOnTheFirstPass covers the handoff. The policy never
// reads a login session, so it sends the browser to the login UI and suspends
// the request.
func TestLoginPolicy_RedirectsOnTheFirstPass(t *testing.T) {
	status, err, recorder := runPolicy(t, pending("session-1"))
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if status != goidc.StatusPending {
		t.Errorf("the status is %q, want %q", status, goidc.StatusPending)
	}

	want := "https://login.example.com/identifier?authRequest=session-1"
	if got := recorder.Header().Get("Location"); got != want {
		t.Errorf("the browser is sent to %q, want %q", got, want)
	}
}

// TestLoginPolicy_SucceedsWithASubject covers the resume pass. The finalize
// step named the person, so the request succeeds.
func TestLoginPolicy_SucceedsWithASubject(t *testing.T) {
	session := pending("session-1")
	session.Subject = "user-1"

	status, err, recorder := runPolicy(t, session)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if status != goidc.StatusSuccess {
		t.Errorf("the status is %q, want %q", status, goidc.StatusSuccess)
	}
	if recorder.Code != http.StatusOK {
		t.Errorf("the policy answered %d, want no answer of its own", recorder.Code)
	}
}

// TestLoginPolicy_FailsOnTheMarker covers the silent request that nobody could
// complete. The marker is the answer, and the client learns login_required.
func TestLoginPolicy_FailsOnTheMarker(t *testing.T) {
	session := pending("session-1")
	session.Store = map[string]any{storeErrorKey: string(goidc.ErrorCodeLoginRequired)}

	status, err, _ := runPolicy(t, session)
	if status != goidc.StatusFailure {
		t.Errorf("the status is %q, want %q", status, goidc.StatusFailure)
	}

	var oidcErr goidc.Error
	if !errors.As(err, &oidcErr) {
		t.Fatalf("authenticate gave %v, want a protocol error", err)
	}
	if oidcErr.Code != goidc.ErrorCodeLoginRequired {
		t.Errorf("the error code is %q, want %q", oidcErr.Code, goidc.ErrorCodeLoginRequired)
	}
}
