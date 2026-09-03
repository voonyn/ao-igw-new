package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/oidc"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/user"
)

// store is the database seam of the service, held in memory. It records what
// the service wrote, so a test reads the row the database would have held.
type store struct {
	saved     LoginSession
	savedHash string
	prevHash  string

	terminated []string

	events   []audit.Event
	auditErr error
}

func (s *store) Save(_ context.Context, live LoginSession, tokenHash, prevTokenHash string) error {
	s.saved, s.savedHash, s.prevHash = live, tokenHash, prevTokenHash
	return nil
}

func (s *store) Find(_ context.Context, tenantID, tokenHash string) (LoginSession, error) {
	if s.savedHash == "" || s.savedHash != tokenHash || s.saved.TenantID != tenantID {
		return LoginSession{}, ErrLoginSessionNotFound
	}
	return s.saved, nil
}

// Terminate is the sign-out seam. It records the login sessions the service
// ended, and it misses every id the store never saved.
func (s *store) Terminate(_ context.Context, tenantID, sessionID string) error {
	if s.saved.TenantID != tenantID || s.saved.ID != sessionID {
		return ErrLoginSessionNotFound
	}
	s.terminated = append(s.terminated, sessionID)
	return nil
}

// Write is the audit seam. A test reads the trail the transaction would have
// held, and auditErr makes the write fail.
func (s *store) Write(_ context.Context, event audit.Event) error {
	if s.auditErr != nil {
		return s.auditErr
	}
	s.events = append(s.events, event)
	return nil
}

// actions names every action the store recorded, in order.
func (s *store) actions() []string {
	names := make([]string, 0, len(s.events))
	for _, event := range s.events {
		names = append(names, event.Action)
	}
	return names
}

// knownPerson answers the identifier of one person and misses every other.
func knownPerson(identifier string, person Identity) IdentityFinder {
	return func(_ context.Context, _, wanted string) (Identity, error) {
		if wanted != identifier {
			return Identity{}, user.ErrNotFound
		}
		return person, nil
	}
}

// noProvider is the resolution seam of a test about the local password. No
// directory proves the sign-in, so the bcrypt compare answers it.
func noProvider(context.Context, string, string, string, string) (string, error) {
	return "", nil
}

// noBind is the bind seam of a test about the local password. No login session
// of such a test names a directory, so the seam is never called.
func noBind(context.Context, string, string, string, string, string) (Identity, error) {
	return Identity{}, errors.New("the bind seam of a local password test was called")
}

// boundAs is a bind seam that accepts the password and answers one person, with
// the email address of the directory entry. It is the seam of a test about what
// the sign-in does with the answer, and not about the bind itself.
func boundAs(userID, email string) Binder {
	return func(_ context.Context, _, _, _, _, _ string) (Identity, error) {
		return Identity{UserID: userID, Email: email}, nil
	}
}

// refusedBind is a bind seam that refuses with one sentinel.
func refusedBind(answer error) Binder {
	return func(_ context.Context, _, _, _, _, _ string) (Identity, error) {
		return Identity{}, answer
	}
}

// noCredential is the credential seam of a test that never reaches the password
// step.
func noCredential(context.Context, string, string) (string, error) {
	return "", user.ErrNotFound
}

// noSteps is the step seam of a test about the password itself. The person owes
// no factor, so the password step finishes the sign-in.
func noSteps(context.Context, string, string) ([]string, error) {
	return nil, nil
}

// runNow stands in for the transaction manager. The test has no database, so
// the work runs on the caller's context.
func runNow(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func testService(t *testing.T, identity IdentityFinder) (*Service, *store) {
	t.Helper()
	return testServiceWith(t, identity, noCredential)
}

func testServiceWith(t *testing.T, identity IdentityFinder, credential CredentialFinder) (*Service, *store) {
	t.Helper()
	return testServiceResolving(t, identity, credential, noProvider)
}

func testServiceResolving(
	t *testing.T, identity IdentityFinder, credential CredentialFinder, provider ProviderResolver,
) (*Service, *store) {
	t.Helper()
	return testServiceBinding(t, identity, credential, provider, noBind)
}

func testServiceBinding(
	t *testing.T, identity IdentityFinder, credential CredentialFinder,
	provider ProviderResolver, bind Binder,
) (*Service, *store) {
	t.Helper()

	log, _ := logger.NewObserved()
	st := &store{}
	svc := NewService(Deps{
		Identity:   identity,
		Provider:   provider,
		Bind:       bind,
		Credential: credential,
		Steps:      noSteps,
		Save:       st.Save,
		Find:       st.Find,
		Terminate:  st.Terminate,
		InTx:       runNow,
		Audit:      audit.NewRecorder(st.Write, log),
		Log:        log,
	})
	return svc, st
}

// signedIn runs the identifier step for one person and returns the token that
// credentials the partial session it opened.
func signedIn(t *testing.T, svc *Service, identifier string) Opened {
	t.Helper()

	opened, err := svc.Identify(context.Background(), "tenant-1", identifier, "203.0.113.7", "a-browser")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	return opened
}

// TestLogout covers the account side of a sign-out. The token names the login
// session, the session ends, and the trail records the sign-out.
func TestLogout(t *testing.T) {
	person := Identity{UserID: "user-1", Email: "person@example.com"}
	svc, st := testService(t, knownPerson("person@example.com", person))
	opened := signedIn(t, svc, "person@example.com")

	if err := svc.Logout(context.Background(), "tenant-1", opened.Token); err != nil {
		t.Fatalf("logout: %v", err)
	}

	if len(st.terminated) != 1 || st.terminated[0] != opened.ID {
		t.Errorf("terminated sessions are %v, want [%s]", st.terminated, opened.ID)
	}
	if got := st.actions(); len(got) != 1 || got[0] != string(audit.ActionLogoutSucceeded) {
		t.Errorf("the trail holds %v, want [%s]", got, audit.ActionLogoutSucceeded)
	}
}

// TestLogout_UnknownToken covers a token no live session carries. Nothing is
// terminated, and the trail records nothing.
func TestLogout_UnknownToken(t *testing.T) {
	person := Identity{UserID: "user-1", Email: "person@example.com"}
	svc, st := testService(t, knownPerson("person@example.com", person))
	signedIn(t, svc, "person@example.com")

	err := svc.Logout(context.Background(), "tenant-1", "a-dead-token")
	if !errors.Is(err, ErrLoginSessionNotFound) {
		t.Fatalf("logout answered %v, want %v", err, ErrLoginSessionNotFound)
	}
	if len(st.terminated) != 0 {
		t.Errorf("terminated sessions are %v, want none", st.terminated)
	}
	if got := st.actions(); len(got) != 0 {
		t.Errorf("the trail holds %v, want nothing", got)
	}
}

// TestTerminateByID covers the sign-out the protocol side drives. The session
// ends, and no audit row is written here: the logout policy records the
// sign-out itself, because only it knows the client that asked.
func TestTerminateByID(t *testing.T) {
	person := Identity{UserID: "user-1", Email: "person@example.com"}
	svc, st := testService(t, knownPerson("person@example.com", person))
	opened := signedIn(t, svc, "person@example.com")

	if err := svc.TerminateByID(context.Background(), "tenant-1", opened.ID); err != nil {
		t.Fatalf("terminate: %v", err)
	}

	if len(st.terminated) != 1 || st.terminated[0] != opened.ID {
		t.Errorf("terminated sessions are %v, want [%s]", st.terminated, opened.ID)
	}
	if got := st.actions(); len(got) != 0 {
		t.Errorf("the trail holds %v, want nothing", got)
	}
}

// TestIdentify covers the identifier step of a person the tenant holds: the
// session carries the person, and the token is handed out once.
func TestIdentify(t *testing.T) {
	person := Identity{UserID: "user-1", Email: "person@example.com"}
	svc, st := testService(t, knownPerson("person@example.com", person))

	opened, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "203.0.113.7", "a-browser")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}

	if opened.ID != st.saved.ID {
		t.Errorf("the opened id is %q, want the saved session id %q", opened.ID, st.saved.ID)
	}
	if opened.Token == "" {
		t.Fatal("identify handed out no token")
	}
	if st.saved.UserID != "user-1" || st.saved.Email != "person@example.com" {
		t.Errorf("the saved session is %+v, want the person it names", st.saved)
	}
	if st.saved.Authenticated() {
		t.Error("the identifier step opened an authenticated session, want a partial one")
	}
}

// TestIdentify_StoresOnlyTheDigest covers the credential rule: the row holds the
// digest of the token, and never the token.
func TestIdentify_StoresOnlyTheDigest(t *testing.T) {
	svc, st := testService(t, knownPerson("person@example.com", Identity{UserID: "user-1"}))

	opened, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", "")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}

	if st.savedHash == opened.Token {
		t.Fatal("the stored value is the token itself")
	}
	if st.savedHash != aocrypto.Digest(opened.Token) {
		t.Errorf("the stored value is %q, want the digest of the token", st.savedHash)
	}
}

// TestIdentify_UnknownIdentifier covers user enumeration. An identifier nobody
// holds opens a session too, so the answer looks the same either way. The
// session names no person.
func TestIdentify_UnknownIdentifier(t *testing.T) {
	svc, st := testService(t, knownPerson("person@example.com", Identity{UserID: "user-1"}))

	opened, err := svc.Identify(context.Background(), "tenant-1", "nobody@example.com", "", "")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}

	if opened.ID == "" || opened.Token == "" {
		t.Fatal("an unknown identifier opened no session")
	}
	if st.saved.UserID != "" || st.saved.Email != "" {
		t.Errorf("the saved session is %+v, want no person named", st.saved)
	}
}

// TestIdentify_ReadFails covers a broken database. A read that is not a miss
// stops the request, because the session would otherwise name the wrong person.
func TestIdentify_ReadFails(t *testing.T) {
	boom := errors.New("the database is down")
	svc, _ := testService(t, func(context.Context, string, string) (Identity, error) {
		return Identity{}, boom
	})

	if _, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", ""); !errors.Is(err, boom) {
		t.Errorf("identify gave %v, want %v", err, boom)
	}
}

// TestIdentify_RecordsTheResolvedProvider proves that the identifier step writes
// the Identity Provider onto the login session. The password step reads it there,
// so the resolution runs once and no later step resolves again.
func TestIdentify_RecordsTheResolvedProvider(t *testing.T) {
	const idpID = "idp-1"
	svc, st := testServiceResolving(t,
		knownPerson("person@example.com", Identity{UserID: "user-1"}), noCredential,
		func(context.Context, string, string, string, string) (string, error) { return idpID, nil })

	if _, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", ""); err != nil {
		t.Fatalf("identify: %v", err)
	}
	if st.saved.IdpID != idpID {
		t.Errorf("the saved session names %q, want %q", st.saved.IdpID, idpID)
	}
}

// TestIdentify_NamesTheEmailOfThePerson proves that the identifier step hands
// the resolver both forms of the person. The identifier step accepts a username,
// and a domain claim read from the typed form alone is stepped around by typing
// one. See internal/identityprovider/resolve.go.
func TestIdentify_NamesTheEmailOfThePerson(t *testing.T) {
	var gotIdentifier, gotEmail string
	svc, _ := testServiceResolving(t,
		knownPerson("ada", Identity{UserID: "user-1", Email: "ada@corp.example"}), noCredential,
		func(_ context.Context, _, _, identifier, email string) (string, error) {
			gotIdentifier, gotEmail = identifier, email
			return "", nil
		})

	if _, err := svc.Identify(context.Background(), "tenant-1", "ada", "", ""); err != nil {
		t.Fatalf("identify: %v", err)
	}
	if gotIdentifier != "ada" || gotEmail != "ada@corp.example" {
		t.Errorf("the resolver read %q and %q, want the typed form and the email of the person",
			gotIdentifier, gotEmail)
	}
}

// TestIdentify_ResolutionFails covers a resolution that broke. It stops the
// request, the way a broken read of the person does.
//
// The resolver answers an empty id for every case the local compare proves, and
// for both of its refusals, so an error here is a read that failed and never a
// person the tenant does not hold. A sign-in that carried on would fall back to a
// local password hash that a claimed domain took out of service.
func TestIdentify_ResolutionFails(t *testing.T) {
	boom := errors.New("the database is down")
	svc, st := testServiceResolving(t,
		knownPerson("person@example.com", Identity{UserID: "user-1"}), noCredential,
		func(context.Context, string, string, string, string) (string, error) { return "", boom })

	if _, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", ""); !errors.Is(err, boom) {
		t.Fatalf("identify gave %v, want %v", err, boom)
	}
	if st.savedHash != "" {
		t.Error("a failed resolution saved a login session")
	}
}

// TestOpen_NamesNoProvider covers the flow that learns the person later. QR Login
// opens a session before anybody has typed an identifier, so there is nothing to
// resolve a directory from.
func TestOpen_NamesNoProvider(t *testing.T) {
	svc, st := testServiceResolving(t,
		knownPerson("person@example.com", Identity{UserID: "user-1"}), noCredential,
		func(context.Context, string, string, string, string) (string, error) {
			t.Error("Open resolved an identity provider")
			return "idp-1", nil
		})

	if _, err := svc.Open(context.Background(), "tenant-1", "", ""); err != nil {
		t.Fatalf("open: %v", err)
	}
	if st.saved.IdpID != "" {
		t.Errorf("the saved session names %q, want no provider", st.saved.IdpID)
	}
}

// passwordService builds a service where one person holds one password. The
// hash is computed once, because bcrypt is deliberately slow.
func passwordService(t *testing.T, password string) (*Service, *store) {
	t.Helper()

	hash, err := aocrypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	person := Identity{UserID: "user-1", Email: "person@example.com"}
	return testServiceWith(t, knownPerson("person@example.com", person),
		func(_ context.Context, _, userID string) (string, error) {
			if userID != "user-1" {
				return "", user.ErrNotFound
			}
			return hash, nil
		})
}

// TestVerifyPassword covers the password step of a person who typed the right
// password: the session gains the pwd factor, its lifetime grows, and its token
// rotates.
func TestVerifyPassword(t *testing.T) {
	svc, st := passwordService(t, "a-correct-password")
	opened := signedIn(t, svc, "person@example.com")
	partialExpiry := st.saved.ExpiresAt

	upgraded, _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if upgraded.ID != opened.ID {
		t.Errorf("the upgraded id is %q, want the same session %q", upgraded.ID, opened.ID)
	}
	if upgraded.Token == opened.Token {
		t.Error("the password step handed back the same token, want a rotated one")
	}
	if st.savedHash != aocrypto.Digest(upgraded.Token) {
		t.Error("the stored digest does not match the token the caller received")
	}
	if !st.saved.Authenticated() {
		t.Error("the upgraded session carries no factor")
	}
	if _, ok := st.saved.Factors[FactorPassword]; !ok {
		t.Errorf("the factors are %v, want the pwd factor", st.saved.Factors)
	}
	if !st.saved.ExpiresAt.After(partialExpiry) {
		t.Error("the password step did not extend the lifetime of the session")
	}
	// The cache drops the old digest from this value. Without it, the token the
	// person presented here keeps answering until its TTL runs out.
	if st.prevHash != aocrypto.Digest(opened.Token) {
		t.Error("the rotation did not name the digest it replaced")
	}
}

// TestVerifyPassword_RotatedTokenResolves covers the rotation from the reader's
// side: the new token names the session, and the old one is dead.
func TestVerifyPassword_RotatedTokenResolves(t *testing.T) {
	svc, _ := passwordService(t, "a-correct-password")
	opened := signedIn(t, svc, "person@example.com")

	upgraded, _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if _, err := svc.Resolve(context.Background(), "tenant-1", upgraded.Token); err != nil {
		t.Errorf("the rotated token gave %v, want a live session", err)
	}
	if _, err := svc.Resolve(context.Background(), "tenant-1", opened.Token); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("the old token gave %v, want %v", err, ErrLoginSessionNotFound)
	}
}

// TestVerifyPassword_RecordsTheOutcome covers the audit trail. A sign-in is
// recorded, and the row names the person and never the password.
func TestVerifyPassword_RecordsTheOutcome(t *testing.T) {
	svc, st := passwordService(t, "a-correct-password")
	opened := signedIn(t, svc, "person@example.com")

	if _, _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password"); err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if len(st.events) != 1 {
		t.Fatalf("the trail holds %v, want one login.succeeded", st.actions())
	}
	event := st.events[0]
	if event.Action != string(audit.ActionLoginSucceeded) {
		t.Errorf("the trail holds %q, want %q", event.Action, audit.ActionLoginSucceeded)
	}
	if event.ActorID != "user-1" || event.EntityID != opened.ID {
		t.Errorf("the row names actor %q and entity %q, want the person and the session", event.ActorID, event.EntityID)
	}
}

// TestVerifyPassword_WrongPassword covers a wrong password: the caller learns
// nothing beyond the refusal, the session stays partial, and the failure is
// recorded.
func TestVerifyPassword_WrongPassword(t *testing.T) {
	svc, st := passwordService(t, "a-correct-password")
	opened := signedIn(t, svc, "person@example.com")

	_, _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "the-wrong-password")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("verify password gave %v, want %v", err, ErrBadCredentials)
	}
	if st.saved.Authenticated() {
		t.Error("a wrong password upgraded the session")
	}
	if len(st.events) != 1 || st.events[0].Action != string(audit.ActionLoginFailed) {
		t.Errorf("the trail holds %v, want one login.failed", st.actions())
	}
}

// TestVerifyPassword_UnknownPerson covers user enumeration at the password
// step. The identifier step opened a session that names nobody, and the answer
// is the same refusal a wrong password gets.
func TestVerifyPassword_UnknownPerson(t *testing.T) {
	svc, st := passwordService(t, "a-correct-password")
	opened := signedIn(t, svc, "nobody@example.com")

	_, _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("verify password gave %v, want %v", err, ErrBadCredentials)
	}
	if st.saved.Authenticated() {
		t.Error("a session that names nobody was upgraded")
	}
}

// TestVerifyPassword_DeadToken covers a token no live session carries.
func TestVerifyPassword_DeadToken(t *testing.T) {
	svc, _ := passwordService(t, "a-correct-password")

	_, _, err := svc.VerifyPassword(context.Background(), "tenant-1", "not-a-token", "a-correct-password")
	if !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("verify password gave %v, want %v", err, ErrLoginSessionNotFound)
	}
}

// TestVerifyPassword_AuditFails covers the audit rule: a sign-in nobody can
// audit is not allowed to stand, so the failed write fails the step.
func TestVerifyPassword_AuditFails(t *testing.T) {
	svc, st := passwordService(t, "a-correct-password")
	opened := signedIn(t, svc, "person@example.com")
	st.auditErr = errors.New("the trail is unwritable")

	if _, _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password"); err == nil {
		t.Fatal("verify password succeeded with an unwritable audit trail")
	}
}

// TestAuthTime covers what an authorization request measures prompt=login and
// max_age against: the moment of the newest factor.
func TestAuthTime(t *testing.T) {
	older := time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC)
	live := LoginSession{Factors: map[string]time.Time{"otp": older, FactorPassword: newer}}

	if got := live.AuthTime(); !got.Equal(newer) {
		t.Errorf("the auth time is %v, want %v", got, newer)
	}
	if got := (LoginSession{}).AuthTime(); !got.IsZero() {
		t.Errorf("a partial session gave %v, want the zero time", got)
	}
}

// TestResolve covers the signed-in check: a session that carries a factor
// resolves, and the caller learns the email it holds.
func TestResolve(t *testing.T) {
	svc, st := testService(t, knownPerson("person@example.com", Identity{UserID: "user-1", Email: "person@example.com"}))

	opened, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", "")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	st.saved.Factors = map[string]time.Time{FactorPassword: time.Now().UTC()}

	live, err := svc.Resolve(context.Background(), "tenant-1", opened.Token)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if live.Email != "person@example.com" {
		t.Errorf("the resolved session holds %q, want the email of the person", live.Email)
	}
}

// TestResolve_PartialSession covers the session the identifier step leaves
// behind. It carries no factor, so it is not a signed-in person.
func TestResolve_PartialSession(t *testing.T) {
	svc, _ := testService(t, knownPerson("person@example.com", Identity{UserID: "user-1"}))

	opened, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", "")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}

	if _, err := svc.Resolve(context.Background(), "tenant-1", opened.Token); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("resolve gave %v, want %v", err, ErrNotAuthenticated)
	}
}

// TestResolve_UnknownToken covers a token no session carries.
func TestResolve_UnknownToken(t *testing.T) {
	svc, _ := testService(t, knownPerson("person@example.com", Identity{UserID: "user-1"}))

	if _, err := svc.Resolve(context.Background(), "tenant-1", "not-a-token"); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("resolve gave %v, want %v", err, ErrLoginSessionNotFound)
	}
}

// TestResolve_OtherTenant covers tenant isolation. The token digest is unique
// across the whole table, so the tenant of the request must match the tenant of
// the session.
func TestResolve_OtherTenant(t *testing.T) {
	svc, _ := testService(t, knownPerson("person@example.com", Identity{UserID: "user-1"}))

	opened, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", "")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}

	if _, err := svc.Resolve(context.Background(), "tenant-2", opened.Token); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("resolve gave %v, want %v", err, ErrLoginSessionNotFound)
	}
}

// TestVerifyPassword_NamesTheFactorStillOwed covers the step signal. The answer
// carries what the seam named, so the sign-in front end knows which step is next.
func TestVerifyPassword_NamesTheFactorStillOwed(t *testing.T) {
	svc, _ := passwordService(t, "a-correct-password")
	svc.deps.Steps = func(context.Context, string, string) ([]string, error) {
		return []string{StepEnrolOTP}, nil
	}
	opened := signedIn(t, svc, "person@example.com")

	_, steps, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "a-correct-password")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if len(steps) != 1 || steps[0] != StepEnrolOTP {
		t.Errorf("the steps are %v, want %v", steps, []string{StepEnrolOTP})
	}
}

// TestVerifyPassword_StepsUnreadable covers the fail-closed rule. A requirement
// nobody could read must never read as "no factor is owed", so the step fails and
// the session is not upgraded.
func TestVerifyPassword_StepsUnreadable(t *testing.T) {
	svc, st := passwordService(t, "a-correct-password")
	svc.deps.Steps = func(context.Context, string, string) ([]string, error) {
		return nil, errors.New("the policy could not be read")
	}
	opened := signedIn(t, svc, "person@example.com")

	if _, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "a-correct-password"); err == nil {
		t.Fatal("the password step succeeded with an unreadable requirement")
	}
	if st.saved.Authenticated() {
		t.Error("the session was upgraded although the requirement could not be read")
	}
}

// finalizeService is a service whose step seam names one fixed list, and one
// live session in the state the caller describes. It is the setup every gate
// test below shares.
func finalizeService(
	t *testing.T, owed []string, proved map[string]time.Time,
) (*Service, string) {
	t.Helper()

	svc, st := testService(t, knownPerson("person@example.com", Identity{UserID: "user-1"}))
	svc.deps.Steps = func(context.Context, string, string) ([]string, error) {
		return owed, nil
	}

	opened, err := svc.Identify(context.Background(), "tenant-1", "person@example.com", "", "")
	if err != nil {
		t.Fatalf("identify: %v", err)
	}
	st.saved.Factors = proved
	return svc, opened.Token
}

// TestResolveForFinalize covers the sign-in that owes nothing. The gate reads
// the same session Resolve does.
func TestResolveForFinalize(t *testing.T) {
	svc, token := finalizeService(t, nil, map[string]time.Time{FactorPassword: time.Now().UTC()})

	live, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if err != nil {
		t.Fatalf("resolve for finalize: %v", err)
	}
	if live.UserID != "user-1" {
		t.Errorf("the resolved session names %q, want %q", live.UserID, "user-1")
	}
}

// TestResolveForFinalize_OwedFactor covers the gate. The person proved a
// password and skipped the challenge, so the finalize step refuses them.
func TestResolveForFinalize_OwedFactor(t *testing.T) {
	svc, token := finalizeService(t,
		[]string{FactorOTP}, map[string]time.Time{FactorPassword: time.Now().UTC()})

	_, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if !errors.Is(err, ErrInsufficientFactors) {
		t.Errorf("resolve for finalize gave %v, want %v", err, ErrInsufficientFactors)
	}
}

// TestResolveForFinalize_OwedEnrolment covers the person the requirement
// governs who holds no factor. A step signal is not an AMR name, so nothing on
// the session can ever answer it, and skipping enrolment is refused.
func TestResolveForFinalize_OwedEnrolment(t *testing.T) {
	svc, token := finalizeService(t,
		[]string{StepEnrolOTP}, map[string]time.Time{FactorPassword: time.Now().UTC()})

	_, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if !errors.Is(err, ErrInsufficientFactors) {
		t.Errorf("resolve for finalize gave %v, want %v", err, ErrInsufficientFactors)
	}
}

// TestResolveForFinalize_EnrolmentIsMatchedWhole covers the gate reading an
// enrolment step by its exact name.
//
// The two Passkey steps differ by a suffix, and a challenge step is met by any
// proved Second Factor. A gate that matched on a prefix would therefore let a
// person who owes webauthn_enroll through on a Passkey the account does not
// hold yet, which is the whole demand the requirement makes of them.
func TestResolveForFinalize_EnrolmentIsMatchedWhole(t *testing.T) {
	now := time.Now().UTC()
	svc, token := finalizeService(t, []string{StepEnrolPasskey, StepEnrolOTP},
		map[string]time.Time{FactorPassword: now, FactorPasskey: now})

	_, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if !errors.Is(err, ErrInsufficientFactors) {
		t.Errorf("resolve for finalize gave %v, want %v", err, ErrInsufficientFactors)
	}
}

// TestResolveForFinalize_ProvedFactor covers the person who answered the
// challenge. The seam still names the factor, because the account still holds
// it, and the session says the demand was answered.
func TestResolveForFinalize_ProvedFactor(t *testing.T) {
	now := time.Now().UTC()
	svc, token := finalizeService(t, []string{FactorOTP},
		map[string]time.Time{FactorPassword: now, FactorOTP: now})

	if _, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token); err != nil {
		t.Fatalf("resolve for finalize: %v", err)
	}
}

// TestResolveForFinalize_ScanIsExempt covers the QR Login. A Wallet
// presentation is a possession factor already, and the poll answers three fixed
// states with no room to name a step still owed.
func TestResolveForFinalize_ScanIsExempt(t *testing.T) {
	svc, token := finalizeService(t,
		[]string{FactorOTP}, map[string]time.Time{FactorScan: time.Now().UTC()})

	if _, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token); err != nil {
		t.Fatalf("resolve for finalize: %v", err)
	}
}

// TestResolveForFinalize_StepsUnreadable covers the fail-closed rule. A
// requirement nobody could read must never read as "no factor is owed".
func TestResolveForFinalize_StepsUnreadable(t *testing.T) {
	svc, token := finalizeService(t, nil, map[string]time.Time{FactorPassword: time.Now().UTC()})
	svc.deps.Steps = func(context.Context, string, string) ([]string, error) {
		return nil, errors.New("the policy could not be read")
	}

	if _, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token); err == nil {
		t.Fatal("the finalize step succeeded with an unreadable requirement")
	}
}

// TestResolveForFinalize_PartialSession covers the session the identifier step
// leaves behind. It proved nothing, so the answer is the one that restarts the
// sign-in and never the one that resumes it.
func TestResolveForFinalize_PartialSession(t *testing.T) {
	svc, token := finalizeService(t, []string{FactorOTP}, nil)

	_, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("resolve for finalize gave %v, want %v", err, ErrNotAuthenticated)
	}
}

// TestResolveForFinalize_TwoChallengeSteps covers the person who is offered two
// Second Factors. Both challenge steps are owed, the person proves one of them,
// and the gate passes. A gate that demanded both would refuse a sign-in that is
// complete. See docs/adr/0012-passkey-amr-value.md.
func TestResolveForFinalize_TwoChallengeSteps(t *testing.T) {
	now := time.Now().UTC()
	svc, token := finalizeService(t, []string{StepChallengePasskey, StepChallengeOTP},
		map[string]time.Time{FactorPassword: now, FactorOTP: now})

	if _, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token); err != nil {
		t.Fatalf("resolve for finalize: %v", err)
	}
}

// TestResolveForFinalize_TwoChallengeStepsPasswordOnly covers the same list with
// no Second Factor proved. Any Second Factor meets a challenge step, and the
// password is not one, so the sign-in is refused.
func TestResolveForFinalize_TwoChallengeStepsPasswordOnly(t *testing.T) {
	svc, token := finalizeService(t, []string{StepChallengePasskey, StepChallengeOTP},
		map[string]time.Time{FactorPassword: time.Now().UTC()})

	_, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if !errors.Is(err, ErrInsufficientFactors) {
		t.Errorf("resolve for finalize gave %v, want %v", err, ErrInsufficientFactors)
	}
}

// TestResolveForFinalize_EnrolmentTakesNoSubstitute covers the enrolment step
// beside a proved Second Factor. A person who owes enrolment proved nothing of
// that step, so another factor never answers it.
func TestResolveForFinalize_EnrolmentTakesNoSubstitute(t *testing.T) {
	now := time.Now().UTC()
	svc, token := finalizeService(t, []string{StepEnrolPasskey},
		map[string]time.Time{FactorPassword: now, FactorOTP: now})

	_, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if !errors.Is(err, ErrInsufficientFactors) {
		t.Errorf("resolve for finalize gave %v, want %v", err, ErrInsufficientFactors)
	}
}

// TestResolveForFinalize_UnknownStepIsRefused covers the step this build cannot
// classify. A gate that took an unknown step for a challenge would sign the
// person in on a factor that answers something else, so it refuses instead.
func TestResolveForFinalize_UnknownStepIsRefused(t *testing.T) {
	now := time.Now().UTC()
	svc, token := finalizeService(t, []string{"webauthn_enrollment"},
		map[string]time.Time{FactorPassword: now, FactorOTP: now})

	_, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token)
	if !errors.Is(err, ErrInsufficientFactors) {
		t.Errorf("resolve for finalize gave %v, want %v", err, ErrInsufficientFactors)
	}
}

// TestResolveForFinalize_PasskeyMeetsTheOTPChallenge covers the person who holds
// both Second Factors and answers the passkey challenge. The TOTP step is still
// owed, and the Passkey answers it.
func TestResolveForFinalize_PasskeyMeetsTheOTPChallenge(t *testing.T) {
	now := time.Now().UTC()
	svc, token := finalizeService(t, []string{StepChallengeOTP},
		map[string]time.Time{FactorPassword: now, FactorPasskey: now})

	if _, err := svc.ResolveForFinalize(context.Background(), "tenant-1", token); err != nil {
		t.Fatalf("resolve for finalize: %v", err)
	}
}

// TestFailSecondFactor covers the per-session cap on code guessing. The codes
// before the last one are counted and nothing else happens. The last one ends
// the session and records one login.failed naming a wrong second factor.
//
// Six digits is a million values, so a sign-in that never ends is a sign-in an
// attacker can guess through.
func TestFailSecondFactor(t *testing.T) {
	person := Identity{UserID: "user-1", Email: "person@example.com"}
	svc, st := testService(t, knownPerson("person@example.com", person))
	opened := signedIn(t, svc, "person@example.com")

	for wrong := 1; wrong < maxWrongCodes; wrong++ {
		ended, err := svc.FailSecondFactor(context.Background(), "tenant-1", opened.Token)
		if err != nil {
			t.Fatalf("wrong code %d: %v", wrong, err)
		}
		if ended {
			t.Fatalf("wrong code %d ended the sign-in, want %d codes", wrong, maxWrongCodes)
		}
		if st.saved.WrongCodes != wrong {
			t.Errorf("the session counted %d wrong codes, want %d", st.saved.WrongCodes, wrong)
		}
	}

	// Nothing is recorded until the sign-in ends. One refused sign-in is one
	// audit row, not five.
	if got := st.actions(); len(got) != 0 {
		t.Fatalf("the trail holds %v before the cap, want nothing", got)
	}

	ended, err := svc.FailSecondFactor(context.Background(), "tenant-1", opened.Token)
	if err != nil {
		t.Fatalf("the last wrong code: %v", err)
	}
	if !ended {
		t.Fatalf("%d wrong codes did not end the sign-in", maxWrongCodes)
	}
	if len(st.terminated) != 1 || st.terminated[0] != opened.ID {
		t.Errorf("terminated sessions are %v, want [%s]", st.terminated, opened.ID)
	}
	if got := st.actions(); len(got) != 1 || got[0] != string(audit.ActionLoginFailed) {
		t.Fatalf("the trail holds %v, want [%s]", got, audit.ActionLoginFailed)
	}
	// The trail says which credential failed. A reader who cannot tell a wrong
	// password from a wrong code cannot tell a guessed account from a stolen one.
	if reason := st.events[0].Metadata; !strings.Contains(reason, "bad_second_factor") {
		t.Errorf("the event metadata is %q, want a wrong second factor", reason)
	}
}

// TestFailSecondFactor_DeadToken covers a token no live session carries. Nothing
// is counted, nothing is terminated, and the trail records nothing.
func TestFailSecondFactor_DeadToken(t *testing.T) {
	person := Identity{UserID: "user-1", Email: "person@example.com"}
	svc, st := testService(t, knownPerson("person@example.com", person))
	signedIn(t, svc, "person@example.com")

	_, err := svc.FailSecondFactor(context.Background(), "tenant-1", "a-dead-token")
	if !errors.Is(err, ErrLoginSessionNotFound) {
		t.Fatalf("the wrong code answered %v, want %v", err, ErrLoginSessionNotFound)
	}
	if len(st.terminated) != 0 || len(st.actions()) != 0 {
		t.Errorf("a dead token terminated %v and recorded %v", st.terminated, st.actions())
	}
}

// TestFactorNames covers what the amr claim of the ID token is built from. The
// names are sorted, so every token minted from one sign-in carries the same
// claim, whatever order the map is read in.
func TestFactorNames(t *testing.T) {
	proved := LoginSession{Factors: map[string]time.Time{
		FactorOTP:      time.Now(),
		FactorPassword: time.Now(),
	}}

	if got := proved.FactorNames(); !reflect.DeepEqual(got, []string{FactorOTP, FactorPassword}) {
		t.Errorf("the factors read %v, want %v", got, []string{FactorOTP, FactorPassword})
	}
	if got := (LoginSession{}).FactorNames(); len(got) != 0 {
		t.Errorf("a session with no factor reads %v, want none", got)
	}
}

// The fixtures of the directory sign-in tests. The person holds a local row and
// the login session names the directory that proves their password.
const (
	directoryIdp        = "77777777-7777-7777-7777-777777777777"
	directoryIdentifier = "alice@corp.example"
)

// signedInAgainst runs the identifier step of a person one directory proves, and
// returns the token that credentials the partial session it opened.
func signedInAgainst(t *testing.T, svc *Service) Opened {
	t.Helper()
	return signedIn(t, svc, directoryIdentifier)
}

// directoryService builds a service whose identifier step resolves one directory
// for one person the tenant already holds. bind is what the directory answers.
func directoryService(t *testing.T, bind Binder) (*Service, *store) {
	t.Helper()

	person := Identity{UserID: "user-1", Email: directoryIdentifier}
	return testServiceBinding(t,
		knownPerson(directoryIdentifier, person),
		// A person the directory owns holds no local hash. A bind that fell back
		// to this seam would read one, so the seam fails the test.
		func(context.Context, string, string) (string, error) {
			t.Error("the password step read a local password hash, want a bind")
			return "", user.ErrNotFound
		},
		func(context.Context, string, string, string, string) (string, error) { return directoryIdp, nil },
		bind)
}

// refusal names the reason and the provider one login.failed row carries.
func refusal(t *testing.T, st *store) string {
	t.Helper()

	if len(st.events) != 1 {
		t.Fatalf("the trail holds %v, want one row", st.actions())
	}
	if st.events[0].Action != string(audit.ActionLoginFailed) {
		t.Fatalf("the trail holds %s, want %s", st.events[0].Action, audit.ActionLoginFailed)
	}
	return st.events[0].Metadata
}

// TestVerifyPassword_Bind covers the password step of a person one directory
// proves. The bind takes the identifier the person typed, the session carries
// the pwd factor, and the token rotates, which is what a local password does.
func TestVerifyPassword_Bind(t *testing.T) {
	var got struct{ tenantID, idpID, userID, identifier, password string }
	svc, st := directoryService(t, func(
		_ context.Context, tenantID, idpID, userID, identifier, password string,
	) (Identity, error) {
		got.tenantID, got.idpID, got.userID = tenantID, idpID, userID
		got.identifier, got.password = identifier, password
		return Identity{UserID: userID, Email: directoryIdentifier}, nil
	})
	opened := signedInAgainst(t, svc)

	upgraded, steps, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if got.tenantID != "tenant-1" || got.idpID != directoryIdp {
		t.Errorf("the bind ran against %s of %s, want %s of tenant-1", got.idpID, got.tenantID, directoryIdp)
	}
	if got.identifier != directoryIdentifier {
		t.Errorf("the bind searched for %q, want %q", got.identifier, directoryIdentifier)
	}
	// The session already names the person, so the bind is told who they are and
	// creates nobody.
	if got.userID != "user-1" {
		t.Errorf("the bind was given the person %q, want user-1", got.userID)
	}
	if got.password != "the-directory-password" {
		t.Error("the bind was given a password other than the one the person typed")
	}
	if upgraded.Token == "" || upgraded.Token == opened.Token {
		t.Error("the token did not rotate")
	}
	if len(steps) != 0 {
		t.Errorf("the answer names %v, want no step owed", steps)
	}
	if _, proved := st.saved.Factors[FactorPassword]; !proved {
		t.Errorf("the session carries %v, want the %s factor", st.saved.Factors, FactorPassword)
	}
	if got := st.actions(); len(got) != 1 || got[0] != string(audit.ActionLoginSucceeded) {
		t.Errorf("the trail holds %v, want [%s]", got, audit.ActionLoginSucceeded)
	}
}

// TestVerifyPassword_BindTellsNobodyItWasADirectory covers the answer of a
// directory sign-in. The trail names the same action and the same factor a local
// password records, so nothing downstream learns which credential was proved.
func TestVerifyPassword_BindTellsNobodyItWasADirectory(t *testing.T) {
	svc, st := directoryService(t, boundAs("user-1", directoryIdentifier))
	opened := signedInAgainst(t, svc)

	if _, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password"); err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if len(st.events) != 1 {
		t.Fatalf("the trail holds %v, want one row", st.actions())
	}
	if strings.Contains(st.events[0].Metadata, "idp") {
		t.Errorf("the successful sign-in recorded %q, want the row a local password writes",
			st.events[0].Metadata)
	}
	if names := st.saved.FactorNames(); len(names) != 1 || names[0] != FactorPassword {
		t.Errorf("the session carries the factors %v, want [%s]", names, FactorPassword)
	}
}

// TestVerifyPassword_BindRefusalsAnswerAlike covers the one slug every bind
// failure answers. A wrong password, an entry the directory does not hold, and a
// search that matched twice must not be told apart.
func TestVerifyPassword_BindRefusalsAnswerAlike(t *testing.T) {
	for _, name := range []string{"a wrong password", "no such entry", "two entries"} {
		t.Run(name, func(t *testing.T) {
			svc, st := directoryService(t, refusedBind(ErrBadCredentials))
			opened := signedInAgainst(t, svc)

			_, _, err := svc.VerifyPassword(
				context.Background(), "tenant-1", opened.Token, "a-wrong-password")
			if !errors.Is(err, ErrBadCredentials) {
				t.Fatalf("err = %v, want ErrBadCredentials", err)
			}
			if !strings.Contains(refusal(t, st), `"reason":"bad_password"`) {
				t.Errorf("the trail recorded %q, want the bad password reason", st.events[0].Metadata)
			}
		})
	}
}

// TestVerifyPassword_RefusalsTakeTheSameTime is the enumeration test. Three
// refusals are measured, and the three must not be told apart:
//
//   - a wrong local password, which pays one bcrypt comparison,
//   - a wrong directory password, which pays two binds,
//   - an entry the directory does not hold, which pays one bind.
//
// Without the floor the three answer at three speeds, and account enumeration
// returns at the password step. Nothing in this suite asserted the property
// before this feature.
//
// It also guards the value of the floor. A floor below the cost of one bcrypt
// comparison would leave the local refusal the slow one, so a build that raised
// the bcrypt cost without raising the floor fails here.
func TestVerifyPassword_RefusalsTakeTheSameTime(t *testing.T) {
	took := func(t *testing.T, svc *Service, opened Opened) time.Duration {
		t.Helper()

		start := time.Now()
		if _, _, err := svc.VerifyPassword(
			context.Background(), "tenant-1", opened.Token, "a-wrong-password",
		); !errors.Is(err, ErrBadCredentials) {
			t.Fatalf("err = %v, want ErrBadCredentials", err)
		}
		return time.Since(start)
	}

	// The two costs a real directory pays. The wrong password runs the second
	// bind, and the unknown entry never reaches it.
	directory := func(t *testing.T, cost time.Duration) time.Duration {
		t.Helper()

		svc, _ := directoryService(t, func(
			_ context.Context, _, _, _, _, _ string,
		) (Identity, error) {
			time.Sleep(cost)
			return Identity{}, ErrBadCredentials
		})
		return took(t, svc, signedInAgainst(t, svc))
	}

	person := Identity{UserID: "user-1", Email: "person@example.com"}
	svc, _ := testServiceWith(t, knownPerson("person@example.com", person), noCredential)
	local := took(t, svc, signedIn(t, svc, "person@example.com"))

	missing := directory(t, 5*time.Millisecond)
	wrong := directory(t, 120*time.Millisecond)

	for name, took := range map[string]time.Duration{
		"a wrong local password": local, "an unknown entry": missing, "a wrong directory password": wrong,
	} {
		if took < passwordStepFloor {
			t.Fatalf("%s took %s, want at least the floor of %s", name, took, passwordStepFloor)
		}
	}

	// The margin is the scheduler of the machine the test runs on, and it is far
	// below the difference the floor hides.
	for _, gap := range []time.Duration{(wrong - missing).Abs(), (local - missing).Abs()} {
		if gap > 100*time.Millisecond {
			t.Fatalf("the refusals took %s, %s and %s, a gap of %s", local, missing, wrong, gap)
		}
	}
}

// TestVerifyPassword_DirectoryUnavailable covers a directory that did not
// answer. It is not a credential failure, so it carries a slug of its own, and
// the trail names the cause and the provider.
func TestVerifyPassword_DirectoryUnavailable(t *testing.T) {
	svc, st := directoryService(t, refusedBind(ErrDirectoryUnavailable))
	opened := signedInAgainst(t, svc)

	_, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("err = %v, want ErrDirectoryUnavailable", err)
	}
	if errors.Is(err, ErrBadCredentials) {
		t.Fatalf("err = %v, want a directory failure and not a credential failure", err)
	}

	metadata := refusal(t, st)
	if !strings.Contains(metadata, `"reason":"directory_unavailable"`) {
		t.Errorf("the trail recorded %q, want the directory reason", metadata)
	}
	if !strings.Contains(metadata, directoryIdp) {
		t.Errorf("the trail recorded %q, want the provider that refused", metadata)
	}
}

// TestVerifyPassword_DirectoryDisabled covers a provider a tenant switched off,
// and a soft-deleted one, which behave alike. The answer is the one an unknown
// identifier gets, and only the trail names the cause.
func TestVerifyPassword_DirectoryDisabled(t *testing.T) {
	svc, st := directoryService(t, refusedBind(ErrDirectoryDisabled))
	opened := signedInAgainst(t, svc)

	_, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if !errors.Is(err, ErrDirectoryDisabled) {
		t.Fatalf("err = %v, want ErrDirectoryDisabled", err)
	}
	if !strings.Contains(refusal(t, st), `"reason":"directory_disabled"`) {
		t.Errorf("the trail recorded %q, want the disabled reason", st.events[0].Metadata)
	}
}

// TestVerifyPassword_TooManyBinds covers the bind budget. The person waits out
// the window, and the trail records the refused sign-in.
func TestVerifyPassword_TooManyBinds(t *testing.T) {
	svc, st := directoryService(t, refusedBind(ErrTooManyBinds))
	opened := signedInAgainst(t, svc)

	_, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if !errors.Is(err, ErrTooManyBinds) {
		t.Fatalf("err = %v, want ErrTooManyBinds", err)
	}
	if !strings.Contains(refusal(t, st), `"reason":"too_many_binds"`) {
		t.Errorf("the trail recorded %q, want the budget reason", st.events[0].Metadata)
	}
}

// firstBindService builds a service whose identifier step names a directory and
// no person. It is the first sign-in of somebody this gateway holds no row for,
// and the bind is what creates them.
func firstBindService(t *testing.T, bind Binder) (*Service, *store) {
	t.Helper()

	return testServiceBinding(t,
		func(context.Context, string, string) (Identity, error) { return Identity{}, user.ErrNotFound },
		noCredential,
		func(context.Context, string, string, string, string) (string, error) { return directoryIdp, nil },
		bind)
}

// TestVerifyPassword_FirstBindCreatesThePerson covers the first successful bind
// of somebody this gateway holds no row for. The bind is told that the session
// names nobody, it answers the person it created, and the sign-in carries on as
// that person: the upgraded session names them, and so does the trail.
func TestVerifyPassword_FirstBindCreatesThePerson(t *testing.T) {
	var given string
	svc, st := firstBindService(t, func(
		_ context.Context, _, _, userID, _, _ string,
	) (Identity, error) {
		given = userID
		return Identity{UserID: "created-1", Email: directoryIdentifier}, nil
	})
	opened := signedInAgainst(t, svc)

	upgraded, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	if given != "" {
		t.Errorf("the bind was given the person %q, want nobody", given)
	}
	if st.saved.UserID != "created-1" {
		t.Errorf("the session names %q, want the person the bind created", st.saved.UserID)
	}
	if !st.saved.Authenticated() {
		t.Error("the sign-in did not upgrade the login session")
	}
	if upgraded.Token == "" || upgraded.Token == opened.Token {
		t.Error("the token did not rotate")
	}
	if got := st.actions(); len(got) != 1 || got[0] != string(audit.ActionLoginSucceeded) {
		t.Errorf("the trail holds %v, want [%s]", got, audit.ActionLoginSucceeded)
	}
	if st.events[0].ActorID != "created-1" {
		t.Errorf("the trail names %q, want the person the bind created", st.events[0].ActorID)
	}
}

// TestVerifyPassword_FirstBindCarriesTheEmail covers the session status of a
// person the first bind created. The identifier step named nobody, so the
// session carried no email, and the bind is the one step that learns one. The
// read the status route makes answers it for the whole life of the session.
func TestVerifyPassword_FirstBindCarriesTheEmail(t *testing.T) {
	svc, st := firstBindService(t, boundAs("created-1", directoryIdentifier))
	opened := signedInAgainst(t, svc)

	upgraded, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}

	status := sessionStatus(t, loginApp(t, svc), upgraded.Token)
	if !status.Active {
		t.Fatal("the status route answers a session that is not active")
	}
	if status.Email != directoryIdentifier {
		t.Errorf("the session status answers %q, want %q", status.Email, directoryIdentifier)
	}
	// No credential travels with the email. The bind proved the password, and no
	// field of the session holds it. The value is not printed on a failure.
	if strings.Contains(fmt.Sprintf("%+v", st.saved), "the-directory-password") {
		t.Error("the saved login session holds the password the person typed")
	}
}

// TestVerifyPassword_SecondBindKeepsTheEmailTheGatewayHolds covers a sign-in the
// identifier step already named. A later bind writes no attribute of the person,
// so the email of the directory entry is not what the gateway holds, and the
// session keeps the one the identifier step found.
func TestVerifyPassword_SecondBindKeepsTheEmailTheGatewayHolds(t *testing.T) {
	svc, st := directoryService(t, boundAs("user-1", "renamed@corp.example"))
	opened := signedInAgainst(t, svc)

	if _, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password"); err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if st.saved.Email != directoryIdentifier {
		t.Errorf("the session carries %q, want %q", st.saved.Email, directoryIdentifier)
	}
}

// TestVerifyPassword_SecondBindNamesTheSamePerson covers every later sign-in of
// a person a bind created. The session names them, so the bind is told who they
// are, and the person the sign-in carries on as is that same one.
func TestVerifyPassword_SecondBindNamesTheSamePerson(t *testing.T) {
	svc, st := directoryService(t, boundAs("user-1", directoryIdentifier))
	opened := signedInAgainst(t, svc)

	if _, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password"); err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if st.saved.UserID != "user-1" {
		t.Errorf("the session names %q, want the person it already held", st.saved.UserID)
	}
}

// TestVerifyPassword_BindNamesNoPerson covers a bind that proved a password and
// answered nobody. The person the sign-in would carry on as does not exist, so
// the step is refused the way an unknown identifier is and no session is
// upgraded.
func TestVerifyPassword_BindNamesNoPerson(t *testing.T) {
	svc, st := firstBindService(t, boundAs("", ""))
	opened := signedInAgainst(t, svc)

	_, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("err = %v, want ErrBadCredentials", err)
	}
	if st.saved.Authenticated() {
		t.Error("the refused sign-in upgraded the login session")
	}
	if !strings.Contains(refusal(t, st), `"reason":"no_local_person"`) {
		t.Errorf("the trail recorded %q, want the missing person reason", st.events[0].Metadata)
	}
}

// TestVerifyPassword_FirstBindThatCreatesNobody covers a first bind whose person
// could not be written, such as a username another person of the tenant already
// holds. It is not a credential failure, so it answers the slug a directory that
// did not answer gets, and no session is upgraded.
func TestVerifyPassword_FirstBindThatCreatesNobody(t *testing.T) {
	svc, st := firstBindService(t, refusedBind(ErrDirectoryUnavailable))
	opened := signedInAgainst(t, svc)

	_, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("err = %v, want ErrDirectoryUnavailable", err)
	}
	if st.saved.Authenticated() {
		t.Error("the refused sign-in upgraded the login session")
	}
	if !strings.Contains(refusal(t, st), `"reason":"directory_unavailable"`) {
		t.Errorf("the trail recorded %q, want the directory reason", st.events[0].Metadata)
	}
}

// TestVerifyPassword_DirectoryMisconfigured covers the two configuration faults
// of a first bind: a provider that names no organization to create people in,
// and a directory entry that carries no username.
//
// Both are permanent, and only an administrator or somebody with the directory
// can mend them. The answer therefore carries a slug of its own, and never the
// one that tells the person to try again. The password was proved, so it must
// not read as a wrong password either.
func TestVerifyPassword_DirectoryMisconfigured(t *testing.T) {
	svc, st := firstBindService(t, refusedBind(ErrDirectoryMisconfigured))
	opened := signedInAgainst(t, svc)

	_, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password")
	if !errors.Is(err, ErrDirectoryMisconfigured) {
		t.Fatalf("err = %v, want ErrDirectoryMisconfigured", err)
	}
	if errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatal("a misconfigured directory reads as a directory that did not answer")
	}
	if errors.Is(err, ErrBadCredentials) {
		t.Fatal("a misconfigured directory reads as a wrong password")
	}
	if st.saved.Authenticated() {
		t.Error("the refused sign-in upgraded the login session")
	}
	if !strings.Contains(refusal(t, st), `"reason":"directory_misconfigured"`) {
		t.Errorf("the trail recorded %q, want the configuration reason", st.events[0].Metadata)
	}
}

// TestDirectoryRefusalsAnswerOneSlug proves on the wire that a disabled
// directory, a spent bind budget, and a wrong password cannot be told apart.
//
// Only a directory sign-in carries a budget, so a slug of its own would say that
// an identifier is served by a directory, and a caller could ask the question
// whenever they liked by spending the budget. A disabled directory would name
// every person tied to it for as long as it stays off.
func TestDirectoryRefusalsAnswerOneSlug(t *testing.T) {
	answer := func(err error) string {
		t.Helper()

		app := fiber.New()
		app.Get("/x", func(c fiber.Ctx) error { return response.Fail(c, err) })

		res, testErr := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
		if testErr != nil {
			t.Fatalf("test request: %v", testErr)
		}
		defer res.Body.Close()

		body, readErr := io.ReadAll(res.Body)
		if readErr != nil {
			t.Fatalf("read the answer: %v", readErr)
		}
		return fmt.Sprintf("%d %s", res.StatusCode, body)
	}

	wrong := answer(fmt.Errorf("%w: session s-1", ErrBadCredentials))
	if disabled := answer(fmt.Errorf("%w: session s-1", ErrDirectoryDisabled)); disabled != wrong {
		t.Fatalf("a disabled directory answers %s, want the %s a wrong password answers", disabled, wrong)
	}
	if spent := answer(fmt.Errorf("%w: session s-1", ErrTooManyBinds)); spent != wrong {
		t.Fatalf("a spent bind budget answers %s, want the %s a wrong password answers", spent, wrong)
	}
	if unavailable := answer(fmt.Errorf("%w: session s-1", ErrDirectoryUnavailable)); unavailable == wrong {
		t.Fatal("a directory that did not answer reads as a wrong password, want a slug of its own")
	}
}

// TestVerifyPassword_BindNamingAnotherPersonReplacesTheEmail covers a bind that
// names somebody other than the person the identifier step found.
//
// The identifier step finds a person by username and writes their email onto the
// session. The bind proves a directory entry whose Identity Link names another
// person, and the sign-in carries on as the person the proof named. The session
// must then carry the email of that person, because a session that named one
// person and showed the address of another is what every screen below it reads.
func TestVerifyPassword_BindNamingAnotherPersonReplacesTheEmail(t *testing.T) {
	const linked = "linked@corp.example"
	svc, st := directoryService(t, boundAs("user-a", linked))
	opened := signedInAgainst(t, svc)

	if _, _, err := svc.VerifyPassword(
		context.Background(), "tenant-1", opened.Token, "the-directory-password"); err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if st.saved.UserID != "user-a" {
		t.Fatalf("the session names %q, want the person the bind named", st.saved.UserID)
	}
	if st.saved.Email != linked {
		t.Errorf("the session carries %q, want %q, the email of the person it names", st.saved.Email, linked)
	}
}

// statusHost is the host the login routes of the test app answer on. The tenant
// middleware refuses a host the issuer does not name, so the two agree.
const statusHost = "login.example"

// loginApp mounts the login routes over one service, the way the server mounts
// them: the tenant middleware resolves the tenant of every request below.
//
// The consent screen and the finalize step are not driven here, so the seams
// they read are nil.
func loginApp(t *testing.T, svc *Service) *fiber.App {
	t.Helper()

	log, _ := logger.NewObserved()
	lookup := func(context.Context, string) (middlewares.TenantContext, error) {
		return middlewares.TenantContext{
			TenantID: "tenant-1",
			Config:   oidc.ProviderConfig{TenantID: "tenant-1", Issuer: "https://" + statusHost},
		}, nil
	}

	app := fiber.New()
	group := app.Group("/login/v1", middlewares.Tenant(lookup, "", log))
	Routes(group, NewHandler(svc, nil, nil, log))
	return app
}

// sessionStatus runs GET /session with one token and returns what the route
// answered.
func sessionStatus(t *testing.T, app *fiber.App, token string) StatusResponse {
	t.Helper()

	req := httptest.NewRequest(fiber.MethodGet, "http://"+statusHost+"/login/v1/session", nil)
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+token)

	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("the status route answers %d, want %d", res.StatusCode, fiber.StatusOK)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read the answer: %v", err)
	}
	var envelope struct {
		Data StatusResponse `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return envelope.Data
}
