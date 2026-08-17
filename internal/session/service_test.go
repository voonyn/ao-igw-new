package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
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

// noCredential is the credential seam of a test that never reaches the password
// step.
func noCredential(context.Context, string, string) (string, error) {
	return "", user.ErrNotFound
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

	log, _ := logger.NewObserved()
	st := &store{}
	svc := NewService(Deps{
		Identity:   identity,
		Credential: credential,
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

	upgraded, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password")
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

	upgraded, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password")
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

	if _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password"); err != nil {
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

	_, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "the-wrong-password")
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

	_, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password")
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

	_, err := svc.VerifyPassword(context.Background(), "tenant-1", "not-a-token", "a-correct-password")
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

	if _, err := svc.VerifyPassword(context.Background(), "tenant-1", opened.Token, "a-correct-password"); err == nil {
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
