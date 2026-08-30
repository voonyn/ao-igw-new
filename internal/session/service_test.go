package session

import (
	"context"
	"errors"
	"reflect"
	"strings"
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

	log, _ := logger.NewObserved()
	st := &store{}
	svc := NewService(Deps{
		Identity:   identity,
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
