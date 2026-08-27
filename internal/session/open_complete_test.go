package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"alphaomega/identitygateway/internal/audit"
)

// noIdentity is the identifier seam of a test that never runs the identifier
// step. Open names nobody, so it never reads a person.
func noIdentity(context.Context, string, string) (Identity, error) {
	return Identity{}, errors.New("the identifier step must not run here")
}

// TestOpen covers the login session a flow opens before anybody has said who
// they are.
func TestOpen(t *testing.T) {
	svc, st := testService(t, noIdentity)

	opened, err := svc.Open(context.Background(), "tenant-1", "203.0.113.7", "a-browser")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	if opened.ID == "" || opened.Token == "" {
		t.Fatalf("open gave %+v, want an id and a token", opened)
	}
	if st.saved.UserID != "" || st.saved.Email != "" {
		t.Errorf("the opened session names %q/%q, want nobody", st.saved.UserID, st.saved.Email)
	}
	if st.saved.Authenticated() {
		t.Error("the opened session carries a factor, want none")
	}
	// The address and the agent are what an operator reads a session by.
	if st.saved.IP != "203.0.113.7" || st.saved.UserAgent != "a-browser" {
		t.Errorf("the opened session holds %q/%q", st.saved.IP, st.saved.UserAgent)
	}
	// Opening a session is not a sign-in. Nothing is recorded yet.
	if got := st.actions(); len(got) != 0 {
		t.Errorf("the trail holds %v, want nothing", got)
	}
}

// TestComplete covers the step that binds a person to a partial login session
// and records one named factor on it.
func TestComplete(t *testing.T) {
	svc, st := testService(t, noIdentity)
	opened, err := svc.Open(context.Background(), "tenant-1", "203.0.113.7", "a-browser")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	upgraded, err := svc.Complete(context.Background(), "tenant-1", opened.Token, "user-1", FactorScan)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	if upgraded.ID != opened.ID {
		t.Errorf("the completed session is %q, want the one that was opened, %q", upgraded.ID, opened.ID)
	}
	// The token rotates, and the token the caller presented is dead.
	if upgraded.Token == opened.Token {
		t.Error("the token did not rotate")
	}
	if _, err := svc.Find(context.Background(), "tenant-1", opened.Token); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("the previous token gave %v, want %v", err, ErrLoginSessionNotFound)
	}

	live, err := svc.Resolve(context.Background(), "tenant-1", upgraded.Token)
	if err != nil {
		t.Fatalf("resolve the rotated token: %v", err)
	}
	if live.UserID != "user-1" {
		t.Errorf("the completed session names %q, want user-1", live.UserID)
	}
	if _, ok := live.Factors[FactorScan]; !ok {
		t.Errorf("the completed session carries %v, want the %s factor", live.Factors, FactorScan)
	}

	// The sign-in is one recorded event, and the factor names how it was proved.
	if got := st.actions(); len(got) != 1 || got[0] != string(audit.ActionLoginSucceeded) {
		t.Fatalf("the trail holds %v, want one %s", got, audit.ActionLoginSucceeded)
	}
	if got := st.events[0].Metadata; !strings.Contains(got, FactorScan) {
		t.Errorf("the recorded event holds metadata %q, want the %s factor named", got, FactorScan)
	}
}

// TestCompleteRefusesAnotherPerson is the one that matters: a live login session
// can never be pointed at a second person.
func TestCompleteRefusesAnotherPerson(t *testing.T) {
	svc, _ := testService(t, noIdentity)
	opened, err := svc.Open(context.Background(), "tenant-1", "203.0.113.7", "a-browser")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	upgraded, err := svc.Complete(context.Background(), "tenant-1", opened.Token, "user-1", FactorScan)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}

	_, err = svc.Complete(context.Background(), "tenant-1", upgraded.Token, "user-2", FactorScan)
	if !errors.Is(err, ErrSubjectBound) {
		t.Errorf("completing for a second person gave %v, want %v", err, ErrSubjectBound)
	}
}

// TestFindReadsAPartialSession covers the read a flow needs before it knows the
// person. Resolve refuses a session with no factor, and Find answers it.
func TestFindReadsAPartialSession(t *testing.T) {
	svc, _ := testService(t, noIdentity)
	opened, err := svc.Open(context.Background(), "tenant-1", "203.0.113.7", "a-browser")
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	live, err := svc.Find(context.Background(), "tenant-1", opened.Token)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if live.ID != opened.ID {
		t.Errorf("find gave session %q, want %q", live.ID, opened.ID)
	}

	if _, err := svc.Resolve(context.Background(), "tenant-1", opened.Token); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("resolve gave %v, want %v", err, ErrNotAuthenticated)
	}
	if _, err := svc.Find(context.Background(), "tenant-2", opened.Token); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("find in another tenant gave %v, want %v", err, ErrLoginSessionNotFound)
	}
}
