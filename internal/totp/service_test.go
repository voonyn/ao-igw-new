package totp

import (
	"context"
	"errors"
	"testing"
	"time"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The activation step accepts a six-digit code, so both caps on guessing apply
// to it. This file proves that they do.
//
// The challenge step was capped when it was written. The activation step was
// not, and it is reached from two places: the sign-in and the portal. The tests
// below drive both, because a cap on one entry point is not a cap.

const (
	guardTenantID  = "11111111-1111-1111-1111-111111111111"
	guardUserID    = "33333333-3333-3333-3333-333333333333"
	guardSessionID = "44444444-4444-4444-4444-444444444444"
	guardToken     = "a-login-session-token"
)

// wrongCode answers a six-digit value the secret does not prove. Two candidates
// are enough: no secret proves both at one instant.
func wrongCode(t *testing.T, secret string) string {
	t.Helper()

	for _, candidate := range []string{"000000", "111111"} {
		if _, ok := verify(secret, candidate, time.Now().UTC()); !ok {
			return candidate
		}
	}
	t.Fatal("both candidates verified against the secret")
	return ""
}

// pendingService builds a service whose person holds a pending enrolment minted
// from a real secret. found reports whether the enrolment was read at all, which
// is how a test tells a refusal before the read from one after it.
func pendingService(t *testing.T, d Deps) (*Service, string, *bool) {
	t.Helper()

	secret, _, err := mint("gateway.test", guardUserID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	sealed, err := aocrypto.SealJSON(nil, secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	found := false
	d.Find = func(context.Context, string, string) (Enrolment, error) {
		found = true
		return Enrolment{TenantID: guardTenantID, UserID: guardUserID, SecretEncrypted: sealed}, nil
	}
	d.FindSession = func(context.Context, string, string) (Principal, error) {
		return Principal{SessionID: guardSessionID, UserID: guardUserID, PasswordProved: true}, nil
	}
	d.Log = logger.New()

	return NewService(d), secret, &found
}

// TestActivateSpendsTheGuessingBudget proves that the trailing-window budget
// covers the activation step on both entry points.
//
// Without it the activation address is the way around the cap. An attacker who
// holds the password starts an enrolment of their own and then guesses six
// digits without limit, which is the bound the budget exists to set.
//
// The budget is spent before the enrolment is read, the way the challenge spends
// it, so a spent budget refuses without touching the database.
func TestActivateSpendsTheGuessingBudget(t *testing.T) {
	tests := []struct {
		name string
		call func(*Service, string) error
	}{
		{
			name: "the sign-in path",
			call: func(s *Service, code string) error {
				_, err := s.Activate(t.Context(), guardTenantID, guardToken, code)
				return err
			},
		},
		{
			name: "the portal path",
			call: func(s *Service, code string) error {
				who := Principal{UserID: guardUserID}
				_, err := s.AccountActivate(t.Context(), guardTenantID, who, code)
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, secret, found := pendingService(t, Deps{
				Allow: func(context.Context, string, int, time.Duration) (bool, error) {
					return false, nil
				},
			})

			err := tc.call(svc, wrongCode(t, secret))
			if !errors.Is(err, ErrTooManyAttempts) {
				t.Errorf("error is %v, want %v", err, ErrTooManyAttempts)
			}
			if *found {
				t.Error("read the enrolment after the budget was spent")
			}
		})
	}
}

// TestActivateRefusesOnACacheFailure proves that a budget nobody could read
// refuses the activation, the way it refuses the challenge.
//
// A failure that let the guess through would leave the guessing unbounded for as
// long as Redis is down, which is the one thing the budget must never do.
func TestActivateRefusesOnACacheFailure(t *testing.T) {
	broken := errors.New("redis is unreachable")
	svc, secret, found := pendingService(t, Deps{
		Allow: func(context.Context, string, int, time.Duration) (bool, error) {
			return false, broken
		},
	})

	_, err := svc.AccountActivate(
		t.Context(), guardTenantID, Principal{UserID: guardUserID}, wrongCode(t, secret),
	)
	if !errors.Is(err, ErrBudgetUnavailable) {
		t.Errorf("error is %v, want %v", err, ErrBudgetUnavailable)
	}
	if *found {
		t.Error("read the enrolment after the budget read failed")
	}
}

// TestActivateCountsAWrongCodeAgainstTheSignIn proves that the per-session count
// covers the activation step of the sign-in.
//
// The Login Session owns the count, so a person who mistypes their way through
// the activation reaches the same end as one who mistypes the challenge: the
// sign-in is over and they start again.
func TestActivateCountsAWrongCodeAgainstTheSignIn(t *testing.T) {
	tests := []struct {
		name  string
		ended bool
		want  error
	}{
		{name: "a wrong code is counted", want: ErrBadCode},
		{name: "the code that reaches the cap ends the sign-in", ended: true, want: ErrSignInEnded},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			counted := false
			svc, secret, _ := pendingService(t, Deps{
				Allow: func(context.Context, string, int, time.Duration) (bool, error) {
					return true, nil
				},
				FailCode: func(context.Context, string, string) (bool, error) {
					counted = true
					return tc.ended, nil
				},
			})

			_, err := svc.Activate(t.Context(), guardTenantID, guardToken, wrongCode(t, secret))
			if !errors.Is(err, tc.want) {
				t.Errorf("error is %v, want %v", err, tc.want)
			}
			if !counted {
				t.Error("the wrong code was not counted against the sign-in")
			}
		})
	}
}

// TestAccountActivateCountsNoSession proves that the portal path does not reach
// for a count it has no session for.
//
// The access token carries no login session, so FailCode has nothing to count
// against. The trailing-window budget is the whole cap on that path.
func TestAccountActivateCountsNoSession(t *testing.T) {
	svc, secret, _ := pendingService(t, Deps{
		Allow: func(context.Context, string, int, time.Duration) (bool, error) {
			return true, nil
		},
		FailCode: func(context.Context, string, string) (bool, error) {
			t.Error("the portal path counted against a login session")
			return false, nil
		},
	})

	_, err := svc.AccountActivate(
		t.Context(), guardTenantID, Principal{UserID: guardUserID}, wrongCode(t, secret),
	)
	if !errors.Is(err, ErrBadCode) {
		t.Errorf("error is %v, want %v", err, ErrBadCode)
	}
}
