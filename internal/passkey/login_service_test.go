package passkey

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
)

// TestLoginEnrolRefusesAHeldFactor proves that both sign-in enrolment addresses
// of this module refuse a person who already holds a Second Factor.
//
// The person here holds a TOTP Enrolment. This module never reads that table.
// The router answers HoldsFactor from the pending steps of the account, and a
// person the steps name a challenge for is a person who holds a Factor, so the
// true below is what the router answers for a TOTP holder. See refuseHeldFactor.
//
// Both addresses are driven. A start refused on its own is not the guard: the
// ceremony lives for its TTL, so the finish would carry the same bypass one call
// later. The sentinel is what the handler maps to mfa_already_held.
func TestLoginEnrolRefusesAHeldFactor(t *testing.T) {
	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		FindSession: func(context.Context, string, string) (Principal, error) {
			return Principal{SessionID: "session-1", UserID: testUserID, PasswordProved: true}, nil
		},
		HoldsFactor: func(context.Context, string, string) (bool, error) { return true, nil },
		Log:         log,
	})

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "the start",
			call: func() error {
				_, err := svc.LoginEnrolStart(
					t.Context(), testTenantID, testHost, testOrigin, "a-login-session-token")
				return err
			},
		},
		{
			name: "the finish",
			call: func() error {
				_, err := svc.LoginEnrolFinish(
					t.Context(), testTenantID, testHost, testOrigin, "a-login-session-token",
					[]byte(`{"id":"aaaa","rawId":"aaaa","type":"public-key"}`))
				return err
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrFactorAlreadyHeld) {
				t.Errorf("the address answered %v, want %v", err, ErrFactorAlreadyHeld)
			}
		})
	}
}

// TestLoginStart_TheCapLeavesTheCodeBudgetWhole is the reason the challenge
// budget is a budget of its own.
//
// A person presses Escape on the browser sheet until the challenge cap refuses
// them. A cancel proves nothing, so it must cost them nothing on the path they
// have left. The shared second-factor guessing budget is untouched by every one
// of those starts, and the code they type next is still answered.
func TestLoginStart_TheCapLeavesTheCodeBudgetWhole(t *testing.T) {
	// What the TOTP module spends. The key shape and the limit are copied here,
	// because this module never imports that one.
	const guessLimit = 15
	guessKey := "mfa_attempts:" + testTenantID + ":" + testUserID

	store := limitingCache{hits: make(map[string]int)}

	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		FindSession: func(context.Context, string, string) (Principal, error) {
			return Principal{SessionID: "session-1", UserID: testUserID, PasswordProved: true}, nil
		},
		Account: func(context.Context, string, string) (string, error) {
			return "person@example.com", nil
		},
		// One live Passkey, so the challenge has a device to name.
		List: func(context.Context, string, string) ([]Credential, error) {
			return []Credential{{Record: `{"id":"AQID"}`}}, nil
		},
		Origins:  func(context.Context, string) ([]string, error) { return []string{testOrigin}, nil },
		Ceremony: store,
		Log:      log,
	})

	ctx := context.Background()
	const token = "a-login-session-token"

	for i := 0; i < challengeLimit; i++ {
		if _, err := svc.LoginStart(ctx, testTenantID, testHost, testOrigin, token); err != nil {
			t.Fatalf("start %d answered %v, want the options", i+1, err)
		}
	}

	if _, err := svc.LoginStart(
		ctx, testTenantID, testHost, testOrigin, token,
	); !errors.Is(err, ErrTooManyChallenges) {
		t.Fatalf("the start over the cap answered %v, want %v", err, ErrTooManyChallenges)
	}

	if got := store.hits[guessKey]; got != 0 {
		t.Fatalf("the challenge starts spent the guessing budget %d times, want 0", got)
	}

	// The code path of the same person, on the same store. Every guess is still
	// there, which is what the split exists for.
	for i := 0; i < guessLimit; i++ {
		allowed, err := store.AllowInWindow(ctx, guessKey, guessLimit, time.Minute)
		if err != nil {
			t.Fatalf("guess %d answered %v, want the budget", i+1, err)
		}
		if !allowed {
			t.Fatalf("guess %d was refused, want the budget", i+1)
		}
	}
}
