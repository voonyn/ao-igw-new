package passkey

import (
	"context"
	"errors"
	"testing"

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
