package http

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/user"
)

// TestClearSecondFactors covers the composition the administrator reset runs on.
//
// The TOTP tables and the passkey table sit in two modules that must not import
// each other, so the router joins the two calls. The one thing that split newly
// risks is a half going missing, which is what this test refuses.
func TestClearSecondFactors(t *testing.T) {
	var order []string

	half := func(name string, err error) user.MFAClearer {
		return func(_ context.Context, tenantID, userID string) error {
			if tenantID != "tenant-1" || userID != "user-1" {
				t.Errorf("%s got %q %q, want tenant-1 user-1", name, tenantID, userID)
			}
			order = append(order, name)
			return err
		}
	}

	clear := clearSecondFactors(half("totp", nil), half("passkeys", nil))
	if err := clear(context.Background(), "tenant-1", "user-1"); err != nil {
		t.Fatalf("clear the second factors: %v", err)
	}
	if len(order) != 2 || order[0] != "totp" || order[1] != "passkeys" {
		t.Errorf("the reset ran %v, want the totp half and then the passkey half", order)
	}

	// A failing first half stops the second and reaches the caller, which rolls
	// the transaction back. A passkey removed beside a secret that survived
	// would leave the person a factor they cannot prove.
	failed := errors.New("the database is down")
	order = nil
	clear = clearSecondFactors(half("totp", failed), half("passkeys", nil))
	if err := clear(context.Background(), "tenant-1", "user-1"); !errors.Is(err, failed) {
		t.Fatalf("error is %v, want the error of the first half", err)
	}
	if len(order) != 1 {
		t.Errorf("the reset ran %v, want the second half skipped", order)
	}
}
