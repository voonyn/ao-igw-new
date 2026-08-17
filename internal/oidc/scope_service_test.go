package oidc

import (
	"context"
	"reflect"
	"testing"

	"alphaomega/identitygateway/internal/platform/logger"
)

// scopeSvc builds the service over a fixed scope list. It stands in for the
// repository read, which needs a database.
func scopeSvc(t *testing.T, scopes []Scope) *ScopeService {
	t.Helper()
	log, _ := logger.NewObserved()

	return NewScopeService(ScopeDeps{
		List: func(context.Context, string) ([]Scope, error) {
			return scopes, nil
		},
		Log: log,
	})
}

// TestAdvertisedHoldsOpenID covers the scopes the discovery document names. The
// tenant decides the list, and openid is always present, because a tenant that
// disables it still runs OpenID Connect.
func TestAdvertisedHoldsOpenID(t *testing.T) {
	svc := scopeSvc(t, []Scope{
		{Name: "profile"},
		{Name: "email"},
	})

	got, err := svc.Advertised(context.Background(), "tenant-1")
	if err != nil {
		t.Fatalf("advertised: %v", err)
	}

	want := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("discovery advertises %v, want %v", got, want)
	}
}

// TestDescribeFallsBackToName covers the text of the consent screen. A scope
// the tenant describes carries its own words. A scope with no display name, and
// a scope the tenant does not hold, both render the bare scope name, because a
// person must read something for every scope the screen asks about.
func TestDescribeFallsBackToName(t *testing.T) {
	svc := scopeSvc(t, []Scope{
		{Name: "email", DisplayName: "Email", Description: "Email address and its verification status."},
		{Name: "profile"},
	})

	got, err := svc.Describe(context.Background(), "tenant-1", []string{"email", "profile", "billing"})
	if err != nil {
		t.Fatalf("describe: %v", err)
	}

	want := []Scope{
		{Name: "email", DisplayName: "Email", Description: "Email address and its verification status."},
		{Name: "profile", DisplayName: "profile"},
		{Name: "billing", DisplayName: "billing"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the consent screen renders %v, want %v", got, want)
	}
}
