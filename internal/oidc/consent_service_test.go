package oidc

import (
	"context"
	"reflect"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// stubFinder answers every lookup with one fixed state.
func stubFinder(state ConsentState) ConsentFinder {
	return func(context.Context, string, string, string) (ConsentState, error) {
		return state, nil
	}
}

// recorded holds what one Approve or Deny call wrote, so a test reads the union
// and the audit row without a database.
type recorded struct {
	scopes  []string
	actions []audit.Action
	inTx    bool
}

// consentSvc builds the service over an in-memory writer. It stands in for the
// repository and the transaction manager, which both need a database.
func consentSvc(t *testing.T, state ConsentState) (*ConsentService, *recorded) {
	t.Helper()
	log, _ := logger.NewObserved()
	got := &recorded{}

	var open bool
	return NewConsentService(ConsentDeps{
		Find: stubFinder(state),
		Save: func(_ context.Context, _, _, _ string, scopes []string) error {
			got.scopes, got.inTx = scopes, open
			return nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			open = true
			defer func() { open = false }()
			return fn(ctx)
		},
		Audit: audit.NewRecorder(func(_ context.Context, event audit.Event) error {
			got.actions = append(got.actions, audit.Action(event.Action))
			return nil
		}, log),
		Log: log,
	}), got
}

// TestApprove covers the answer the person gives on the consent screen. The
// union of the stored set and the new scopes is written, and the audit row
// lands on the same transaction.
func TestApprove(t *testing.T) {
	svc, got := consentSvc(t, ConsentState{Scopes: []string{"openid", "profile"}})

	err := svc.Approve(context.Background(), Consent{
		TenantID: "tenant-1",
		UserID:   "user-1",
		ClientID: "client-1",
		Scopes:   []string{"email", "openid"},
	})
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	want := []string{"openid", "profile", "email"}
	if !reflect.DeepEqual(got.scopes, want) {
		t.Errorf("stored scopes are %v, want %v", got.scopes, want)
	}
	if !got.inTx {
		t.Error("the union was written outside a transaction")
	}
	if !reflect.DeepEqual(got.actions, []audit.Action{audit.ActionConsentGranted}) {
		t.Errorf("recorded %v, want one %s", got.actions, audit.ActionConsentGranted)
	}
}

// TestDeny covers the refusal. Nothing is stored, so the next sign-in asks
// again, and the trail holds the refusal.
func TestDeny(t *testing.T) {
	svc, got := consentSvc(t, ConsentState{})

	err := svc.Deny(context.Background(), Consent{
		TenantID: "tenant-1",
		UserID:   "user-1",
		ClientID: "client-1",
		Scopes:   []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("deny: %v", err)
	}

	if got.scopes != nil {
		t.Errorf("a refusal stored %v, want nothing", got.scopes)
	}
	if !reflect.DeepEqual(got.actions, []audit.Action{audit.ActionConsentDenied}) {
		t.Errorf("recorded %v, want one %s", got.actions, audit.ActionConsentDenied)
	}
}

// TestDecideFirstParty covers the tenant's own applications. The person already
// trusts the tenant, so the screen never renders for them.
func TestDecideFirstParty(t *testing.T) {
	log, _ := logger.NewObserved()
	svc := NewConsentService(ConsentDeps{
		Find: stubFinder(ConsentState{FirstParty: true}),
		Log:  log,
	})

	missing, err := svc.Decide(
		context.Background(), "tenant-1", "user-1", "client-1",
		[]string{"openid", "profile"}, false)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("first party asks for consent: %v", missing)
	}
}

// TestDecideCovered covers the second sign-in of a third-party client. The
// person approved these scopes before, so the screen never renders again.
func TestDecideCovered(t *testing.T) {
	log, _ := logger.NewObserved()
	svc := NewConsentService(ConsentDeps{
		Find: stubFinder(ConsentState{Scopes: []string{"openid", "profile", "email"}}),
		Log:  log,
	})

	missing, err := svc.Decide(
		context.Background(), "tenant-1", "user-1", "client-1",
		[]string{"openid", "profile"}, false)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("a covered request asks for consent: %v", missing)
	}
}

// TestDecideNewScopes covers a client that asks for more than it holds. The
// screen names the new scopes only, and never the ones already approved.
func TestDecideNewScopes(t *testing.T) {
	log, _ := logger.NewObserved()
	svc := NewConsentService(ConsentDeps{
		Find: stubFinder(ConsentState{Scopes: []string{"openid", "profile"}}),
		Log:  log,
	})

	missing, err := svc.Decide(
		context.Background(), "tenant-1", "user-1", "client-1",
		[]string{"openid", "email", "offline_access"}, false)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	want := []string{"email", "offline_access"}
	if !reflect.DeepEqual(missing, want) {
		t.Fatalf("consent asks for %v, want %v", missing, want)
	}
}

// TestDecideForced covers prompt=consent. The client demands a fresh answer, so
// the screen renders with the whole request on it. A first-party client and a
// stored set that covers the request are both overruled.
func TestDecideForced(t *testing.T) {
	log, _ := logger.NewObserved()
	requested := []string{"openid", "profile"}

	states := map[string]ConsentState{
		"first party": {FirstParty: true},
		"covered":     {Scopes: []string{"openid", "profile", "email"}},
	}
	for name, state := range states {
		t.Run(name, func(t *testing.T) {
			svc := NewConsentService(ConsentDeps{Find: stubFinder(state), Log: log})

			missing, err := svc.Decide(
				context.Background(), "tenant-1", "user-1", "client-1", requested, true)
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if !reflect.DeepEqual(missing, requested) {
				t.Fatalf("prompt=consent asks for %v, want %v", missing, requested)
			}
		})
	}
}
