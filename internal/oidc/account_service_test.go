package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// connectionOwner is the person every connected applications test acts as. It is
// the subject of the caller's own token, because the account API has no other
// subject.
var connectionOwner = AccountActor{
	TenantID:  "11111111-1111-1111-1111-111111111111",
	UserID:    "66666666-6666-6666-6666-666666666666",
	IP:        "203.0.113.7",
	UserAgent: "a-browser",
}

// What one connected applications test read and wrote.
type connectionSpy struct {
	readUser     string
	withdrawnFor [2]string
	revokedFor   [2]string
	events       []audit.Event
}

// connectionService stands the self-service service up on closures. rows is
// every consent the tenant holds, and each closure narrows it the way the
// repository query does. A fake that ignored the narrowing would prove nothing,
// because the narrowing is the whole ownership rule.
//
// failAt names a step that fails, so a test can prove that the transaction takes
// both writes back together.
func connectionService(
	t *testing.T, rows map[string]ConnectionRecord, failAt string,
) (*AccountService, *connectionSpy) {
	t.Helper()
	log, _ := logger.NewObserved()
	spy := &connectionSpy{}

	fail := errors.New("the database refused")

	svc := NewAccountService(AccountDeps{
		List: func(_ context.Context, _, userID string) ([]ConnectionRecord, error) {
			spy.readUser = userID
			var mine []ConnectionRecord
			for owner, row := range rows {
				if owner == userID {
					mine = append(mine, row)
				}
			}
			return mine, nil
		},
		Withdraw: func(_ context.Context, _, userID, clientID string) error {
			spy.withdrawnFor = [2]string{userID, clientID}
			if failAt == "withdraw" {
				return ErrConsentNotFound
			}
			return nil
		},
		Revoke: func(_ context.Context, _, subject, clientID string) (int, error) {
			spy.revokedFor = [2]string{subject, clientID}
			if failAt == "revoke" {
				return 0, fail
			}
			return 3, nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			// A rolled-back transaction leaves nothing behind, so the spy is
			// cleared the way the database would be.
			if err := fn(ctx); err != nil {
				spy.withdrawnFor, spy.revokedFor, spy.events = [2]string{}, [2]string{}, nil
				return err
			}
			return nil
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			if failAt == "audit" {
				return fail
			}
			spy.events = append(spy.events, e)
			return nil
		}, log),
		Log: log,
	})
	return svc, spy
}

// ownConsents is one connection of the caller and one of a different person. The
// second is what every ownership assertion turns on.
func ownConsents() map[string]ConnectionRecord {
	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	return map[string]ConnectionRecord{
		connectionOwner.UserID: {
			ClientID: "the-portal-client", Scopes: "openid profile",
			AppName: "The Portal", HasGrant: true,
			CreatedAt: at, UpdatedAt: at,
		},
		"77777777-7777-7777-7777-777777777777": {
			ClientID: "another-client", Scopes: "openid", AppName: "Another App",
			CreatedAt: at, UpdatedAt: at,
		},
	}
}

// TestAccountListReadsOnlyTheCallersConnections covers the ownership rule of the
// read, and the shape of one row.
func TestAccountListReadsOnlyTheCallersConnections(t *testing.T) {
	svc, spy := connectionService(t, ownConsents(), "")

	views, err := svc.List(context.Background(), connectionOwner)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	if spy.readUser != connectionOwner.UserID {
		t.Errorf("the read narrowed to user %q, want %q", spy.readUser, connectionOwner.UserID)
	}
	if len(views) != 1 {
		t.Fatalf("the list reads %+v, want the one connection of the caller", views)
	}

	view := views[0]
	if view.ClientID != "the-portal-client" || view.AppName != "The Portal" {
		t.Errorf("the connection reads %q named %q, want the client and its application",
			view.ClientID, view.AppName)
	}
	if len(view.Scopes) != 2 || view.Scopes[0] != "openid" || view.Scopes[1] != "profile" {
		t.Errorf("the connection allows %v, want the two scopes split apart", view.Scopes)
	}
	if !view.HasLiveGrant {
		t.Error("the connection holds no live grant, want one")
	}
}

// TestAccountDisconnectWithdrawsAndRevokes covers one disconnect: both writes
// name the caller, and one audit event records what went.
func TestAccountDisconnectWithdrawsAndRevokes(t *testing.T) {
	svc, spy := connectionService(t, ownConsents(), "")

	view, err := svc.Disconnect(context.Background(), connectionOwner, "the-portal-client")
	if err != nil {
		t.Fatalf("Disconnect: %v", err)
	}
	if view.ClientID != "the-portal-client" || view.Grants != 3 {
		t.Errorf("the disconnect reads %+v, want the client and its three grants", view)
	}

	want := [2]string{connectionOwner.UserID, "the-portal-client"}
	if spy.withdrawnFor != want {
		t.Errorf("the withdraw named %v, want %v", spy.withdrawnFor, want)
	}
	if spy.revokedFor != want {
		t.Errorf("the grant delete named %v, want %v", spy.revokedFor, want)
	}

	if len(spy.events) != 1 {
		t.Fatalf("the disconnect recorded %d events, want one", len(spy.events))
	}
	if got := spy.events[0].Action; got != string(audit.ActionConsentRevoked) {
		t.Errorf("the event records %q, want %q", got, audit.ActionConsentRevoked)
	}
	if got := spy.events[0].EntityID; got != "the-portal-client" {
		t.Errorf("the event names entity %q, want the client", got)
	}
}

// TestAccountDisconnectIsAllOrNothing covers the transaction. A failure in
// either later step takes the withdraw back with it, so an application can never
// keep a refresh token of a consent that is already withdrawn.
func TestAccountDisconnectIsAllOrNothing(t *testing.T) {
	for _, failAt := range []string{"revoke", "audit"} {
		svc, spy := connectionService(t, ownConsents(), failAt)

		view, err := svc.Disconnect(context.Background(), connectionOwner, "the-portal-client")
		if err == nil {
			t.Fatalf("a failure at the %s step answered no error", failAt)
		}
		if view != (DisconnectedView{}) {
			t.Errorf("a failure at the %s step answered %+v, want nothing", failAt, view)
		}
		if spy.withdrawnFor != [2]string{} || len(spy.events) != 0 {
			t.Errorf("a failure at the %s step left %v and %d events behind, want neither",
				failAt, spy.withdrawnFor, len(spy.events))
		}
	}
}

// TestAccountDisconnectRefusesWhatTheCallerDoesNotHold covers the refusal. A
// client the caller never connected and a consent of another person read alike,
// so the answer never says which applications another person connected.
func TestAccountDisconnectRefusesWhatTheCallerDoesNotHold(t *testing.T) {
	svc, spy := connectionService(t, ownConsents(), "withdraw")

	_, err := svc.Disconnect(context.Background(), connectionOwner, "another-client")
	if !errors.Is(err, ErrConsentNotFound) {
		t.Fatalf("the disconnect answered %v, want ErrConsentNotFound", err)
	}
	if spy.revokedFor != [2]string{} {
		t.Errorf("the refused disconnect deleted the grants of %v, want none", spy.revokedFor)
	}
}
