package user

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// person is the person every account service test acts as. It is the subject of
// the caller's own token, because the account API has no other subject.
var person = Actor{TenantID: testTenantID, UserID: testUserID, IP: "203.0.113.7", UserAgent: "a-browser"}

// TestAccountProfileWritesTheCallerAndNobodyElse proves the ownership rule. The
// write names the subject of the token, and the body names no account at all.
func TestAccountProfileWritesTheCallerAndNobodyElse(t *testing.T) {
	var written []Human
	svc := accountService(t, func(_ context.Context, row Human) error {
		written = append(written, row)
		return nil
	})

	body := ProfileBody{FirstName: "Ada", LastName: "Lovelace", DisplayName: "Ada", Locale: "en"}
	if err := svc.UpdateProfile(context.Background(), person, body); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}

	if len(written) != 1 {
		t.Fatalf("the service wrote %d rows, want 1", len(written))
	}
	got := written[0]
	if got.UserID != testUserID || got.TenantID != testTenantID {
		t.Errorf("the write reached user %s of tenant %s, want %s of %s",
			got.UserID, got.TenantID, testUserID, testTenantID)
	}
	if got.FirstName != "Ada" || got.LastName != "Lovelace" || got.DisplayName != "Ada" {
		t.Errorf("the write carries %+v, want the four fields of the body", got)
	}
	if got.Lang != "en" {
		t.Errorf("the write stores the language %q, want the locale the portal sent", got.Lang)
	}
}

// TestAccountProfileLeavesContactFieldsAlone proves that the self-service write
// carries no phone number. The column list of the repository leaves the stored
// number in place, and the row the service builds never names one.
func TestAccountProfileLeavesContactFieldsAlone(t *testing.T) {
	var written []Human
	svc := accountService(t, func(_ context.Context, row Human) error {
		written = append(written, row)
		return nil
	})

	if err := svc.UpdateProfile(context.Background(), person, ProfileBody{FirstName: "Ada"}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if written[0].Phone != "" || written[0].Email != "" || written[0].PasswordHash != "" {
		t.Errorf("the write carries %+v, want the four identity fields only", written[0])
	}
}

// TestAccountProfileRecordsOneEvent proves the audit trail names the person as
// the actor and as the entity, which is what the activity feed reads.
func TestAccountProfileRecordsOneEvent(t *testing.T) {
	svc := accountService(t, func(context.Context, Human) error { return nil })

	if err := svc.UpdateProfile(context.Background(), person, ProfileBody{FirstName: "Ada"}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("the service recorded %d events, want 1", len(events))
	}
	if events[0].ActorID != testUserID || events[0].EntityID != testUserID {
		t.Errorf("the event names actor %s and entity %s, want %s for both",
			events[0].ActorID, events[0].EntityID, testUserID)
	}
	if events[0].Action != string(audit.ActionUserUpdated) {
		t.Errorf("the event records the action %q, want %q", events[0].Action, audit.ActionUserUpdated)
	}
}

// TestAccountProfileRollsBackAFailedWrite proves that a failed write records no
// event. The write and the event land on one transaction.
func TestAccountProfileRollsBackAFailedWrite(t *testing.T) {
	svc := accountService(t, func(context.Context, Human) error { return ErrNoSuchUser })

	err := svc.UpdateProfile(context.Background(), person, ProfileBody{FirstName: "Ada"})
	if !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("err = %v, want ErrNoSuchUser", err)
	}
	if len(events) != 0 {
		t.Errorf("the service recorded %d events, want none", len(events))
	}
	if !rolledBack {
		t.Error("the transaction committed, want a rollback")
	}
}

// accountService builds the service with its one repository write substituted by
// a closure. No database and no HTTP, so the test runs on any machine.
func accountService(t *testing.T, update ProfileUpdater) *AccountService {
	t.Helper()
	var log logger.Logger
	log, logs = logger.NewObserved()
	events, rolledBack = nil, false

	record := func(_ context.Context, e audit.Event) error {
		events = append(events, e)
		return nil
	}

	return NewAccountService(AccountDeps{
		UpdateProfile: update,
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			if err := fn(ctx); err != nil {
				rolledBack = true
				return err
			}
			return nil
		},
		Audit: audit.NewRecorder(record, log),
		Log:   log,
	})
}
