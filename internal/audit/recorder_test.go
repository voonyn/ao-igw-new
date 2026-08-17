package audit

import (
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/platform/logger"
)

// seedEntry is the entry the token endpoint records after it issued a grant.
func seedEntry() Entry {
	return Entry{
		TenantID:   "tenant-1",
		ActorID:    "user-1",
		Action:     ActionTokenIssued,
		EntityType: "grant",
		EntityID:   "grant-1",
		IP:         "203.0.113.7",
		UserAgent:  "Mozilla/5.0",
	}
}

// TestNewEvent covers the mapping from an entry to the row: the caller names the
// action and the entity, and the recorder fills the id, the result, and the
// time.
func TestNewEvent(t *testing.T) {
	log, _ := logger.NewObserved()

	event, err := newEvent(seedEntry(), log)
	if err != nil {
		t.Fatalf("map entry: %v", err)
	}

	if event.ID == "" {
		t.Error("event id is empty, want a generated id")
	}
	if event.TenantID != "tenant-1" {
		t.Errorf("tenant id is %q, want %q", event.TenantID, "tenant-1")
	}
	if event.ActorID != "user-1" {
		t.Errorf("actor id is %q, want %q", event.ActorID, "user-1")
	}
	if event.Action != "token.issued" {
		t.Errorf("action is %q, want %q", event.Action, "token.issued")
	}
	if event.EntityType != "grant" || event.EntityID != "grant-1" {
		t.Errorf("entity is %q %q, want grant grant-1", event.EntityType, event.EntityID)
	}
	if event.Result != ResultSuccess {
		t.Errorf("result is %q, want %q", event.Result, ResultSuccess)
	}
	if event.CreatedAt.IsZero() {
		t.Error("created at is zero, want the time of the event")
	}
}

// TestNewEvent_Result covers the result column: the recorder derives it from the
// action, so a call site cannot record a failure as a success.
func TestNewEvent_Result(t *testing.T) {
	log, _ := logger.NewObserved()

	cases := map[Action]string{
		ActionLoginSucceeded:     ResultSuccess,
		ActionLoginFailed:        ResultFailure,
		ActionConsentGranted:     ResultSuccess,
		ActionConsentDenied:      ResultFailure,
		ActionTokenIssued:        ResultSuccess,
		ActionTokenRefreshReused: ResultFailure,
		ActionTokenRevoked:       ResultSuccess,
		ActionLogoutSucceeded:    ResultSuccess,
	}
	if len(cases) != 8 {
		t.Fatalf("the table holds %d actions, want the eight actions", len(cases))
	}

	for action, want := range cases {
		entry := seedEntry()
		entry.Action = action

		event, err := newEvent(entry, log)
		if err != nil {
			t.Fatalf("map entry of action %q: %v", action, err)
		}
		if event.Result != want {
			t.Errorf("result of %q is %q, want %q", action, event.Result, want)
		}
	}
}

// TestNewEvent_Metadata covers the context the trail carries: the client, the
// scopes, and the grant reach the row as JSON.
func TestNewEvent_Metadata(t *testing.T) {
	log, _ := logger.NewObserved()

	entry := seedEntry()
	entry.Metadata = map[string]any{
		"client_id": "client-1",
		"scopes":    "openid profile",
		"grant_id":  "grant-1",
	}

	event, err := newEvent(entry, log)
	if err != nil {
		t.Fatalf("map entry: %v", err)
	}

	want := `{"client_id":"client-1","grant_id":"grant-1","scopes":"openid profile"}`
	if string(event.Metadata) != want {
		t.Errorf("metadata is %s, want %s", event.Metadata, want)
	}
}

// TestNewEvent_MetadataDropsCredentials covers the rule that matters most here:
// a credential never reaches the trail. The keys are an allow-list, so a key
// nobody listed is dropped and the event is still recorded.
func TestNewEvent_MetadataDropsCredentials(t *testing.T) {
	log, logs := logger.NewObserved()

	entry := seedEntry()
	entry.Metadata = map[string]any{
		"client_id":     "client-1",
		"client_secret": "the-secret",
		"code":          "the-authorization-code",
		"refresh_token": "the-refresh-token",
		"password":      "the-password",
	}

	event, err := newEvent(entry, log)
	if err != nil {
		t.Fatalf("map entry: %v", err)
	}

	if string(event.Metadata) != `{"client_id":"client-1"}` {
		t.Errorf("metadata is %s, want the client id alone", event.Metadata)
	}
	for _, secret := range []string{"the-secret", "the-authorization-code", "the-refresh-token", "the-password"} {
		for _, line := range logs.All() {
			if line.ContextMap()["dropped_key"] == secret || line.Message == secret {
				t.Errorf("a log line carries the value %q", secret)
			}
		}
	}
	if logs.FilterMessage("drop audit metadata key").Len() != 4 {
		t.Errorf("the recorder logged %d dropped keys, want 4", logs.FilterMessage("drop audit metadata key").Len())
	}
}

// TestNewEvent_NoMetadata covers the common entry: no context, so the column
// stays NULL rather than holding an empty object.
func TestNewEvent_NoMetadata(t *testing.T) {
	log, _ := logger.NewObserved()

	event, err := newEvent(seedEntry(), log)
	if err != nil {
		t.Fatalf("map entry: %v", err)
	}
	if event.Metadata != "" {
		t.Errorf("metadata is %s, want nothing", event.Metadata)
	}
}

// TestRecord covers the recorder from the outside: the caller hands over an
// entry, and one row reaches the writer. The writer is the transaction seam, so
// the row lands on the caller's transaction.
func TestRecord(t *testing.T) {
	log, _ := logger.NewObserved()

	var written []Event
	recorder := NewRecorder(func(_ context.Context, event Event) error {
		written = append(written, event)
		return nil
	}, log)

	if err := recorder.Record(context.Background(), seedEntry()); err != nil {
		t.Fatalf("record entry: %v", err)
	}

	if len(written) != 1 {
		t.Fatalf("the writer received %d rows, want 1", len(written))
	}
	if written[0].Action != "token.issued" || written[0].TenantID != "tenant-1" {
		t.Errorf("the row is %+v, want the seeded token.issued event", written[0])
	}
}

// TestRecord_WriteFails covers the rule that a failed audit write fails the
// request: the error reaches the caller, which rolls the transaction back.
func TestRecord_WriteFails(t *testing.T) {
	log, _ := logger.NewObserved()

	writeErr := errors.New("the database is down")
	recorder := NewRecorder(func(context.Context, Event) error {
		return writeErr
	}, log)

	if err := recorder.Record(context.Background(), seedEntry()); !errors.Is(err, writeErr) {
		t.Fatalf("error is %v, want the write error", err)
	}
}

// TestRecord_IncompleteEntry covers the two columns the table requires. A row
// without a tenant or an entity type cannot be read back by any report, so the
// recorder refuses it before the database does.
func TestRecord_IncompleteEntry(t *testing.T) {
	log, _ := logger.NewObserved()

	recorder := NewRecorder(func(context.Context, Event) error {
		t.Error("the writer received an incomplete entry")
		return nil
	}, log)

	noTenant := seedEntry()
	noTenant.TenantID = ""
	if err := recorder.Record(context.Background(), noTenant); !errors.Is(err, ErrIncompleteEntry) {
		t.Errorf("error is %v, want ErrIncompleteEntry", err)
	}

	noEntity := seedEntry()
	noEntity.EntityType = ""
	if err := recorder.Record(context.Background(), noEntity); !errors.Is(err, ErrIncompleteEntry) {
		t.Errorf("error is %v, want ErrIncompleteEntry", err)
	}
}

// TestNewEvent_UnknownAction covers an action nobody defined. The row would
// carry a name no report can read, so the mapping fails instead.
func TestNewEvent_UnknownAction(t *testing.T) {
	log, _ := logger.NewObserved()

	entry := seedEntry()
	entry.Action = "token.exploded"

	if _, err := newEvent(entry, log); !errors.Is(err, ErrUnknownAction) {
		t.Fatalf("error is %v, want ErrUnknownAction", err)
	}
}
