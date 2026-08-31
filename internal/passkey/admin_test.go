package passkey

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The console surface: an operator reads the Passkeys of somebody else and
// revokes one. The role check of the user domain arrives as a function value,
// so every rule below is proved without a database and without a router.

// testOperatorID is the person who presses the button. It is never the person
// the address names, and the trail must be able to tell the two apart.
const testOperatorID = "33333333-3333-3333-3333-333333333333"

// refused is what an Authorizer answers for a member without the role. The user
// domain answers its own sentinel, and this module passes it through untouched.
var refused = errors.New("forbidden")

// adminService builds the console service over the three parts each test wants
// to control, and records what reached the trail. One Authorizer stands for
// both gates, which is what a test that names one operator wants.
func adminService(
	t *testing.T, authorize Authorizer,
	list CredentialLister, remove CredentialRemover,
) (*AdminService, *[]audit.Event) {
	t.Helper()
	return adminServiceGated(t, authorize, authorize, list, remove)
}

// adminServiceGated builds the same service with the two gates apart, for the
// tests that read as one operator and are refused the revoke as that same
// operator.
func adminServiceGated(
	t *testing.T, read, write Authorizer,
	list CredentialLister, remove CredentialRemover,
) (*AdminService, *[]audit.Event) {
	t.Helper()

	log, _ := logger.NewObserved()
	written := make([]audit.Event, 0, 1)
	svc := NewAdminService(AdminDeps{
		AuthorizeRead:  read,
		AuthorizeWrite: write,
		List:           list,
		Delete:         remove,
		InTx:           func(ctx context.Context, run func(context.Context) error) error { return run(ctx) },
		Audit: audit.NewRecorder(func(_ context.Context, event audit.Event) error {
			written = append(written, event)
			return nil
		}, log),
		Log: log,
	})
	return svc, &written
}

// allow is the Authorizer of an operator who holds the role.
func allow(context.Context, string, string, string) error { return nil }

// deny is the Authorizer of a member who does not.
func deny(context.Context, string, string, string) error { return refused }

// TestAdminList_AnswersTheLivePasskeysOfThatPerson proves the read reaches the
// person the address names, and not the operator who asked.
//
// An operator opens somebody else's screen, so a read keyed on the caller would
// answer the wrong list and look right doing it.
func TestAdminList_AnswersTheLivePasskeysOfThatPerson(t *testing.T) {
	var readFor string
	svc, _ := adminService(t, allow,
		func(_ context.Context, _, userID string) ([]Credential, error) {
			readFor = userID
			return []Credential{{
				TenantID:     testTenantID,
				CredentialID: []byte{1, 2, 3},
				UserID:       testUserID,
				Name:         "Work laptop",
				CreatedAt:    time.Now().UTC(),
			}}, nil
		}, nil)

	who := Principal{UserID: testOperatorID}
	rows, err := svc.List(context.Background(), testTenantID, who, testUserID)
	if err != nil {
		t.Fatalf("the list answered %v, want the passkeys of that person", err)
	}

	if readFor != testUserID {
		t.Errorf("the read named %q, want the person the address names", readFor)
	}
	if len(rows) != 1 || rows[0].Name != "Work laptop" {
		t.Errorf("the list answered %v, want the one device that person holds", rows)
	}
}

// TestAdminList_APersonWithNoPasskeyAnswersAnEmptyList proves the empty state
// the console renders is a list and never a missing key.
func TestAdminList_APersonWithNoPasskeyAnswersAnEmptyList(t *testing.T) {
	svc, _ := adminService(t, allow,
		func(context.Context, string, string) ([]Credential, error) {
			return []Credential{}, nil
		}, nil)

	rows, err := svc.List(context.Background(), testTenantID, Principal{UserID: testOperatorID}, testUserID)
	if err != nil {
		t.Fatalf("the list answered %v, want an empty list", err)
	}
	if out := views(rows); out == nil || len(out) != 0 {
		t.Errorf("the answer is %v, want an empty list and never null", out)
	}
}

// TestAdminList_ARefusedMemberReadsNothing proves the gate runs before the read.
//
// A member without the role must not learn whether that person holds a Passkey
// at all, so the refusal lands before the database is touched.
func TestAdminList_ARefusedMemberReadsNothing(t *testing.T) {
	svc, _ := adminService(t, deny,
		func(context.Context, string, string) ([]Credential, error) {
			t.Error("a refused member reached the read")
			return nil, nil
		}, nil)

	_, err := svc.List(context.Background(), testTenantID, Principal{UserID: testOperatorID}, testUserID)
	if !errors.Is(err, refused) {
		t.Errorf("the list answered %v, want the refusal of the user domain", err)
	}
}

// TestAdminRevoke_RemovesThatDeviceAndRecordsTheActor proves the whole revoke:
// the right row is marked, and the trail names who pressed the button, whose
// account it was, and which credential went.
func TestAdminRevoke_RemovesThatDeviceAndRecordsTheActor(t *testing.T) {
	var removedFor string
	var removedID []byte
	svc, written := adminService(t, allow, nil,
		func(_ context.Context, _, userID string, credID []byte) error {
			removedFor = userID
			removedID = credID
			return nil
		})

	who := Principal{UserID: testOperatorID, IP: "203.0.113.7", UserAgent: "Console"}
	// The padded spelling. A client that pads the id names the same device, and
	// the trail must carry the canonical spelling either way.
	if err := svc.Revoke(context.Background(), testTenantID, who, testUserID, "AQID="); err != nil {
		t.Fatalf("the revoke answered %v, want the device removed", err)
	}

	if removedFor != testUserID {
		t.Errorf("the write named %q, want the person the address names", removedFor)
	}
	if string(removedID) != string([]byte{1, 2, 3}) {
		t.Errorf("the write named %v, want the credential the operator picked", removedID)
	}

	if len(*written) != 1 {
		t.Fatalf("the revoke wrote %d events, want one", len(*written))
	}
	event := (*written)[0]
	if event.Action != string(audit.ActionUserPasskeyRevoked) {
		t.Errorf("the trail records %q, want %q", event.Action, audit.ActionUserPasskeyRevoked)
	}
	if event.ActorID != testOperatorID {
		t.Errorf("the trail names actor %q, want the operator", event.ActorID)
	}
	if event.EntityID != testUserID {
		t.Errorf("the trail names entity %q, want the person who held the device", event.EntityID)
	}
	if !strings.Contains(event.Metadata, "AQID") {
		t.Errorf("the trail carries %q, want the canonical credential id", event.Metadata)
	}
}

// TestAdminRevoke_TheTrailCarriesNoKeyMaterial proves the metadata bag holds the
// public handle and nothing beside it.
//
// The stored blob is the one thing a revoke has in reach that must never reach
// the trail. A Passkey stores a public key, so this is tidiness and not a leak,
// but an audit row is read forever and the blob answers no question anybody asks
// of it.
func TestAdminRevoke_TheTrailCarriesNoKeyMaterial(t *testing.T) {
	const blob = `{"publicKey":"BASE64KEYMATERIAL"}`

	svc, written := adminService(t, allow, nil,
		func(context.Context, string, string, []byte) error { return nil })

	if err := svc.Revoke(
		context.Background(), testTenantID, Principal{UserID: testOperatorID}, testUserID, "AQID",
	); err != nil {
		t.Fatalf("the revoke answered %v, want the device removed", err)
	}

	event := (*written)[0]
	if strings.Contains(event.Metadata, "publicKey") || strings.Contains(event.Metadata, blob) {
		t.Errorf("the trail carries %q, want the credential id alone", event.Metadata)
	}
}

// TestAdminRevoke_ARefusedMemberWritesNothing proves the gate runs before the
// write and before the trail.
//
// The API refuses the member the console never showed the action to. A view that
// hides a button is a convenience, and this is the enforcement point.
func TestAdminRevoke_ARefusedMemberWritesNothing(t *testing.T) {
	svc, written := adminService(t, deny, nil,
		func(context.Context, string, string, []byte) error {
			t.Error("a refused member reached the write")
			return nil
		})

	err := svc.Revoke(
		context.Background(), testTenantID, Principal{UserID: testOperatorID}, testUserID, "AQID")
	if !errors.Is(err, refused) {
		t.Errorf("the revoke answered %v, want the refusal of the user domain", err)
	}
	if len(*written) != 0 {
		t.Errorf("the trail records %d events, want none", len(*written))
	}
}

// TestAdminRevoke_AnIDNoRowHoldsIsNotFound proves an id nobody registered reads
// as a Passkey that is gone, and writes no trail.
func TestAdminRevoke_AnIDNoRowHoldsIsNotFound(t *testing.T) {
	svc, written := adminService(t, allow, nil,
		func(context.Context, string, string, []byte) error { return ErrNotFound })

	err := svc.Revoke(
		context.Background(), testTenantID, Principal{UserID: testOperatorID}, testUserID, "AQID")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoke answered %v, want %v", err, ErrNotFound)
	}
	if len(*written) != 0 {
		t.Errorf("the trail records %d events, want none", len(*written))
	}
}

// TestAdminList_AnOperatorRefusedTheRevokeStillReadsTheList proves the two gates
// are apart.
//
// An operator who holds ORG_USER_MANAGER in one organization reads the account
// record of somebody in another organization, so they read the devices on that
// account too. The support call is about a lost device, and the name and the
// last-used date are the answer.
func TestAdminList_AnOperatorRefusedTheRevokeStillReadsTheList(t *testing.T) {
	svc, _ := adminServiceGated(t, allow, deny,
		func(context.Context, string, string) ([]Credential, error) {
			return []Credential{{
				TenantID:     testTenantID,
				CredentialID: []byte{1, 2, 3},
				UserID:       testUserID,
				Name:         "Work laptop",
				CreatedAt:    time.Now().UTC(),
			}}, nil
		}, nil)

	rows, err := svc.List(context.Background(), testTenantID, Principal{UserID: testOperatorID}, testUserID)
	if err != nil {
		t.Fatalf("the list answered %v, want the passkeys of that person", err)
	}
	if len(rows) != 1 || rows[0].Name != "Work laptop" {
		t.Errorf("the list answered %v, want the one device that person holds", rows)
	}
}

// TestAdminRevoke_AnOperatorWhoOnlyReadsIsRefusedTheRevoke is the other half of
// the rule above. The read gate admitted that operator, and the write gate is
// the one the removal runs.
func TestAdminRevoke_AnOperatorWhoOnlyReadsIsRefusedTheRevoke(t *testing.T) {
	svc, written := adminServiceGated(t, allow, deny, nil,
		func(context.Context, string, string, []byte) error {
			t.Error("an operator refused the write reached the removal")
			return nil
		})

	err := svc.Revoke(
		context.Background(), testTenantID, Principal{UserID: testOperatorID}, testUserID, "AQID")
	if !errors.Is(err, refused) {
		t.Errorf("the revoke answered %v, want the refusal of the user domain", err)
	}
	if len(*written) != 0 {
		t.Errorf("the trail records %d events, want none", len(*written))
	}
}
