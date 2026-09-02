package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/user"
)

// The rules a person meets after the first Passkey exists: the cap, the device
// that is already registered, the device that comes back, and the removal that
// demands the password.
//
// The ceremony itself is proved in service_test.go. Nothing here signs anything,
// because none of these rules is decided by a signature.

// heldCredentials answers n rows the account reader can parse. The blob is what
// the library writes, and an empty object is enough for a count.
func heldCredentials(n int) []Credential {
	rows := make([]Credential, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, Credential{
			TenantID:     testTenantID,
			CredentialID: []byte{byte(i)},
			UserID:       testUserID,
			Record:       "{}",
			Name:         "Device",
		})
	}
	return rows
}

// TestRegisterStart_TheCapRefusesTheEleventh proves that a person who holds the
// most Passkeys allowed starts no ceremony.
//
// The refusal lands at the start, so the person is never asked to touch a device
// for a Factor the gateway was never going to keep.
func TestRegisterStart_TheCapRefusesTheEleventh(t *testing.T) {
	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		Account: func(context.Context, string, string) (string, error) {
			return "person@example.com", nil
		},
		List: func(context.Context, string, string) ([]Credential, error) {
			return heldCredentials(maxPasskeys), nil
		},
		Origins: func(context.Context, string) ([]string, error) {
			return []string{testOrigin}, nil
		},
		// A cap that let the ceremony through would store a challenge here. The
		// budget read still answers, because the cap is what the test is about.
		Ceremony: budgetOnlyCache{errCache{err: errors.New("no challenge belongs to a refused start")}},
		Log:      log,
	})

	who := Principal{UserID: testUserID}
	_, err := svc.registerStart(context.Background(), testTenantID, testHost, testOrigin, who)

	if !errors.Is(err, ErrTooManyPasskeys) {
		t.Errorf("the start answered %v, want %v", err, ErrTooManyPasskeys)
	}
}

// TestRegisterStart_OneUnderTheCapRuns proves the boundary. Nine held Passkeys
// leave room for the tenth, which is the last one a person registers.
func TestRegisterStart_OneUnderTheCapRuns(t *testing.T) {
	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		Account: func(context.Context, string, string) (string, error) {
			return "person@example.com", nil
		},
		List: func(context.Context, string, string) ([]Credential, error) {
			return heldCredentials(maxPasskeys - 1), nil
		},
		Origins: func(context.Context, string) ([]string, error) {
			return []string{testOrigin}, nil
		},
		Ceremony: recordingCache{stored: make(map[string]string)},
		Log:      log,
	})

	who := Principal{UserID: testUserID}
	if _, err := svc.registerStart(
		context.Background(), testTenantID, testHost, testOrigin, who,
	); err != nil {
		t.Fatalf("the start answered %v, want the options", err)
	}
}

// TestClaim_ADeviceAlreadyRegisteredIsRefused proves the case the exclude list
// cannot see.
//
// The exclude list names the devices of one person. A live row of another
// account of the same tenant holds the same primary key, so the registration is
// refused here with a slug of its own.
func TestClaim_ADeviceAlreadyRegisteredIsRefused(t *testing.T) {
	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		Find: func(context.Context, string, []byte) (Credential, error) {
			return Credential{TenantID: testTenantID, UserID: "another-person", Name: "Laptop"}, nil
		},
		Log: log,
	})

	_, err := svc.claim(context.Background(), testTenantID, Principal{UserID: testUserID}, []byte{1})

	if !errors.Is(err, ErrDuplicateDevice) {
		t.Errorf("the claim answered %v, want %v", err, ErrDuplicateDevice)
	}
}

// TestClaim_ARemovedRowIsRevived proves that a device somebody removed can
// register again.
//
// The primary key is (tenant_id, credential_id), so the removed row still holds
// the id. A plain insert would fail on it, and the person could never use that
// device again.
func TestClaim_ARemovedRowIsRevived(t *testing.T) {
	removed := Credential{
		TenantID:  testTenantID,
		UserID:    testUserID,
		DeletedAt: time.Now().UTC(),
	}

	revived := false
	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		Find: func(context.Context, string, []byte) (Credential, error) { return removed, nil },
		Insert: func(context.Context, Credential) error {
			t.Error("the finish inserted over a removed row, want a revive")
			return nil
		},
		Revive: func(context.Context, Credential) error { revived = true; return nil },
		Log:    log,
	})

	write, err := svc.claim(
		context.Background(), testTenantID, Principal{UserID: testUserID}, []byte{1})
	if err != nil {
		t.Fatalf("the claim answered %v, want the write", err)
	}
	if err := write(context.Background(), Credential{}); err != nil {
		t.Fatalf("the write answered %v, want nil", err)
	}
	if !revived {
		t.Error("the claim chose the insert, want the revive")
	}
}

// TestClaim_AnUnknownIDIsInserted proves the normal path: a device this tenant
// never saw takes a new row.
func TestClaim_AnUnknownIDIsInserted(t *testing.T) {
	inserted := false
	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		Find: func(context.Context, string, []byte) (Credential, error) {
			return Credential{}, ErrNotFound
		},
		Insert: func(context.Context, Credential) error { inserted = true; return nil },
		Revive: func(context.Context, Credential) error {
			t.Error("the finish revived a row nobody registered, want an insert")
			return nil
		},
		Log: log,
	})

	write, err := svc.claim(
		context.Background(), testTenantID, Principal{UserID: testUserID}, []byte{1})
	if err != nil {
		t.Fatalf("the claim answered %v, want the write", err)
	}
	if err := write(context.Background(), Credential{}); err != nil {
		t.Fatalf("the write answered %v, want nil", err)
	}
	if !inserted {
		t.Error("the claim chose the revive, want the insert")
	}
}

// TestAccountRemove_TheWrongPasswordWritesNothing proves the proof.
//
// The access token carries no session identifier, so the password is the whole
// proof of the request. A removal that ran without it would let a leaked access
// token strip the account of a Factor.
func TestAccountRemove_TheWrongPasswordWritesNothing(t *testing.T) {
	const secret = "the-password-the-person-typed"
	wrong := errors.New("invalid credentials")

	log, logs := logger.NewObserved()
	svc := NewService(Deps{
		VerifyPassword: func(context.Context, string, string, string) error { return wrong },
		Delete: func(context.Context, string, string, []byte) error {
			t.Error("the removal wrote before the password was proved")
			return nil
		},
		Log: log,
	})

	who := Principal{UserID: testUserID}
	err := svc.AccountRemove(context.Background(), testTenantID, who, "AQID", secret)

	if !errors.Is(err, wrong) {
		t.Errorf("the removal answered %v, want %v", err, wrong)
	}
	for _, line := range logs.All() {
		if strings.Contains(line.Message, secret) {
			t.Fatal("the password reached a log message")
		}
		blob, _ := json.Marshal(line.ContextMap())
		if strings.Contains(string(blob), secret) {
			t.Fatal("the password reached a log field")
		}
	}
}

// TestAccountRemove_RecordsTheRemoval proves that a removal leaves a trail of
// its own. It is the only record that the Factor existed.
func TestAccountRemove_RecordsTheRemoval(t *testing.T) {
	var written []string

	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		VerifyPassword: func(context.Context, string, string, string) error { return nil },
		Delete:         func(context.Context, string, string, []byte) error { return nil },
		InTx:           func(ctx context.Context, run func(context.Context) error) error { return run(ctx) },
		Audit: audit.NewRecorder(func(_ context.Context, event audit.Event) error {
			written = append(written, event.Action)
			return nil
		}, log),
		Log: log,
	})

	who := Principal{UserID: testUserID}
	if err := svc.AccountRemove(
		context.Background(), testTenantID, who, "AQID", "a-password",
	); err != nil {
		t.Fatalf("the removal answered %v, want nil", err)
	}

	if len(written) != 1 || written[0] != string(audit.ActionMFAPasskeyRemoved) {
		t.Errorf("the removal recorded %v, want one %v", written, audit.ActionMFAPasskeyRemoved)
	}
}

// TestAccountRename_TrimsTheName proves that the name reaches the column as the
// person reads it. A name of spaces alone is refused by the request rules, so
// nothing here can empty the column.
func TestAccountRename_TrimsTheName(t *testing.T) {
	var got string

	log, _ := logger.NewObserved()
	svc := NewService(Deps{
		Rename: func(_ context.Context, _, _ string, _ []byte, name string) error {
			got = name
			return nil
		},
		Log: log,
	})

	who := Principal{UserID: testUserID}
	if err := svc.AccountRename(
		context.Background(), testTenantID, who, "AQID", "  Work laptop  ",
	); err != nil {
		t.Fatalf("the rename answered %v, want nil", err)
	}
	if got != "Work laptop" {
		t.Errorf("the rename wrote %q, want %q", got, "Work laptop")
	}

	// A name of spaces alone meets the request rules and trims to nothing. It
	// falls back to the word a registration uses, so the column is never emptied.
	if err := svc.AccountRename(
		context.Background(), testTenantID, who, "AQID", "   ",
	); err != nil {
		t.Fatalf("the rename answered %v, want nil", err)
	}
	if got != defaultName {
		t.Errorf("the rename wrote %q, want %q", got, defaultName)
	}
}

// TestDecodeCredentialID proves how an id from the address bar is read.
//
// An id that is not base64url names no row, so it reads as a Passkey that is
// gone. The padding is trimmed, because the list answers the unpadded spelling
// and a client that pads it names the same device.
func TestDecodeCredentialID(t *testing.T) {
	raw, err := decodeCredentialID("AQID")
	if err != nil || len(raw) != 3 {
		t.Fatalf("decodeCredentialID of AQID answered %v, %v, want three bytes", raw, err)
	}

	if padded, err := decodeCredentialID("AQIDBA=="); err != nil || len(padded) != 4 {
		t.Errorf("decodeCredentialID with padding answered %v, %v, want four bytes", padded, err)
	}

	for _, bad := range []string{"", "not base64!", "===="} {
		if _, err := decodeCredentialID(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("decodeCredentialID of %q answered %v, want %v", bad, err, ErrNotFound)
		}
	}
}

// TestAccountRemove_CarriesTheBrokenAccountOfADirectoryPerson proves the answer
// a person reads when no single directory entry proves them.
//
// The state is permanent. The person holds no live active Identity Link, or more
// than one, or the search of the directory matched none, or it matched two. No
// try of theirs changes any of that, so the sentinel must reach the caller whole
// and never collapse into the refusal a wrong password gets.
func TestAccountRemove_CarriesTheBrokenAccountOfADirectoryPerson(t *testing.T) {
	log := logger.New()
	account := user.NewAccountService(user.AccountDeps{
		// A person the Directory owns. The stored hash is empty, always.
		Credential: func(_ context.Context, tenantID, userID string) (user.User, error) {
			return user.User{ID: userID, TenantID: tenantID, PasswordHash: ""}, nil
		},
		ProveDirectory: func(context.Context, string, string, string) error {
			return user.ErrDirectoryNoEntry
		},
		DirectoryOwns: func(context.Context, string, string) (bool, error) { return true, nil },
		Log:           log,
	})

	svc := NewService(Deps{
		VerifyPassword: func(ctx context.Context, tenantID, userID, plain string) error {
			return account.VerifyPassword(ctx,
				user.Actor{TenantID: tenantID, UserID: userID}, plain)
		},
		Delete: func(context.Context, string, string, []byte) error {
			t.Error("the removal wrote for an account no directory entry proves")
			return nil
		},
		Log: log,
	})

	who := Principal{UserID: testUserID}
	err := svc.AccountRemove(t.Context(), testTenantID, who, "AQID", "the-directory-password")
	if !errors.Is(err, user.ErrDirectoryNoEntry) {
		t.Fatalf("the removal answered %v, want %v", err, user.ErrDirectoryNoEntry)
	}
}

// TestAccountRemove_BindsForAClaimedPersonWhoKeepsAStaleHash proves the seam for
// the second person the Directory owns: the one a domain claim routes.
//
// Provider Resolution case 1 claims the email domain of a person the tenant
// already held. The claim writes no row, so password_hash keeps the value it
// held, and the bind signs the person in from that moment. A compare against the
// stale hash would refuse the password that signs them in, and this removal
// would shut on them.
//
// See .scratch/directory-sign-in/issues/21.
func TestAccountRemove_BindsForAClaimedPersonWhoKeepsAStaleHash(t *testing.T) {
	stale, err := crypto.HashPassword("the-retired-local-password")
	if err != nil {
		t.Fatalf("hash the retired local password: %v", err)
	}

	log := logger.New()
	bound := ""
	account := user.NewAccountService(user.AccountDeps{
		// The person keeps every column they had, the hash included.
		Credential: func(_ context.Context, tenantID, userID string) (user.User, error) {
			return user.User{ID: userID, TenantID: tenantID, PasswordHash: stale}, nil
		},
		ProveDirectory: func(_ context.Context, _, _, plain string) error {
			bound = plain
			return nil
		},
		DirectoryOwns: func(context.Context, string, string) (bool, error) { return true, nil },
		Log:           log,
	})

	deleted := false
	svc := NewService(Deps{
		VerifyPassword: func(ctx context.Context, tenantID, userID, plain string) error {
			return account.VerifyPassword(ctx,
				user.Actor{TenantID: tenantID, UserID: userID}, plain)
		},
		Delete: func(context.Context, string, string, []byte) error {
			deleted = true
			return nil
		},
		InTx:  func(ctx context.Context, run func(context.Context) error) error { return run(ctx) },
		Audit: audit.NewRecorder(func(context.Context, audit.Event) error { return nil }, log),
		Log:   log,
	})

	who := Principal{UserID: testUserID}
	if err := svc.AccountRemove(
		t.Context(), testTenantID, who, "AQID", "the-directory-password"); err != nil {
		t.Fatalf("the removal answered %v", err)
	}
	if bound != "the-directory-password" {
		t.Errorf("the directory was asked %q, want the password the person typed", bound)
	}
	if !deleted {
		t.Error("the passkey was not removed")
	}
}
