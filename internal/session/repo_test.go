package session

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
)

func testCipher(t *testing.T) *aocrypto.Cipher {
	t.Helper()

	cipher, err := aocrypto.NewCipher("a-test-database-encryption-key-32+chars")
	if err != nil {
		t.Fatalf("build cipher: %v", err)
	}
	return cipher
}

// testSession is the session the password step leaves behind: one person, one
// verified factor.
func testSession() LoginSession {
	at := time.Unix(1_700_000_000, 0).UTC()
	return LoginSession{
		ID:        "session-1",
		TenantID:  "tenant-1",
		UserID:    "user-1",
		Email:     "person@example.com",
		IP:        "203.0.113.7",
		UserAgent: "a-browser",
		Factors:   map[string]time.Time{FactorPassword: at},
		CreatedAt: at,
		ExpiresAt: at.Add(12 * time.Hour),
	}
}

// TestSeal covers the round trip every login step makes: seal into a row, then
// open the row back into the same session.
func TestSeal(t *testing.T) {
	cipher := testCipher(t)

	row, err := seal(testSession(), "the-digest", cipher)
	if err != nil {
		t.Fatalf("seal login session: %v", err)
	}

	if row.ID != "session-1" || row.TenantID != "tenant-1" || row.UserID != "user-1" {
		t.Errorf("row lookup columns are %+v, want the values of the session", row)
	}
	if row.State != StateActive {
		t.Errorf("row state is %d, want %d", row.State, StateActive)
	}
	if row.TokenHash != "the-digest" {
		t.Errorf("row token hash is %q, want the digest it was sealed with", row.TokenHash)
	}
	if !row.ExpiresAt.Equal(testSession().ExpiresAt) {
		t.Errorf("row expires at %s, want %s", row.ExpiresAt, testSession().ExpiresAt)
	}

	opened, err := open(row, cipher)
	if err != nil {
		t.Fatalf("open login session: %v", err)
	}
	if !reflect.DeepEqual(opened, testSession()) {
		t.Errorf("the opened session is %+v, want %+v", opened, testSession())
	}
}

// TestSeal_HidesTheEmail covers the reason the blob is encrypted: the row holds
// no readable personal data, only the columns an operator needs.
func TestSeal_HidesTheEmail(t *testing.T) {
	row, err := seal(testSession(), "the-digest", testCipher(t))
	if err != nil {
		t.Fatalf("seal login session: %v", err)
	}

	if bytes.Contains(row.Data, []byte("person@example.com")) {
		t.Error("the sealed blob holds the email in the clear")
	}
}

// TestSeal_PartialSession covers the identifier step. No person is named yet, so
// the user id column stays empty and bun writes NULL.
func TestSeal_PartialSession(t *testing.T) {
	partial := testSession()
	partial.UserID = ""
	partial.Factors = nil

	row, err := seal(partial, "the-digest", testCipher(t))
	if err != nil {
		t.Fatalf("seal login session: %v", err)
	}

	if row.UserID != "" {
		t.Errorf("row user id is %q, want it empty", row.UserID)
	}
}
