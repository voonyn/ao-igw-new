package oidc

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/luikyv/go-oidc/pkg/goidc"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
)

// testGrant is the grant the token endpoint stores: a code that was redeemed and
// a refresh token that is still live.
func testGrant() *goidc.Grant {
	return &goidc.Grant{
		ID:                    "grant-1",
		Subject:               "user-1",
		ClientID:              "client-1",
		Scopes:                "openid profile",
		AuthCode:              "the-authorization-code",
		AuthCodeExpiresAt:     1_700_000_060,
		RefreshToken:          "the-refresh-token",
		RefreshTokenExpiresAt: 1_700_086_400,
	}
}

// TestSealGrant covers the round trip the grant store makes on every token
// request: seal into a row, then open the row back into the same grant.
func TestSealGrant(t *testing.T) {
	cipher := testCipher(t)

	row, err := sealGrant("tenant-1", testGrant(), cipher)
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}

	if row.TenantID != "tenant-1" {
		t.Errorf("row tenant is %q, want %q", row.TenantID, "tenant-1")
	}
	if row.ID != "grant-1" || row.ClientID != "client-1" || row.Subject != "user-1" {
		t.Errorf("row lookup columns are %+v, want the values of the grant", row)
	}
	if row.ExpiresAt.Unix() != 1_700_086_400 {
		t.Errorf("row expires at %s, want the refresh token deadline", row.ExpiresAt)
	}

	opened, err := openGrant(row, cipher)
	if err != nil {
		t.Fatalf("open grant: %v", err)
	}
	if !reflect.DeepEqual(opened, testGrant()) {
		t.Errorf("the opened grant is %+v, want %+v", opened, testGrant())
	}
}

// TestSealGrant_Digests covers the lookup keys. The row carries a digest of the
// code and of the refresh token, and never the value itself, so a leaked row
// cannot be replayed.
func TestSealGrant_Digests(t *testing.T) {
	cipher := testCipher(t)

	row, err := sealGrant("tenant-1", testGrant(), cipher)
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}

	if row.AuthCodeHash != aocrypto.Digest("the-authorization-code") {
		t.Errorf("auth code hash is %q, want the digest of the code", row.AuthCodeHash)
	}
	if row.RefreshTokenHash != aocrypto.Digest("the-refresh-token") {
		t.Errorf("refresh token hash is %q, want the digest of the token", row.RefreshTokenHash)
	}
	for _, secret := range []string{"the-authorization-code", "the-refresh-token"} {
		if bytes.Contains(row.Data, []byte(secret)) {
			t.Errorf("the sealed data holds the plain text of %q", secret)
		}
	}
}

// TestSealGrant_NoTokens covers a grant that carries neither a code nor a
// refresh token. An empty digest column stays NULL, so it never matches a
// lookup.
func TestSealGrant_NoTokens(t *testing.T) {
	row, err := sealGrant("tenant-1", &goidc.Grant{ID: "grant-2", ClientID: "client-1"}, testCipher(t))
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}

	if row.AuthCodeHash != "" || row.RefreshTokenHash != "" {
		t.Errorf("row digests are %q and %q, want both empty", row.AuthCodeHash, row.RefreshTokenHash)
	}
	if !row.ExpiresAt.IsZero() {
		t.Errorf("row expires at %s, want the zero time", row.ExpiresAt)
	}
}

// TestSupersede covers one rotation: the token the grant carried before the
// save is retained by digest, under the grant it belonged to, until it would
// have expired on its own.
func TestSupersede(t *testing.T) {
	prev := testGrant()
	next := testGrant()
	next.RefreshToken = "the-next-refresh-token"
	next.RefreshTokenExpiresAt = 1_700_172_800

	row, ok := supersede("tenant-1", prev, next, time.Unix(1_700_000_000, 0).UTC())
	if !ok {
		t.Fatal("the rotation retained nothing, want one row")
	}
	if row.TenantID != "tenant-1" || row.GrantID != "grant-1" {
		t.Errorf("the row is %+v, want the tenant and the grant of the rotation", row)
	}
	if row.TokenHash != aocrypto.Digest("the-refresh-token") {
		t.Errorf("the row holds %q, want the digest of the superseded token", row.TokenHash)
	}
	if row.ExpiresAt.Unix() != 1_700_086_400 {
		t.Errorf("the row expires at %s, want the deadline of the superseded token", row.ExpiresAt)
	}
}

// TestSupersede_NoRotation covers a save that is not a rotation. The engine
// saves the same grant again on code redemption and on every token request, and
// a live token must never be retained as superseded.
func TestSupersede_NoRotation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	unchanged := testGrant()
	if _, ok := supersede("tenant-1", testGrant(), unchanged, now); ok {
		t.Error("an unchanged refresh token was retained, want no row")
	}

	fresh := &goidc.Grant{ID: "grant-2", ClientID: "client-1"}
	if _, ok := supersede("tenant-1", fresh, testGrant(), now); ok {
		t.Error("a grant with no refresh token retained a row, want no row")
	}
}

// TestSupersede_NoDeadline covers a grant the provider stamped no refresh token
// expiry on, which migration 00037 left possible for existing rows. The row
// falls back to the shipped 30-day bound, so it never lives forever.
func TestSupersede_NoDeadline(t *testing.T) {
	prev := testGrant()
	prev.RefreshTokenExpiresAt = 0
	next := testGrant()
	next.RefreshToken = "the-next-refresh-token"
	now := time.Unix(1_700_000_000, 0).UTC()

	row, ok := supersede("tenant-1", prev, next, now)
	if !ok {
		t.Fatal("the rotation retained nothing, want one row")
	}
	if want := now.Add(30 * 24 * time.Hour); !row.ExpiresAt.Equal(want) {
		t.Errorf("the row expires at %s, want %s", row.ExpiresAt, want)
	}
}

// TestSealSession covers the round trip the authorization endpoint makes: the
// session is sealed while the person authenticates, and opened when the browser
// comes back.
func TestSealSession(t *testing.T) {
	cipher := testCipher(t)
	session := &goidc.AuthnSession{
		ID:        "session-1",
		ClientID:  "client-1",
		Subject:   "user-1",
		ExpiresAt: 1_700_000_060,
	}

	row, err := sealSession("tenant-1", session, cipher)
	if err != nil {
		t.Fatalf("seal session: %v", err)
	}
	if row.TenantID != "tenant-1" || row.ID != "session-1" || row.ClientID != "client-1" || row.Subject != "user-1" {
		t.Errorf("row lookup columns are %+v, want the values of the session", row)
	}
	if row.ExpiresAt.Unix() != 1_700_000_060 {
		t.Errorf("row expires at %s, want the session deadline", row.ExpiresAt)
	}

	opened, err := openSession(row, cipher)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if opened.ID != session.ID || opened.Subject != session.Subject || opened.ExpiresAt != session.ExpiresAt {
		t.Errorf("the opened session is %+v, want %+v", opened, session)
	}
}

// TestOpenGrant_WrongCipher covers a row that the configured key cannot open.
// The read fails instead of handing the engine an empty grant.
func TestOpenGrant_WrongCipher(t *testing.T) {
	row, err := sealGrant("tenant-1", testGrant(), testCipher(t))
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}

	other, err := aocrypto.NewCipher("another-test-database-encryption-key-32")
	if err != nil {
		t.Fatalf("build cipher: %v", err)
	}
	if _, err := openGrant(row, other); err == nil {
		t.Error("open grant with the wrong key succeeded, want an error")
	}
}

// TestGrantNotFound keeps the sentinel errors distinct, because the protocol
// engine answers a missing grant and a missing session the same way only after
// the adapter maps both to goidc.ErrNotFound.
func TestGrantNotFound(t *testing.T) {
	if errors.Is(ErrGrantNotFound, ErrSessionNotFound) {
		t.Error("the grant and the session sentinel are the same error")
	}
}
