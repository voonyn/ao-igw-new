package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"strings"
	"testing"
)

const (
	keyA = "root-key-a-0123456789abcdef0123456789abcdef"
	keyB = "root-key-b-fedcba9876543210fedcba9876543210"
)

func mustNewCipher(t *testing.T, key string) *Cipher {
	t.Helper()
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

// TestCipher_SealedBlobNamesItsKey is ticket 16's headline property: the stored
// bytes say which key sealed them. Without it, rotation is an offline
// stop-the-world re-encrypt because nothing can tell an old blob from a new one.
func TestCipher_SealedBlobNamesItsKey(t *testing.T) {
	a, b := mustNewCipher(t, keyA), mustNewCipher(t, keyB)
	if a.KeyID() == b.KeyID() {
		t.Fatal("two different keys derived the same id")
	}

	sealed, err := a.Encrypt([]byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	id, _, hasHeader := splitSealed(sealed)
	if !hasHeader {
		t.Fatal("sealed blob carries no header")
	}
	if id != a.KeyID() {
		t.Fatalf("header names key %q, want %q", id, a.KeyID())
	}
	if !a.SealedUnderCurrentKey(sealed) || b.SealedUnderCurrentKey(sealed) {
		t.Fatal("SealedUnderCurrentKey does not follow the header")
	}
}

// TestCipher_RotatedKeyStillOpensPriorBlobs is the precondition every other F-5
// ticket rests on: seal under A, rotate to B, and both still decrypt.
func TestCipher_RotatedKeyStillOpensPriorBlobs(t *testing.T) {
	underA, err := mustNewCipher(t, keyA).Encrypt([]byte("sealed under A"))
	if err != nil {
		t.Fatalf("Encrypt under A: %v", err)
	}

	rotated := mustNewCipher(t, keyB)
	if _, err := rotated.Decrypt(underA); err == nil {
		t.Fatal("B decrypted an A blob without being told about A")
	}
	if err := rotated.AddPriorKey(keyA); err != nil {
		t.Fatalf("AddPriorKey: %v", err)
	}

	got, err := rotated.Decrypt(underA)
	if err != nil {
		t.Fatalf("Decrypt A blob after rotation: %v", err)
	}
	if string(got) != "sealed under A" {
		t.Fatalf("decrypted %q", got)
	}

	underB, err := rotated.Encrypt([]byte("sealed under B"))
	if err != nil {
		t.Fatalf("Encrypt under B: %v", err)
	}
	if got, err := rotated.Decrypt(underB); err != nil || string(got) != "sealed under B" {
		t.Fatalf("Decrypt B blob: %q, %v", got, err)
	}
	// The sealing key never becomes ambiguous: prior keys read, they do not write.
	if !rotated.SealedUnderCurrentKey(underB) || rotated.SealedUnderCurrentKey(underA) {
		t.Fatal("a prior key was used to seal")
	}
}

// TestCipher_LegacyHeaderlessBlobStillDecrypts is what makes F-5 shippable with
// no data migration and no downtime: every blob written before this change is a
// bare nonce||ct||tag under the environment key, and must keep opening.
func TestCipher_LegacyHeaderlessBlobStillDecrypts(t *testing.T) {
	legacy := sealLegacy(t, keyA, []byte("written before the header existed"))
	if _, _, hasHeader := splitSealed(legacy); hasHeader {
		t.Fatal("the legacy fixture is not headerless")
	}

	c := mustNewCipher(t, keyA)
	got, err := c.Decrypt(legacy)
	if err != nil {
		t.Fatalf("Decrypt legacy blob: %v", err)
	}
	if string(got) != "written before the header existed" {
		t.Fatalf("decrypted %q", got)
	}
	// It is not "current", so a rotation run knows it still has work to do.
	if c.SealedUnderCurrentKey(legacy) {
		t.Fatal("a headerless blob reported itself as sealed under the current key")
	}
}

func TestCipher_UnknownKeyIDIsRefused(t *testing.T) {
	sealed, err := mustNewCipher(t, keyA).Encrypt([]byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = mustNewCipher(t, keyB).Decrypt(sealed)
	if err == nil || !strings.Contains(err.Error(), "no key") {
		t.Fatalf("Decrypt with the wrong key = %v, want a missing-key error", err)
	}
}

func TestCipher_TamperedBlobFailsAuthentication(t *testing.T) {
	c := mustNewCipher(t, keyA)
	sealed, err := c.Encrypt([]byte("x"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	sealed[len(sealed)-1] ^= 0xff
	if _, err := c.Decrypt(sealed); err == nil {
		t.Fatal("a tampered blob decrypted")
	}
}

// sealLegacy produces pre-header ciphertext — nonce||ct||tag under the same
// derived key, exactly what is sitting in the database today.
func sealLegacy(t *testing.T, key string, plaintext []byte) []byte {
	t.Helper()
	sum := sha256.Sum256(append([]byte(encKeyDomain), key...))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatalf("read nonce: %v", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil)
}
