package crypto

import (
	"bytes"
	"testing"
)

func TestCipher_RoundTrip(t *testing.T) {
	c, err := NewCipher("a-sufficiently-long-random-dev-key")
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	plaintext := []byte(`{"id":"g1","refresh_token":"rt-secret"}`)
	sealed, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(sealed, []byte("rt-secret")) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := c.Decrypt(sealed)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}
}

func TestCipher_NonceIsRandom(t *testing.T) {
	c, _ := NewCipher("key")
	a, _ := c.Encrypt([]byte("same"))
	b, _ := c.Encrypt([]byte("same"))
	if bytes.Equal(a, b) {
		t.Fatal("identical plaintexts produced identical ciphertexts (nonce reuse)")
	}
}

func TestCipher_TamperDetected(t *testing.T) {
	c, _ := NewCipher("key")
	sealed, _ := c.Encrypt([]byte("payload"))
	sealed[len(sealed)-1] ^= 0xFF // flip a tag bit
	if _, err := c.Decrypt(sealed); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}
}

func TestCipher_WrongKeyFails(t *testing.T) {
	a, _ := NewCipher("key-a")
	b, _ := NewCipher("key-b")
	sealed, _ := a.Encrypt([]byte("payload"))
	if _, err := b.Decrypt(sealed); err == nil {
		t.Fatal("expected decrypt under wrong key to fail")
	}
}

func TestNewCipher_EmptyKey(t *testing.T) {
	if _, err := NewCipher(""); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestDecrypt_ShortInput(t *testing.T) {
	c, _ := NewCipher("key")
	if _, err := c.Decrypt([]byte{0x00}); err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
}

func TestDigest(t *testing.T) {
	if got := Digest("token"); got != Digest("token") {
		t.Fatal("Digest is not deterministic")
	}
	if Digest("a") == Digest("b") {
		t.Fatal("distinct inputs collided")
	}
	if got := len(Digest("token")); got != 64 {
		t.Fatalf("Digest length = %d, want 64 hex chars", got)
	}
}
