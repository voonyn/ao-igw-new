package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// SessionToken returns a 256-bit URL-safe random token for crediting an opaque
// session (e.g. the login-session bearer token). Only its Digest is persisted;
// the plaintext is disclosed exactly once, at mint or rotation. The encoding is
// base64url without padding, so the value is safe in headers and cookies.
func SessionToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Digest returns a deterministic, non-reversible hex SHA-256 of value, for
// indexing a high-entropy secret (e.g. an authorization code or refresh token)
// without storing the secret itself. Equality lookups work because the digest
// is deterministic; it is intentionally key-independent so lookups keep working
// across encryption-key rotation.
//
// This is NOT a password hash — only use it for high-entropy inputs.
func Digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
