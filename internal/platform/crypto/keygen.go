package crypto

import (
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// JOSE algorithm identifiers supported by Generate. These match the
// `alg` values used elsewhere in the codebase (e.g. oidc_keys.algorithm
// and the goidc client/provider configuration).
const (
	AlgES256 = "ES256" // ECDSA on P-256, SHA-256
	AlgES384 = "ES384" // ECDSA on P-384, SHA-384
	AlgES512 = "ES512" // ECDSA on P-521, SHA-512 (note: curve is 521, alg name is 512)
	AlgRS256 = "RS256" // RSA 2048, SHA-256 (RSASSA-PKCS1-v1_5)
	AlgRS384 = "RS384" // RSA 3072, SHA-384 (RSASSA-PKCS1-v1_5)
	AlgRS512 = "RS512" // RSA 4096, SHA-512 (RSASSA-PKCS1-v1_5)
	AlgPS256 = "PS256" // RSA 2048, SHA-256 (RSASSA-PSS)
	AlgPS384 = "PS384" // RSA 3072, SHA-384 (RSASSA-PSS)
	AlgPS512 = "PS512" // RSA 4096, SHA-512 (RSASSA-PSS)
)

// Generate returns a freshly generated asymmetric key pair for the given
// JOSE algorithm, encoded as JWK JSON (RFC 7517 / RFC 7518). publicJWK holds
// the public members only and is safe to publish at the JWKS endpoint.
// privateJWK holds the same members plus the private ones, and must be sealed
// by the Cipher before it reaches oidc_keys.private_key.
func Generate(alg string) (publicJWK, privateJWK []byte, err error) {
	switch alg {
	case AlgES256:
		return generateECDSA(alg, elliptic.P256())
	case AlgES384:
		return generateECDSA(alg, elliptic.P384())
	case AlgES512:
		return generateECDSA(alg, elliptic.P521())
	case AlgRS256:
		return generateRSA(alg, 2048)
	case AlgRS384:
		return generateRSA(alg, 3072)
	case AlgRS512:
		return generateRSA(alg, 4096)
	// PS* (RSASSA-PSS) sign with ordinary RSA keys: the PSS padding is chosen at
	// signing time by the JOSE `alg`, not by the key material, so the same RSA
	// generation backs both RS* and PS* at the matching modulus size.
	case AlgPS256:
		return generateRSA(alg, 2048)
	case AlgPS384:
		return generateRSA(alg, 3072)
	case AlgPS512:
		return generateRSA(alg, 4096)
	default:
		return nil, nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// jsonWebKey is the wire shape of one JWK. Members absent for a key type are
// omitted, so the same struct serves both EC and RSA keys, public and private.
// No `kid` is set here: the oidc_keys row id is the kid, and it is added when
// the key set is read.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`

	// EC members.
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// RSA members.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// Private members. D is the private scalar for EC and the private exponent
	// for RSA; the rest are the RSA primes and CRT values.
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	Dp string `json:"dp,omitempty"`
	Dq string `json:"dq,omitempty"`
	Qi string `json:"qi,omitempty"`
}

func generateECDSA(alg string, curve elliptic.Curve) ([]byte, []byte, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate EC key: %w", err)
	}
	// RFC 7518 section 6.2.1 fixes x, y and d at the octet length of the curve,
	// so short values keep their leading zeros.
	size := (curve.Params().BitSize + 7) / 8
	pub := jsonWebKey{
		Kty: "EC",
		Alg: alg,
		Use: "sig",
		Crv: curve.Params().Name,
		X:   b64Fixed(priv.X, size),
		Y:   b64Fixed(priv.Y, size),
	}
	full := pub
	full.D = b64Fixed(priv.D, size)
	return marshalKeyPair(pub, full)
}

func generateRSA(alg string, bits int) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA-%d key: %w", bits, err)
	}
	pub := jsonWebKey{
		Kty: "RSA",
		Alg: alg,
		Use: "sig",
		N:   b64Int(priv.N),
		E:   b64Int(big.NewInt(int64(priv.E))),
	}
	full := pub
	full.D = b64Int(priv.D)
	full.P = b64Int(priv.Primes[0])
	full.Q = b64Int(priv.Primes[1])
	full.Dp = b64Int(priv.Precomputed.Dp)
	full.Dq = b64Int(priv.Precomputed.Dq)
	full.Qi = b64Int(priv.Precomputed.Qinv)
	return marshalKeyPair(pub, full)
}

func marshalKeyPair(pub, priv jsonWebKey) ([]byte, []byte, error) {
	publicJWK, err := json.Marshal(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public JWK: %w", err)
	}
	privateJWK, err := json.Marshal(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private JWK: %w", err)
	}
	return publicJWK, privateJWK, nil
}

// b64Int encodes a JWK integer member: big-endian, no leading zero octet.
func b64Int(v *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(v.Bytes())
}

// b64Fixed encodes a JWK integer member padded to a fixed octet length.
func b64Fixed(v *big.Int, size int) string {
	return base64.RawURLEncoding.EncodeToString(v.FillBytes(make([]byte, size)))
}

// Cipher provides authenticated symmetric encryption (AES-256-GCM) for
// protecting *reversible* secrets at rest — values that must be recovered
// later, not merely compared. Examples: oidc_keys.private_key and
// application_oidc_configs client secrets.
//
// The 256-bit AES key is derived from the configured key string via SHA-256, so
// any sufficiently long, random DATABASE_ENCRYPTION_KEY is accepted regardless
// of its length or encoding.
// Sealed output is self-describing: it carries a version magic and the id of
// the key that sealed it, so two keys can coexist and root-key rotation becomes
// possible (harden-core F-5). See keyring.go for the wire shape, the legacy
// headerless case, and AddPriorKey.
type Cipher struct {
	aead  cipher.AEAD
	keyID string
	// prior holds keys that may still open stored blobs but never seal new
	// ones. Populated only by AddPriorKey, during a rotation.
	prior map[string]cipher.AEAD
}

// encKeyDomain domain-separates the AES key from any other use of the same
// configured secret. Bump the version suffix only with a key-migration plan,
// since it changes the derived key (old ciphertexts stop decrypting).
const encKeyDomain = "ao:db-encryption:aes-256-gcm:v1\x00"

// NewCipher builds a Cipher from a non-empty key string.
func NewCipher(key string) (*Cipher, error) {
	aead, id, err := aeadFor(key)
	if err != nil {
		return nil, err
	}
	if len(id) > maxKeyIDLen {
		return nil, fmt.Errorf("crypto: key id %q is too long for the header", id)
	}
	return &Cipher{aead: aead, keyID: id}, nil
}

// Encrypt seals plaintext, returning header||nonce||ciphertext||tag. A fresh
// random nonce is drawn per call, so equal plaintexts produce distinct
// ciphertexts. The header names the key, so a later rotation can tell this blob
// apart from one sealed under a different one.
func (c *Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	out := append(c.header(), nonce...)
	// Seal appends the ciphertext+tag after the nonce, so the payload is
	// self-framing behind the header.
	return c.aead.Seal(out, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt. It dispatches on the key id in the header, falling
// back to the current key for pre-header (legacy) ciphertext. It fails if the
// data was truncated or tampered with (GCM authentication), or if the key that
// sealed it is not on the ring.
func (c *Cipher) Decrypt(data []byte) ([]byte, error) {
	aead, payload, err := c.aeadForBlob(data)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(payload) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce, ciphertext := payload[:ns], payload[ns:]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}

// otpAlphabet is the character set used for one-time passwords.
// 70 characters: 26 upper + 26 lower + 10 digits + 8 symbols.
const otpAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"

// otpLength is the number of characters in a generated one-time password.
// 24 chars over a 70-char alphabet ≈ 147 bits of entropy.
const otpLength = 24

// OneTimePassword returns a 24-character random password suitable for
// bootstrap credentials that the recipient must change on first use.
// Bytes are drawn from crypto/rand using rejection sampling so the
// distribution is uniform.
func OneTimePassword() (string, error) {
	// Largest multiple of len(otpAlphabet) that fits in a byte. Reject any
	// random byte at or above this cutoff to avoid modulo bias.
	const cutoff = 256 - (256 % len(otpAlphabet))

	out := make([]byte, 0, otpLength)
	buf := make([]byte, otpLength)
	for len(out) < otpLength {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("read random bytes: %w", err)
		}
		for _, b := range buf {
			if int(b) >= cutoff {
				continue
			}
			out = append(out, otpAlphabet[int(b)%len(otpAlphabet)])
			if len(out) == otpLength {
				break
			}
		}
	}
	return string(out), nil
}

// tokenBytes is the entropy of a RandomToken: 32 bytes (256 bits), which
// hex-encodes to 64 characters — matching the `openssl rand -hex 32`
// convention documented for AO_LOGIN_UI_PAT.
const tokenBytes = 32

// RandomToken returns a hex-encoded, cryptographically random shared secret
// with 256 bits of entropy, suitable for bearer-style secrets such as the
// login-ui PAT (AO_LOGIN_UI_PAT).
func RandomToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("crypto: read random bytes: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
