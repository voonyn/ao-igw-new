package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/luikyv/go-oidc/pkg/goidc"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/utils"
)

// seedKey builds one oidc_keys row the way bootstrap writes it: the public half
// as plain JWK JSON, the private half sealed by the cipher.
func seedKey(t *testing.T, alg string, state int, cipher *aocrypto.Cipher) Key {
	t.Helper()

	publicJWK, privateJWK, err := aocrypto.Generate(alg)
	if err != nil {
		t.Fatalf("generate %s key: %v", alg, err)
	}
	sealed, err := cipher.Encrypt(privateJWK)
	if err != nil {
		t.Fatalf("seal %s key: %v", alg, err)
	}
	return Key{
		ID:         utils.NewUUIDv7(),
		TenantID:   "tenant-1",
		Algorithm:  alg,
		State:      state,
		PublicKey:  publicJWK,
		PrivateKey: sealed,
	}
}

func testCipher(t *testing.T) *aocrypto.Cipher {
	t.Helper()

	cipher, err := aocrypto.NewCipher("a-test-database-encryption-key-32+chars")
	if err != nil {
		t.Fatalf("build cipher: %v", err)
	}
	return cipher
}

// TestPublicKeySet covers what the JWKS endpoint serves: both the active and
// the inactive key, each carrying the row id as its kid, and no private member.
func TestPublicKeySet(t *testing.T) {
	cipher := testCipher(t)
	active := seedKey(t, aocrypto.AlgES256, KeyStateActive, cipher)
	inactive := seedKey(t, aocrypto.AlgES256, KeyStateInactive, cipher)

	set, err := publicKeySet([]Key{active, inactive})
	if err != nil {
		t.Fatalf("build public key set: %v", err)
	}

	if len(set.Keys) != 2 {
		t.Fatalf("key set holds %d keys, want 2", len(set.Keys))
	}
	for _, want := range []Key{active, inactive} {
		jwk, err := set.Key(want.ID)
		if err != nil {
			t.Fatalf("key set is missing kid %s: %v", want.ID, err)
		}
		if !jwk.IsPublic() {
			t.Errorf("kid %s carries private material", want.ID)
		}
		if jwk.Algorithm != want.Algorithm {
			t.Errorf("kid %s has alg %q, want %q", want.ID, jwk.Algorithm, want.Algorithm)
		}
		raw, err := jwk.MarshalJSON()
		if err != nil {
			t.Fatalf("marshal kid %s: %v", want.ID, err)
		}
		var members map[string]any
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatalf("published key %s is not JSON: %v", want.ID, err)
		}
		if _, ok := members["d"]; ok {
			t.Errorf("published key %s carries the private member d", want.ID)
		}
	}
}

// TestSigningKey covers signer selection: only the active key signs, the
// signature verifies against the published public half, and the returned kid
// names that key.
func TestSigningKey(t *testing.T) {
	cipher := testCipher(t)
	active := seedKey(t, aocrypto.AlgES256, KeyStateActive, cipher)
	inactive := seedKey(t, aocrypto.AlgES256, KeyStateInactive, cipher)

	kid, signer, err := signingKey([]Key{active, inactive}, cipher, goidc.SigAlgES256)
	if err != nil {
		t.Fatalf("select signing key: %v", err)
	}
	if kid != active.ID {
		t.Fatalf("signer kid is %s, want the active key %s", kid, active.ID)
	}

	digest := sha256.Sum256([]byte("an ID token to sign"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	set, err := publicKeySet([]Key{active, inactive})
	if err != nil {
		t.Fatalf("build public key set: %v", err)
	}
	jwk, err := set.Key(kid)
	if err != nil {
		t.Fatalf("published set is missing kid %s: %v", kid, err)
	}
	pub, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("published key %s is a %T, want *ecdsa.PublicKey", kid, jwk.Key)
	}

	// The signer answers in the JOSE form: r and s, each padded to the octet
	// length of the curve. TestSigningKey_JOSESignature covers why.
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*size {
		t.Fatalf("signature is %d bytes, want %d", len(signature), 2*size)
	}
	r := new(big.Int).SetBytes(signature[:size])
	s := new(big.Int).SetBytes(signature[size:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Error("the signature does not verify against the published public key")
	}
}

// TestSigningKey_JOSESignature covers the contract the protocol engine holds
// the signer to. The engine hands the signer to go-jose, which writes what it
// returns straight into the JWS, so an EC signature must carry the fixed-width
// r||s form of RFC 7518, never the ASN.1 form crypto.Signer returns by default.
//
// A token signed the wrong way verifies nowhere: not at the userinfo endpoint,
// and not at any client.
func TestSigningKey_JOSESignature(t *testing.T) {
	cipher := testCipher(t)
	active := seedKey(t, aocrypto.AlgES256, KeyStateActive, cipher)

	kid, signer, err := signingKey([]Key{active}, cipher, goidc.SigAlgES256)
	if err != nil {
		t.Fatalf("select signing key: %v", err)
	}

	joseSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       joseOpaqueSigner{kid: kid, signer: signer},
	}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("build jose signer: %v", err)
	}
	token, err := jwt.Signed(joseSigner).Claims(map[string]any{"sub": "user-1"}).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	set, err := publicKeySet([]Key{active})
	if err != nil {
		t.Fatalf("build public key set: %v", err)
	}
	jwk, err := set.Key(kid)
	if err != nil {
		t.Fatalf("published set is missing kid %s: %v", kid, err)
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	var claims map[string]any
	if err := parsed.Claims(jwk.Key, &claims); err != nil {
		t.Fatalf("the token does not verify against the published key: %v", err)
	}
	if claims["sub"] != "user-1" {
		t.Errorf("token carries sub %v, want user-1", claims["sub"])
	}
}

// joseOpaqueSigner is how the protocol engine wraps the signer this package
// returns. It repeats what goidc does, so the test signs the way the running
// server signs.
type joseOpaqueSigner struct {
	kid    string
	signer crypto.Signer
}

func (s joseOpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{KeyID: s.kid, Key: s.signer.Public(), Algorithm: string(goidc.SigAlgES256)}
}

func (s joseOpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

func (s joseOpaqueSigner) SignPayload(payload []byte, _ jose.SignatureAlgorithm) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return s.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
}

// TestSigningKey_NoActiveKey covers the failure a provider build must catch: a
// tenant whose only key cannot sign.
func TestSigningKey_NoActiveKey(t *testing.T) {
	cipher := testCipher(t)
	inactive := seedKey(t, aocrypto.AlgES256, KeyStateInactive, cipher)

	if _, _, err := signingKey([]Key{inactive}, cipher, goidc.SigAlgES256); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("error is %v, want ErrNoSigningKey", err)
	}
}
