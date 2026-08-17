package crypto

import (
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// testCurve maps a JWK `crv` name to its curve, so the tests can recompute the
// public point independently of the implementation.
var testCurve = map[string]elliptic.Curve{
	"P-256": elliptic.P256(),
	"P-384": elliptic.P384(),
	"P-521": elliptic.P521(),
}

// jwk is the wire shape the tests read back. Expected member names come from
// RFC 7517 / RFC 7518, not from the implementation.
type jwk struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	N   string `json:"n"`
	E   string `json:"e"`
	P   string `json:"p"`
	Q   string `json:"q"`
	Dp  string `json:"dp"`
	Dq  string `json:"dq"`
	Qi  string `json:"qi"`
}

func parseJWK(t *testing.T, raw []byte) jwk {
	t.Helper()
	var k jwk
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("parse JWK %q: %v", raw, err)
	}
	return k
}

// b64uint decodes a base64url JWK member into a big integer.
func b64uint(t *testing.T, member, value string) *big.Int {
	t.Helper()
	if strings.ContainsAny(value, "+/=") {
		t.Errorf("member %q is not base64url without padding: %q", member, value)
	}
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode member %q: %v", member, err)
	}
	return new(big.Int).SetBytes(b)
}

func TestGenerate_ECDSA_AllCurves(t *testing.T) {
	cases := []struct {
		alg      string
		crv      string
		coordLen int // fixed octet length of x, y and d for this curve
	}{
		{AlgES256, "P-256", 32},
		{AlgES384, "P-384", 48},
		{AlgES512, "P-521", 66},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			pubJWK, privJWK, err := Generate(c.alg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			pub := parseJWK(t, pubJWK)
			if pub.Kty != "EC" {
				t.Errorf("public kty: expected EC, got %q", pub.Kty)
			}
			if pub.Crv != c.crv {
				t.Errorf("public crv: expected %s, got %q", c.crv, pub.Crv)
			}
			if pub.Alg != c.alg {
				t.Errorf("public alg: expected %s, got %q", c.alg, pub.Alg)
			}
			if pub.Use != "sig" {
				t.Errorf("public use: expected sig, got %q", pub.Use)
			}
			if pub.D != "" {
				t.Error("public JWK carries the private member d")
			}
			for member, value := range map[string]string{"x": pub.X, "y": pub.Y} {
				b, err := base64.RawURLEncoding.DecodeString(value)
				if err != nil {
					t.Fatalf("decode %q: %v", member, err)
				}
				if len(b) != c.coordLen {
					t.Errorf("member %q: expected %d octets, got %d", member, c.coordLen, len(b))
				}
			}

			priv := parseJWK(t, privJWK)
			if priv.X != pub.X || priv.Y != pub.Y || priv.Crv != pub.Crv {
				t.Error("private JWK does not carry the same public half")
			}
			d := b64uint(t, "d", priv.D)
			if d.Sign() == 0 {
				t.Fatal("private member d is zero")
			}
			// Independent check: the published point must be d*G on the curve.
			curve := testCurve[c.crv]
			wantX, wantY := curve.ScalarBaseMult(d.Bytes())
			if wantX.Cmp(b64uint(t, "x", pub.X)) != 0 || wantY.Cmp(b64uint(t, "y", pub.Y)) != 0 {
				t.Error("published point is not the public half of d")
			}
		})
	}
}

func TestGenerate_RSA_AllSizes(t *testing.T) {
	// PS* (RSASSA-PSS) reuse plain RSA keys — only the signing padding differs —
	// so they generate the same RSA material at the matching modulus size.
	cases := []struct {
		alg  string
		bits int
	}{
		{AlgRS256, 2048},
		{AlgRS384, 3072},
		{AlgRS512, 4096},
		{AlgPS256, 2048},
		{AlgPS384, 3072},
		{AlgPS512, 4096},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			pubJWK, privJWK, err := Generate(c.alg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			pub := parseJWK(t, pubJWK)
			if pub.Kty != "RSA" {
				t.Errorf("public kty: expected RSA, got %q", pub.Kty)
			}
			if pub.Alg != c.alg {
				t.Errorf("public alg: expected %s, got %q", c.alg, pub.Alg)
			}
			if pub.Use != "sig" {
				t.Errorf("public use: expected sig, got %q", pub.Use)
			}
			if pub.D != "" {
				t.Error("public JWK carries the private member d")
			}
			n := b64uint(t, "n", pub.N)
			if n.BitLen() != c.bits {
				t.Errorf("expected %d-bit modulus, got %d", c.bits, n.BitLen())
			}
			// RFC 7518 fixes the public exponent members; Go generates e = 65537.
			if e := b64uint(t, "e", pub.E); e.Int64() != 65537 {
				t.Errorf("expected exponent 65537, got %s", e)
			}

			priv := parseJWK(t, privJWK)
			if priv.N != pub.N || priv.E != pub.E {
				t.Error("private JWK does not carry the same public half")
			}
			p := b64uint(t, "p", priv.P)
			q := b64uint(t, "q", priv.Q)
			// Independent check: the primes must multiply back to the modulus.
			if new(big.Int).Mul(p, q).Cmp(n) != 0 {
				t.Error("p*q does not equal the published modulus n")
			}
			// And the CRT members must agree with d mod (p-1), (q-1).
			d := b64uint(t, "d", priv.D)
			one := big.NewInt(1)
			if want := new(big.Int).Mod(d, new(big.Int).Sub(p, one)); want.Cmp(b64uint(t, "dp", priv.Dp)) != 0 {
				t.Error("dp is not d mod (p-1)")
			}
			if want := new(big.Int).Mod(d, new(big.Int).Sub(q, one)); want.Cmp(b64uint(t, "dq", priv.Dq)) != 0 {
				t.Error("dq is not d mod (q-1)")
			}
			if want := new(big.Int).ModInverse(q, p); want.Cmp(b64uint(t, "qi", priv.Qi)) != 0 {
				t.Error("qi is not the inverse of q mod p")
			}
		})
	}
}

func TestGenerate_UnknownAlgorithm(t *testing.T) {
	_, _, err := Generate("HS256")
	if err == nil {
		t.Fatal("expected error for unknown algorithm, got nil")
	}
	if !strings.Contains(err.Error(), "HS256") {
		t.Errorf("expected error to mention algorithm name, got %q", err)
	}
}

func TestGenerate_Uniqueness(t *testing.T) {
	for _, alg := range []string{AlgES256, AlgES384, AlgES512, AlgPS256, AlgPS384, AlgPS512} {
		t.Run(alg, func(t *testing.T) {
			_, priv1, err := Generate(alg)
			if err != nil {
				t.Fatalf("first generate: %v", err)
			}
			_, priv2, err := Generate(alg)
			if err != nil {
				t.Fatalf("second generate: %v", err)
			}
			if string(priv1) == string(priv2) {
				t.Error("two consecutive generations produced identical private keys")
			}
		})
	}
}

func TestOneTimePassword_LengthAndAlphabet(t *testing.T) {
	pw, err := OneTimePassword()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pw) != otpLength {
		t.Errorf("expected length %d, got %d", otpLength, len(pw))
	}
	for i, c := range pw {
		if !strings.ContainsRune(otpAlphabet, c) {
			t.Errorf("char %d (%q) not in allowed alphabet", i, c)
		}
	}
}

func TestOneTimePassword_Uniqueness(t *testing.T) {
	pw1, err := OneTimePassword()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	pw2, err := OneTimePassword()
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if pw1 == pw2 {
		t.Error("two consecutive OTPs were identical (vanishingly unlikely; test broken or RNG broken)")
	}
}

func TestRandomToken_LengthAndAlphabet(t *testing.T) {
	tok, err := RandomToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// tokenBytes bytes hex-encode to twice as many characters.
	if want := tokenBytes * 2; len(tok) != want {
		t.Errorf("expected length %d, got %d", want, len(tok))
	}
	for i, c := range tok {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("char %d (%q) is not lowercase hex", i, c)
		}
	}
}

func TestRandomToken_Uniqueness(t *testing.T) {
	tok1, err := RandomToken()
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	tok2, err := RandomToken()
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if tok1 == tok2 {
		t.Error("two consecutive tokens were identical (vanishingly unlikely; test broken or RNG broken)")
	}
}
