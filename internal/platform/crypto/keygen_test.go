package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
)

func TestGenerate_ECDSA_AllCurves(t *testing.T) {
	cases := []struct {
		alg   string
		curve elliptic.Curve
	}{
		{AlgES256, elliptic.P256()},
		{AlgES384, elliptic.P384()},
		{AlgES512, elliptic.P521()},
	}
	for _, c := range cases {
		t.Run(c.alg, func(t *testing.T) {
			pubDER, privDER, err := Generate(c.alg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(pubDER) == 0 || len(privDER) == 0 {
				t.Fatalf("expected non-empty key bytes, got pub=%d priv=%d", len(pubDER), len(privDER))
			}

			pub, err := x509.ParsePKIXPublicKey(pubDER)
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			ecPub, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
			}
			if ecPub.Curve != c.curve {
				t.Errorf("expected curve %v, got %v", c.curve, ecPub.Curve)
			}

			priv, err := x509.ParsePKCS8PrivateKey(privDER)
			if err != nil {
				t.Fatalf("parse private: %v", err)
			}
			ecPriv, ok := priv.(*ecdsa.PrivateKey)
			if !ok {
				t.Fatalf("expected *ecdsa.PrivateKey, got %T", priv)
			}
			if ecPriv.Curve != c.curve {
				t.Errorf("expected private curve %v, got %v", c.curve, ecPriv.Curve)
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
			pubDER, privDER, err := Generate(c.alg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			pub, err := x509.ParsePKIXPublicKey(pubDER)
			if err != nil {
				t.Fatalf("parse public: %v", err)
			}
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("expected *rsa.PublicKey, got %T", pub)
			}
			if rsaPub.N.BitLen() != c.bits {
				t.Errorf("expected %d-bit modulus, got %d", c.bits, rsaPub.N.BitLen())
			}

			priv, err := x509.ParsePKCS8PrivateKey(privDER)
			if err != nil {
				t.Fatalf("parse private: %v", err)
			}
			if _, ok := priv.(*rsa.PrivateKey); !ok {
				t.Fatalf("expected *rsa.PrivateKey, got %T", priv)
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
