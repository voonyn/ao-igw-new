package cmd

import (
	"bufio"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/crypto"
)

// TestGenerateSigningKey_JWKMaterial covers what bootstrap writes into
// oidc_keys: public_key must be readable JWK JSON, because the column is a
// MySQL JSON column and the JWKS endpoint serves the value as it is.
// private_key must be sealed, and must open back into the private JWK.
func TestGenerateSigningKey_JWKMaterial(t *testing.T) {
	cipher, err := crypto.NewCipher("a-test-database-encryption-key-32+chars")
	if err != nil {
		t.Fatalf("build cipher: %v", err)
	}

	key, err := generateSigningKey(crypto.AlgES256, cipher)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}

	var pub map[string]any
	if err := json.Unmarshal(key.publicJWK, &pub); err != nil {
		t.Fatalf("public half is not JSON: %v", err)
	}
	if pub["kty"] != "EC" || pub["alg"] != crypto.AlgES256 {
		t.Errorf("unexpected public JWK header: kty=%v alg=%v", pub["kty"], pub["alg"])
	}
	if _, ok := pub["d"]; ok {
		t.Error("public half carries the private member d")
	}

	if json.Valid(key.privateBlob) {
		t.Error("private half was stored unsealed")
	}
	plain, err := cipher.Decrypt(key.privateBlob)
	if err != nil {
		t.Fatalf("decrypt private half: %v", err)
	}
	var priv map[string]any
	if err := json.Unmarshal(plain, &priv); err != nil {
		t.Fatalf("sealed private half is not JWK JSON: %v", err)
	}
	if _, ok := priv["d"]; !ok {
		t.Error("private half is missing the member d")
	}
	if priv["x"] != pub["x"] || priv["y"] != pub["y"] {
		t.Error("private half does not carry the same public point")
	}
}

// TestGenerateSigningKey_NoCipher covers the development path: with no
// DATABASE_ENCRYPTION_KEY the private half is stored as plain JWK JSON.
func TestGenerateSigningKey_NoCipher(t *testing.T) {
	key, err := generateSigningKey(crypto.AlgRS256, nil)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	var priv map[string]any
	if err := json.Unmarshal(key.privateBlob, &priv); err != nil {
		t.Fatalf("unsealed private half is not JWK JSON: %v", err)
	}
	if priv["kty"] != "RSA" {
		t.Errorf("expected kty RSA, got %v", priv["kty"])
	}
}

// TestNormalizeAppURL covers the pure validation/normalization a seeded SPA
// client origin (console-ui / portal-ui) goes through once a value is chosen:
// bare host gets a scheme (https, or http for loopback), host is lowercased,
// trailing slash trimmed, path preserved, non-http schemes rejected.
func TestNormalizeAppURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "bare FQDN gets https", in: "console.example.com", want: "https://console.example.com"},
		{name: "bare FQDN with port keeps the port", in: "console.example.com:8443", want: "https://console.example.com:8443"},
		{name: "explicit http scheme preserved", in: "http://console.internal:9000", want: "http://console.internal:9000"},
		{name: "loopback host defaults to http", in: "localhost:3002", want: "http://localhost:3002"},
		{name: "loopback IP defaults to http", in: "127.0.0.1:3000", want: "http://127.0.0.1:3000"},
		{name: "trailing slash trimmed", in: "https://console.example.com/", want: "https://console.example.com"},
		{name: "host lowercased, path preserved", in: "https://Console.Example.COM/app", want: "https://console.example.com/app"},
		{name: "non-http scheme rejected", in: "ftp://console.example.com", wantErr: true},
		{name: "empty rejected", in: "   ", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeAppURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("normalizeAppURL(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeAppURL(%q) returned error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("normalizeAppURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestResolveAppURL covers the precedence the seeded SPA clients use to pick
// their origin: the --console-url / --portal-url flag wins outright; otherwise
// the operator is prompted, with the configured value (or the localhost
// fallback) as the Enter-to-accept default. An empty/EOF response takes the
// default, so piped/CI runs without a flag still resolve.
func TestResolveAppURL(t *testing.T) {
	const fallback = "http://localhost:3002"

	tests := []struct {
		name  string
		flag  string
		cfg   string
		input string // simulated stdin used only when prompted (flag empty)
		want  string
	}{
		{
			name:  "flag wins and skips the prompt",
			flag:  "console.example.com",
			cfg:   "https://from-config.example.com",
			input: "should-be-ignored\n",
			want:  "https://console.example.com",
		},
		{
			name:  "empty prompt response falls back to config default",
			flag:  "",
			cfg:   "https://console.acme.io",
			input: "\n",
			want:  "https://console.acme.io",
		},
		{
			name:  "empty prompt and no config uses localhost default",
			flag:  "",
			cfg:   "",
			input: "\n",
			want:  fallback,
		},
		{
			name:  "EOF (no stdin) takes the default",
			flag:  "",
			cfg:   "",
			input: "",
			want:  fallback,
		},
		{
			name:  "typed bare FQDN overrides the default and gets https",
			flag:  "",
			cfg:   "https://console.acme.io",
			input: "console.typed.io\n",
			want:  "https://console.typed.io",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := bufio.NewReader(strings.NewReader(tc.input))
			got, err := resolveAppURL(r, io.Discard, "console-ui", tc.flag, tc.cfg, fallback)
			if err != nil {
				t.Fatalf("resolveAppURL(flag=%q, cfg=%q) returned error: %v", tc.flag, tc.cfg, err)
			}
			if got != tc.want {
				t.Fatalf("resolveAppURL(flag=%q, cfg=%q, input=%q) = %q, want %q", tc.flag, tc.cfg, tc.input, got, tc.want)
			}
		})
	}
}

// TestSeededResourceIndicators covers what bootstrap writes into
// oidc_provider_configs.resource_indicators. The column is a MySQL JSON column,
// so the value must bind as a JSON string, and it must hold exactly the two
// identifiers the front ends send at /authorize: console-ui sends
// urn:alphaomega:admin-api, portal-ui sends urn:alphaomega:account-api. A
// mismatch makes the authorization server refuse the resource, and sign-in
// stops there.
func TestSeededResourceIndicators(t *testing.T) {
	raw, err := toJSON(oidc.SeedResourceIndicators)
	if err != nil {
		t.Fatalf("marshal resource indicators: %v", err)
	}

	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("seeded value is not JSON: %v", err)
	}

	want := []string{"urn:alphaomega:admin-api", "urn:alphaomega:account-api"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("seeded resource indicators = %v, want %v", got, want)
	}
}
