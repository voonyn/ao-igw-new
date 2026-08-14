package cmd

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

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
