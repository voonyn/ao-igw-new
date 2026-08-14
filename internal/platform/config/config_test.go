package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

// TestLoadAppliesTimezone pins app.timezone to the process clock: log rotation
// at midnight and every other time.Now() follow it. An unknown zone must fail
// loudly instead of leaving the OS timezone in place.
func TestLoadAppliesTimezone(t *testing.T) {
	viper.Reset()
	defer viper.Reset()
	saved := time.Local
	defer func() { time.Local = saved }()

	t.Setenv("AO_APP_TIMEZONE", "Asia/Kuching")
	if _, err := InitConfig(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if time.Local.String() != "Asia/Kuching" {
		t.Fatalf("time.Local = %s, want Asia/Kuching", time.Local)
	}

	viper.Reset()
	t.Setenv("AO_APP_TIMEZONE", "Mars/Olympus")
	if _, err := InitConfig(); err == nil {
		t.Fatal("expected an error for an unknown timezone, got nil")
	}
}

// TestTrustedProxiesDefaultUnmarshals guards the viper key path for the
// trusted-proxy allow-list: the snake_case default (server.trusted_proxies) must
// reach cfg.Server.TrustedProxies via Unmarshal. Reading it back with a
// camel-case viper key silently returns empty (trust nobody), so this pins the
// mechanism FiberConfig depends on.
func TestTrustedProxiesDefaultUnmarshals(t *testing.T) {
	viper.Reset()
	defer viper.Reset()

	SetDefaultValue()
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.Server.TrustedProxies) == 0 {
		t.Fatal("expected default trusted proxies (loopback), got none — the proxy allow-list would trust nobody")
	}
}

// TestFiberConfigSetsServerHeaderAndAppName pins the viper-key fix: the typed
// config fields must reach the Fiber config (a viper read under the normalized
// keys silently left ServerHeader/AppName unset).
func TestFiberConfigSetsServerHeaderAndAppName(t *testing.T) {
	fc := FiberConfig(nil, "IdentityGateway", "AO-Gateway")
	if fc.AppName != "IdentityGateway" {
		t.Errorf("AppName = %q, want IdentityGateway", fc.AppName)
	}
	if fc.ServerHeader != "AO-Gateway" {
		t.Errorf("ServerHeader = %q, want AO-Gateway", fc.ServerHeader)
	}
}

// TestIsDevelopmentCaseInsensitive pins the single-sourced, case-insensitive
// environment classification.
func TestIsDevelopmentCaseInsensitive(t *testing.T) {
	for _, env := range []string{"development", "Development", "DEVELOPMENT"} {
		if !(AppConfig{Environment: env}).IsDevelopment() {
			t.Errorf("IsDevelopment(%q) = false, want true", env)
		}
	}
	for _, env := range []string{"production", "staging", "dev", ""} {
		if (AppConfig{Environment: env}).IsDevelopment() {
			t.Errorf("IsDevelopment(%q) = true, want false", env)
		}
	}
}

// TestLoginPATsFromEnv pins the F-6 mechanism end to end: a single AO_LOGIN_UI_PAT
// keeps working unchanged, and a comma-separated value arrives as a SET (viper's
// string-to-slice decode hook) so a rotation can overlap. A key bound as a slice
// without its explicit BindEnv silently arrives empty, which would unmount the
// login API — hence the env path, not a struct literal.
func TestLoginPATsFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		env      string
		expected []string
	}{
		{name: "single value", env: "one", expected: []string{"one"}},
		{name: "rotation overlap", env: "one,two", expected: []string{"one", "two"}},
		{name: "entries are trimmed", env: " one , two ", expected: []string{"one", "two"}},
		{name: "trailing comma cannot authorize an empty header", env: "one,", expected: []string{"one"}},
		{name: "unset", env: "", expected: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			defer viper.Reset()
			t.Setenv("AO_LOGIN_UI_PAT", tt.env)

			SetDefaultValue()
			_ = viper.BindEnv("auth.login_ui_pat", "AO_LOGIN_UI_PAT")
			var cfg Config
			if err := viper.Unmarshal(&cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			got := cfg.Auth.LoginPATs()
			if len(got) != len(tt.expected) {
				t.Fatalf("LoginPATs() = %q, want %q", got, tt.expected)
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Fatalf("LoginPATs() = %q, want %q", got, tt.expected)
				}
			}
		})
	}
}

// TestValidateLoginPATsRejectsBlankEntry pins the startup rejection: a stray comma
// is a typed-wrong rotation, and dropping it silently would shrink the accepted
// set without saying so.
func TestValidateLoginPATsRejectsBlankEntry(t *testing.T) {
	if err := (AuthConfig{LoginUIPATs: []string{"one", "  "}}).ValidateLoginPATs(); err == nil {
		t.Fatal("expected a blank PAT entry to be rejected")
	}
	if err := (AuthConfig{LoginUIPATs: []string{"one", "two"}}).ValidateLoginPATs(); err != nil {
		t.Fatalf("valid PAT set rejected: %v", err)
	}
}
