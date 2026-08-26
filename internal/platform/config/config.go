// Package config loads application configuration with viper.
//
// Precedence (highest wins): environment variables (AO_*) > cmd/config.yaml > defaults.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/viper"
)

type Config struct {
	App          AppConfig
	Server       ServerConfig
	Database     DatabaseConfig
	Redis        RedisConfig
	Log          LogConfig
	OIDC         OIDCConfig
	Auth         AuthConfig
	Notification NotificationConfig
}

// NotificationConfig is the deployment-wide default and fallback for outbound mail.
// Per-tenant settings in notification_settings override every field; when a
// tenant has no row, these apply. When neither yields a usable transport the
// Notifier falls back to the log transport (it never fails startup). Bound to
// AO_NOTIFICATION_* env vars.
type NotificationConfig struct {
	// Transport selects the deployment default delivery: "smtp" or "log". Defaults
	// to "log", so an unconfigured deployment is safe (renders + logs, never
	// sends). Set to "smtp" with the SMTP* fields to actually deliver.
	Transport string `mapstructure:"transport"`

	SMTPHost     string `mapstructure:"smtp_host"`
	SMTPPort     int    `mapstructure:"smtp_port"`
	SMTPUsername string `mapstructure:"smtp_username"`
	SMTPPassword string `mapstructure:"smtp_password"`

	FromAddress string `mapstructure:"from_address"`
	FromName    string `mapstructure:"from_name"`

	// TLSMode is the SMTP connection security: "starttls" (upgrade on 587),
	// "tls" (implicit TLS on 465), or "none" (dev only). Defaults to "starttls".
	TLSMode string `mapstructure:"tls_mode"`

	// SendTimeout bounds a single send (dial + conversation). Defaults to 10s.
	SendTimeout time.Duration `mapstructure:"send_timeout"`
}

// UsableSMTP reports whether the deployment SMTP transport is configured well
// enough to attempt a send (host + from address present). The Notifier uses it
// to decide the deployment-default → log fallback without failing startup.
func (n NotificationConfig) UsableSMTP() bool {
	return n.SMTPHost != "" && n.FromAddress != ""
}

// AuthConfig holds the login-ui shared PAT. The lockout / password / recovery
// policy that used to live here (AO_AUTH_*) moved into the database as the sole
// source of truth (auth_policy_settings, move-auth-settings-to-db) — resolved
// per tenant + org at runtime, with code-default constants in internal/authpolicy
// as the floor.
type AuthConfig struct {
	// LoginUIPATs is the SET of accepted login PATs, so the BFF credential can be
	// rotated without a synchronised restart: introduce the new value, roll the
	// BFF, then remove the old one (harden-core F-6). A single value keeps working
	// unchanged — AO_LOGIN_UI_PAT is comma-separated, and viper's slice decode
	// hook turns one value into a one-element set.
	LoginUIPATs []string `mapstructure:"login_ui_pat"`
}

// LoginPATs returns the configured login PATs, trimmed, with empty entries
// dropped — so a trailing comma can never authorize an empty header. Every
// "is the login API configured" check keys off the length of this set, not off a
// string being non-empty. ValidateLoginPATs rejects the blank entry outright at
// startup; this accessor is the fail-safe for every other caller.
func (a AuthConfig) LoginPATs() []string {
	pats := make([]string, 0, len(a.LoginUIPATs))
	for _, p := range a.LoginUIPATs {
		if p = strings.TrimSpace(p); p != "" {
			pats = append(pats, p)
		}
	}
	return pats
}

// ValidateLoginPATs reports a configured-but-blank PAT entry (a stray comma or
// whitespace-only value). It is the startup-time rejection: silently dropping the
// entry would hide a rotation that was typed wrong.
func (a AuthConfig) ValidateLoginPATs() error {
	for i, p := range a.LoginUIPATs {
		if strings.TrimSpace(p) == "" {
			return fmt.Errorf("auth.login_ui_pat entry %d is empty", i+1)
		}
	}
	return nil
}

type AppConfig struct {
	Name        string `mapstructure:"name"`
	Version     string `mapstructure:"version"`
	Environment string `mapstructure:"environment"`
	Timezone    string `mapstructure:"timezone"`
	URL         string `mapstructure:"url"`
	LoginURL    string `mapstructure:"login_url"`
	PortalURL   string `mapstructure:"portal_url"`
	ConsoleURL  string `mapstructure:"console_url"`
}

// IsDevelopment reports whether the process is running in the development
// environment. It is the single, case-insensitive classifier every environment
// branch (the login-PAT guard, the encryption-key guard, the notifier dev-mode
// flag) routes through, so no two subsystems can disagree about the same
// App.Environment value, and the safe-by-default guards fail closed for any
// non-development value.
func (a AppConfig) IsDevelopment() bool {
	return strings.EqualFold(a.Environment, "development")
}

// OIDCConfig holds the process-wide OIDC settings. Per-tenant provider settings
// (issuer, token lifetimes, PKCE, rotation, signing keys) are NOT here — they
// live in the database (oidc_provider_configs / oidc_keys) and are selected per
// request by the request's domain, Zitadel-style. Only routing and host
// resolution, which are shared across tenants, remain process config.
type OIDCConfig struct {
	// PathPrefix namespaces every OIDC endpoint except discovery (e.g. "/oidc").
	// Discovery is always served at /.well-known/openid-configuration. An empty
	// value serves all endpoints at the server root. Shared by every tenant.
	PathPrefix string `mapstructure:"path_prefix"`

	// TenantHeader, when set, is a trusted request header (e.g. "X-AO-Tenant")
	// whose value overrides the request host when resolving the tenant domain. It
	// takes priority over the verified host (the Host header, or a trusted-proxy
	// X-Forwarded-Host). Leave empty to resolve from the verified host only. Only
	// set it when a trusted proxy injects it, since it bypasses the host trust
	// check. Bound to AO_OIDC_TENANT_HEADER.
	TenantHeader string `mapstructure:"tenant_header"`

	// WebAuthnRPID overrides the derived WebAuthn RP ID (the registrable domain of
	// the tenant's issuer/auth host, shared by the login and self-service account
	// passkey ceremonies). Leave EMPTY in production so the RP ID is derived per
	// request from the host's registrable domain (eTLD+1). Set it only for
	// non-registrable dev domains (e.g. "acme.test" or "localhost") where eTLD+1
	// yields no domain the portal and auth hosts share. Bound to AO_WEBAUTHN_RP_ID.
	WebAuthnRPID string `mapstructure:"webauthn_rp_id"`
}

type ServerConfig struct {
	Host       string `mapstructure:"host"`
	Port       int    `mapstructure:"port"`
	HeaderName string `mapstructure:"header_name"`
	Prefork    bool   `mapstructure:"prefork"`

	// TrustedProxies is the allow-list of reverse-proxy/LB IPs or CIDRs whose
	// X-Forwarded-For / X-Forwarded-Host headers Fiber will honor (see
	// FiberConfig). Requests arriving directly from any other peer are treated as
	// untrusted and their forwarding headers are ignored. Defaults to loopback
	// (an on-host nginx). NEVER set this to 0.0.0.0/0 in production — that
	// re-enables header spoofing. Env override AO_SERVER_TRUSTED_PROXIES
	// (comma-separated).
	TrustedProxies []string `mapstructure:"trusted_proxies"`
}

type DatabaseConfig struct {
	Driver   string `mapstructure:"driver"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	SSLMode  bool   `mapstructure:"ssl_mode"`
	// SSLCAPath is an optional path to a PEM CA bundle used to verify the database
	// server certificate when SSLMode is true. When set, the connection verifies
	// against this CA; when empty, TLS still applies but verifies against the host
	// system root store (tls=true). Ignored when SSLMode is false.
	SSLCAPath     string `mapstructure:"ssl_ca_path"`
	EncryptionKey string `mapstructure:"encryption_key"`
	// RootKeyProvider names where the root key (the key protecting every
	// reversible secret at rest) comes from. "env" — the default and the only
	// implementation today — reads DATABASE_ENCRYPTION_KEY. An unrecognised
	// value is an error, not a fallback: silently downgrading to the
	// environment key would defeat the point of configuring a provider at all
	// (harden-core F-5, ticket 17).
	RootKeyProvider string `mapstructure:"root_key_provider"`
	// PriorEncryptionKey is the PREVIOUS root key, read only by the
	// rotate-root-key command so it can decrypt rows not yet re-encrypted. It is
	// never used to seal anything, and a running server ignores it entirely.
	PriorEncryptionKey string             `mapstructure:"prior_encryption_key"`
	Pool               DatabasePoolConfig `mapstructure:"pool"`
}

type DatabasePoolConfig struct {
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime"`
	MaxConnIdleTime time.Duration `mapstructure:"max_conn_idle_time"`
}

type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	Password string `mapstructure:"password"`
	Database int    `mapstructure:"database"`
	// TLS enables TLS for the Redis connection. When false the connection is
	// plaintext, so existing deployments are unaffected until they opt in.
	TLS bool `mapstructure:"tls"`
	// TLSCAPath is an optional path to a PEM CA bundle used to verify the Redis
	// server certificate when TLS is true. When empty, TLS verifies against the
	// host system root store. Ignored when TLS is false.
	TLSCAPath string `mapstructure:"tls_ca_path"`
}

type LogConfig struct {
	Level     string             `mapstructure:"level"`
	Formatter LogFormatterConfig `mapstructure:"formatter"`
}

type LogFormatterConfig struct {
	Format string `mapstructure:"format"`
}

func InitConfig() (*Config, error) {
	// Load .env file first (silently ignore if not found)
	_ = godotenv.Load()

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("cmd/")

	viper.AutomaticEnv()

	// Explicit env bindings (independent of the dot-to-underscore replacer).
	_ = viper.BindEnv("database.root_key_provider", "AO_DATABASE_ROOT_KEY_PROVIDER")
	_ = viper.BindEnv("database.prior_encryption_key", "AO_PRIOR_DATABASE_ENCRYPTION_KEY")

	_ = viper.BindEnv("auth.login_ui_pat", "AO_LOGIN_UI_PAT")
	// Lockout / password / recovery policy is no longer env config — it is resolved
	// per tenant + org from auth_policy_settings (move-auth-settings-to-db).
	_ = viper.BindEnv("oidc.tenant_header", "AO_OIDC_TENANT_HEADER")
	// WebAuthn RP-ID override (shared by login + account passkey ceremonies); empty
	// ⇒ derive the registrable domain of the request host.
	_ = viper.BindEnv("oidc.webauthn_rp_id", "AO_WEBAUTHN_RP_ID")
	// Base URL of the login UI; enables the OIDC login policy when set.
	_ = viper.BindEnv("app.login_url", "AO_LOGIN_URL")
	// IANA zone that drives the process clock. AutomaticEnv alone never reaches
	// Unmarshal for an unset key, so bind it explicitly.
	_ = viper.BindEnv("app.timezone", "AO_APP_TIMEZONE")
	// Reverse-proxy allow-list for trusted X-Forwarded-* headers. Explicit bind so
	// the value flows through Unmarshal; comma-separated CIDRs/IPs when set via env
	// (or a yaml list).
	_ = viper.BindEnv("server.trusted_proxies", "AO_SERVER_TRUSTED_PROXIES")

	// Deployment-wide notification defaults (AO_NOTIFICATION_*). Per-tenant DB
	// settings override these; an unconfigured deployment falls back to the log
	// transport.
	_ = viper.BindEnv("notification.transport", "AO_NOTIFICATION_TRANSPORT")
	_ = viper.BindEnv("notification.smtp_host", "AO_NOTIFICATION_SMTP_HOST")
	_ = viper.BindEnv("notification.smtp_port", "AO_NOTIFICATION_SMTP_PORT")
	_ = viper.BindEnv("notification.smtp_username", "AO_NOTIFICATION_SMTP_USERNAME")
	_ = viper.BindEnv("notification.smtp_password", "AO_NOTIFICATION_SMTP_PASSWORD")
	_ = viper.BindEnv("notification.from_address", "AO_NOTIFICATION_FROM_ADDRESS")
	_ = viper.BindEnv("notification.from_name", "AO_NOTIFICATION_FROM_NAME")
	_ = viper.BindEnv("notification.tls_mode", "AO_NOTIFICATION_TLS_MODE")
	_ = viper.BindEnv("notification.send_timeout", "AO_NOTIFICATION_SEND_TIMEOUT")

	// Set defaults (fallback if neither config file nor env var exists)
	SetDefaultValue()

	if err := viper.ReadInConfig(); err != nil {
		// Allow missing config file — env vars alone are sufficient
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, err
	}

	// App.Timezone drives every time.Now() in the process: log rotation at
	// midnight, timestamps, schedulers. Empty ⇒ keep the OS timezone.
	if cfg.App.Timezone != "" {
		loc, err := time.LoadLocation(cfg.App.Timezone)
		if err != nil {
			return nil, fmt.Errorf("app.timezone %q: %w", cfg.App.Timezone, err)
		}
		time.Local = loc
	}

	return cfg, nil
}

func SetDefaultValue() {
	// OIDC endpoints (except discovery) are namespaced under this prefix.
	viper.SetDefault("oidc.path_prefix", "/oidc/v1")
	// Trust only an on-host reverse proxy by default. Widen to the real LB CIDR
	// in production; never to 0.0.0.0/0.
	viper.SetDefault("server.trusted_proxies", []string{"127.0.0.1/32", "::1/128"})
	// Notification defaults: safe log transport (no send) unless SMTP is
	// configured; STARTTLS on submission port 587; a 10s per-send budget.
	viper.SetDefault("notification.transport", "log")
	viper.SetDefault("notification.smtp_port", 587)
	viper.SetDefault("notification.tls_mode", "starttls")
	viper.SetDefault("notification.send_timeout", "10s")
}
