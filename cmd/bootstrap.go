package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/authpolicy"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/utils"
)

// Bootstrap identity constants. The AlphaOmega tenant, its default organization
// and its default project are all named "AlphaOmega"; they are distinct entity
// types, so the shared name is unambiguous in context.
const (
	bootstrapTenantName  = "AlphaOmega"
	bootstrapOrgName     = "AlphaOmega"
	bootstrapProjectName = "AlphaOmega"
	bootstrapVersion     = "1"

	roleIAMOwner = "IAM_OWNER" // tenant-level superuser
	roleOrgOwner = "ORG_OWNER" // organization-level owner

	// Token-endpoint auth + subject type for browser SPAs that cannot keep a
	// secret. PKCE (S256) is enforced separately by oidc_provider_configs.
	publicClientAuthMethod = "none"
	publicSubjectType      = "public"
)

// Bootstrap flags. Each, when set, suppresses its interactive prompt so the
// command can run unattended (CI/provisioning). Unset values are prompted for.
var (
	bootstrapDomain        string
	bootstrapAlg           string
	bootstrapAdminEmail    string
	bootstrapAdminUsername string
	bootstrapConsoleURL    string
	bootstrapPortalURL     string
)

// bootstrapCmd performs the one-time, instance-wide initialization of the IAM:
// it creates the AlphaOmega default tenant, organization and project; a default
// admin user wired to all three and granted IAM_OWNER + ORG_OWNER; the console-ui
// and portal-ui OIDC applications (public SPA clients, PKCE); the per-tenant OIDC
// provider config and its primary domain; and two signing keys (one active, one
// standby for the next rotation). It also generates a login-ui PAT
// (AO_LOGIN_UI_PAT) unless one is already configured — printed once for the
// operator to place in env config, never persisted by bootstrap.
//
// The database writes happen in a single transaction whose first statement claims
// the system_bootstrap singleton row (migration 00013). A second invocation hits
// that primary-key/CHECK constraint and is refused, so the routine runs exactly
// once across the system lifecycle.
var bootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "One-time initialization of the IAM (default tenant, admin, apps, OIDC keys, login-ui PAT)",
	Long: "Initialize a fresh IAM instance exactly once: the AlphaOmega default tenant,\n" +
		"organization and project, a default admin user, the console-ui and portal-ui\n" +
		"OIDC applications, the OIDC provider config and two signing keys. Also\n" +
		"generates a login-ui PAT (AO_LOGIN_UI_PAT), shown once, unless one is already\n" +
		"configured.\n\n" +
		"This command can only succeed once — a second run is refused by the\n" +
		"system_bootstrap singleton guard. Run 'migrate up' first.",
	RunE: runBootstrap,
}

func runBootstrap(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	cfg, err := config.InitConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	bdb, err := db.NewDB(cfg.Database, logger.New())
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer bdb.Close() //nolint:errcheck

	// Friendly pre-flight guard. The authoritative, race-safe guard is the
	// INSERT into system_bootstrap inside the transaction below; this check just
	// turns the common "already initialized" / "migrations not run" cases into a
	// clear message instead of a raw SQL error.
	if err := checkNotBootstrapped(ctx, bdb); err != nil {
		return err
	}

	// ── Gather inputs (flags first, then interactive prompts) ──────────────
	reader := bufio.NewReader(cmd.InOrStdin())
	out := cmd.OutOrStdout()

	domain, issuer, err := resolveDomain(reader, out, bootstrapDomain)
	if err != nil {
		return err
	}

	alg, err := resolveAlgorithm(reader, out, bootstrapAlg)
	if err != nil {
		return err
	}

	adminEmail, err := resolveAdminEmail(reader, out, bootstrapAdminEmail)
	if err != nil {
		return err
	}
	adminUsername := strings.TrimSpace(bootstrapAdminUsername)
	if adminUsername == "" {
		adminUsername = adminEmail
	}

	// Origins for the seeded SPA clients; the redirect + post-logout URIs derive
	// from each. Resolved flag → interactive prompt → config/localhost default:
	// when the flag is unset the operator is prompted, with the configured value
	// (or the localhost default) offered as the Enter-to-accept default. Pass the
	// --console-url / --portal-url flags to skip the prompts (CI/unattended).
	consoleURL, err := resolveAppURL(reader, out, "console-ui", bootstrapConsoleURL, cfg.App.ConsoleURL, "http://localhost:3002")
	if err != nil {
		return err
	}
	portalURL, err := resolveAppURL(reader, out, "portal-ui", bootstrapPortalURL, cfg.App.PortalURL, "http://localhost:3001")
	if err != nil {
		return err
	}

	// ── Encryption cipher for sealing private key material ─────────────────
	var cipher *crypto.Cipher
	if cfg.Database.EncryptionKey != "" {
		if cipher, err = crypto.NewCipher(cfg.Database.EncryptionKey); err != nil {
			return fmt.Errorf("build cipher: %w", err)
		}
	} else if strings.EqualFold(cfg.App.Environment, "production") {
		return errors.New("DATABASE_ENCRYPTION_KEY must be set in production: refusing to store OIDC private keys unencrypted")
	}

	// ── Confirmation ───────────────────────────────────────────────────────
	hasLoginUIPAT := len(cfg.Auth.LoginPATs()) > 0
	printPlan(out, domain, issuer, alg, adminEmail, adminUsername, consoleURL, portalURL, cipher != nil, hasLoginUIPAT)
	ok, err := confirm(reader, out, "Proceed with bootstrap? This cannot be undone or repeated. (yes/no): ")
	if err != nil {
		return err
	}
	if !ok {
		fmt.Fprintln(out, "Aborted.")
		return nil
	}

	// ── Generate all material before opening the transaction ───────────────
	bs, err := buildBootstrapData(alg, cipher, adminEmail, adminUsername, consoleURL, portalURL, hasLoginUIPAT)
	if err != nil {
		return err
	}

	// ── Single, all-or-nothing transaction ─────────────────────────────────
	if err := applyBootstrap(ctx, bdb, bs, domain, issuer); err != nil {
		return err
	}

	printSummary(out, bs, domain, issuer, alg, cipher != nil)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Generated data
// ─────────────────────────────────────────────────────────────────────────────

// signingKey is one generated OIDC key pair, already sealed for storage.
type signingKey struct {
	id          string
	publicJWK   []byte // public JWK JSON, stored as it is
	privateBlob []byte // encrypted private JWK JSON, or raw JWK JSON when no cipher
}

// seedApplication is a default OIDC application (public SPA client).
type seedApplication struct {
	id                     string
	name                   string
	clientID               string
	scopes                 string // space-separated; goidc validates requested scopes against this
	redirectURIs           []byte // JSON
	grantTypes             []byte // JSON
	responseTypes          []byte // JSON
	postLogoutRedirectURIs []byte // JSON
}

// bootstrapData is everything the transaction inserts. IDs and key material are
// generated up front so the transaction itself only performs writes.
type bootstrapData struct {
	tenantID  string
	orgID     string
	projectID string

	adminUserID   string
	adminEmail    string
	adminUsername string
	adminPassword string // plaintext OTP, printed once; never persisted
	adminPwdHash  string

	alg        string
	activeKey  signingKey
	standbyKey signingKey

	apps []seedApplication

	// loginUIPAT is a freshly generated shared secret for the login-ui BFF
	// (AO_LOGIN_UI_PAT). It is printed once and never persisted — the PAT lives
	// only in env config, read at server startup. Empty when the operator
	// already configured AO_LOGIN_UI_PAT, in which case bootstrap generates
	// nothing and leaves the existing value untouched.
	loginUIPAT string
}

func buildBootstrapData(alg string, cipher *crypto.Cipher, adminEmail, adminUsername, consoleURL, portalURL string, hasLoginUIPAT bool) (*bootstrapData, error) {
	activeKey, err := generateSigningKey(alg, cipher)
	if err != nil {
		return nil, fmt.Errorf("generate active signing key: %w", err)
	}
	standbyKey, err := generateSigningKey(alg, cipher)
	if err != nil {
		return nil, fmt.Errorf("generate standby signing key: %w", err)
	}

	otp, err := crypto.OneTimePassword()
	if err != nil {
		return nil, fmt.Errorf("generate admin one-time password: %w", err)
	}
	// bcrypt via the same helper the login path verifies with, so the seeded
	// credential and any later rehash always agree.
	pwdHash, err := crypto.HashPassword(otp)
	if err != nil {
		return nil, fmt.Errorf("hash admin password: %w", err)
	}

	// Generate a login-ui PAT only when the operator has not already configured
	// one (AO_LOGIN_UI_PAT). The PAT is not persisted by bootstrap — it is shown
	// once for the operator to place in the gateway env and web/login-ui/.env.local.
	var loginUIPAT string
	if !hasLoginUIPAT {
		if loginUIPAT, err = crypto.RandomToken(); err != nil {
			return nil, fmt.Errorf("generate login-ui PAT: %w", err)
		}
	}

	consoleApp, err := newSeedApplication("console-ui", consoleURL)
	if err != nil {
		return nil, err
	}
	portalApp, err := newSeedApplication("portal-ui", portalURL)
	if err != nil {
		return nil, err
	}

	return &bootstrapData{
		tenantID:      utils.NewUUIDv7(),
		orgID:         utils.NewUUIDv7(),
		projectID:     utils.NewUUIDv7(),
		adminUserID:   utils.NewUUIDv7(),
		adminEmail:    adminEmail,
		adminUsername: adminUsername,
		adminPassword: otp,
		adminPwdHash:  pwdHash,
		alg:           alg,
		activeKey:     activeKey,
		standbyKey:    standbyKey,
		apps:          []seedApplication{consoleApp, portalApp},
		loginUIPAT:    loginUIPAT,
	}, nil
}

func generateSigningKey(alg string, cipher *crypto.Cipher) (signingKey, error) {
	publicJWK, privateJWK, err := crypto.Generate(alg)
	if err != nil {
		return signingKey{}, err
	}
	privateBlob := privateJWK
	if cipher != nil {
		if privateBlob, err = cipher.Encrypt(privateJWK); err != nil {
			return signingKey{}, fmt.Errorf("encrypt private key: %w", err)
		}
	}
	return signingKey{id: utils.NewUUIDv7(), publicJWK: publicJWK, privateBlob: privateBlob}, nil
}

func newSeedApplication(name, baseURL string) (seedApplication, error) {
	base := strings.TrimRight(baseURL, "/")
	redirects, err := toJSON([]string{base + "/auth/callback"})
	if err != nil {
		return seedApplication{}, err
	}
	grants, err := toJSON([]string{"authorization_code", "refresh_token"})
	if err != nil {
		return seedApplication{}, err
	}
	responses, err := toJSON([]string{"code"})
	if err != nil {
		return seedApplication{}, err
	}
	postLogout, err := toJSON([]string{base + "/"})
	if err != nil {
		return seedApplication{}, err
	}
	return seedApplication{
		id:                     utils.NewUUIDv7(),
		name:                   name,
		clientID:               utils.NewUUIDv7(),
		scopes:                 "openid profile email offline_access",
		redirectURIs:           redirects,
		grantTypes:             grants,
		responseTypes:          responses,
		postLogoutRedirectURIs: postLogout,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence
// ─────────────────────────────────────────────────────────────────────────────

const appTypeOIDC = 1 // applications.app_type: 1=oidc

// applyBootstrap writes every seed row inside one transaction.
//
// Deliberate exception to the router→service→repository rule: this uses raw SQL
// over the tx instead of the repositories. The repositories each open their own
// connection and expose no caller-supplied *bun.Tx, so routing through them
// would break the single-transaction atomicity this one-time init needs — the
// singleton-lock claim and all seeds must commit or roll back together.
// ponytail: raw SQL here; if a seed's SQL ever drifts from its repository's,
// add a Tx-accepting repo variant (e.g. seedBuiltinScopes) rather than more raw SQL.
func applyBootstrap(ctx context.Context, db *bun.DB, bs *bootstrapData, domain, issuer string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	// Claim the singleton first: a concurrent or repeat run fails here before any
	// other write, and the whole transaction rolls back.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO system_bootstrap (id, tenant_id, version) VALUES (1, ?, ?)`,
		bs.tenantID, bootstrapVersion,
	); err != nil {
		return fmt.Errorf("claim bootstrap lock (already initialized?): %w", err)
	}

	if err := seedTenantHierarchy(ctx, tx, bs); err != nil {
		return err
	}
	if err := seedAdminUser(ctx, tx, bs); err != nil {
		return err
	}
	if err := seedApplications(ctx, tx, bs); err != nil {
		return err
	}
	if err := seedProviderConfig(ctx, tx, bs, domain, issuer); err != nil {
		return err
	}
	// Builtin OIDC scopes + standard claim mappers, matching the existing-tenant
	// backfill (migration 00020). Without these the DB-driven WithScopes would
	// advertise only `openid` and the seeded SPA clients (scopes
	// "openid profile email offline_access") would fail with invalid_scope.
	if err := seedBuiltinScopes(ctx, tx, bs.tenantID); err != nil {
		return err
	}
	if err := seedSigningKeys(ctx, tx, bs); err != nil {
		return err
	}
	// Seed the tenant-wide auth-policy default row (org_id = '') from the code
	// defaults so the operator sees editable lockout/password/recovery values in the
	// console immediately (move-auth-settings-to-db).
	if err := seedAuthPolicyDefault(ctx, tx, bs.tenantID); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// seedTenantHierarchy inserts the tenant, its default organization and project,
// and points the tenant at that org.
func seedTenantHierarchy(ctx context.Context, tx bun.Tx, bs *bootstrapData) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tenants (id, name, state) VALUES (?, ?, 1)`,
		bs.tenantID, bootstrapTenantName,
	); err != nil {
		return fmt.Errorf("insert tenant: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO organizations (id, tenant_id, name, state) VALUES (?, ?, ?, 1)`,
		bs.orgID, bs.tenantID, bootstrapOrgName,
	); err != nil {
		return fmt.Errorf("insert organization: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE tenants SET default_org_id = ? WHERE id = ?`,
		bs.orgID, bs.tenantID,
	); err != nil {
		return fmt.Errorf("set tenant default org: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO projects (id, tenant_id, org_id, name, state) VALUES (?, ?, ?, ?, 1)`,
		bs.projectID, bs.tenantID, bs.orgID, bootstrapProjectName,
	); err != nil {
		return fmt.Errorf("insert project: %w", err)
	}
	return nil
}

// seedAdminUser inserts the admin user + human profile and grants IAM_OWNER
// (tenant) and ORG_OWNER (org).
func seedAdminUser(ctx context.Context, tx bun.Tx, bs *bootstrapData) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
		 VALUES (?, ?, ?, ?, 1, 1)`,
		bs.adminUserID, bs.tenantID, bs.orgID, bs.adminUsername,
	); err != nil {
		return fmt.Errorf("insert admin user: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_humans
		   (user_id, tenant_id, first_name, last_name, display_name, preferred_language,
		    email, is_email_verified, password_hash, password_change_required)
		 VALUES (?, ?, 'AlphaOmega', 'Admin', 'AlphaOmega Admin', 'en', ?, 1, ?, 1)`,
		bs.adminUserID, bs.tenantID, bs.adminEmail, bs.adminPwdHash,
	); err != nil {
		return fmt.Errorf("insert admin human profile: %w", err)
	}
	iamRoles, err := toJSON([]string{roleIAMOwner})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tenant_members (tenant_id, user_id, roles) VALUES (?, ?, ?)`,
		bs.tenantID, bs.adminUserID, string(iamRoles),
	); err != nil {
		return fmt.Errorf("grant IAM_OWNER: %w", err)
	}
	orgRoles, err := toJSON([]string{roleOrgOwner})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO organization_members (tenant_id, org_id, user_id, roles) VALUES (?, ?, ?, ?)`,
		bs.tenantID, bs.orgID, bs.adminUserID, string(orgRoles),
	); err != nil {
		return fmt.Errorf("grant ORG_OWNER: %w", err)
	}
	return nil
}

// seedApplications inserts the default first-party public SPA OIDC clients and
// their oidc configs.
func seedApplications(ctx context.Context, tx bun.Tx, bs *bootstrapData) error {
	now := time.Now()
	for _, app := range bs.apps {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO applications (id, tenant_id, project_id, name, app_type, state)
			 VALUES (?, ?, ?, ?, ?, 1)`,
			app.id, bs.tenantID, bs.projectID, app.name, appTypeOIDC,
		); err != nil {
			return fmt.Errorf("insert application %q: %w", app.name, err)
		}
		// The seeded apps are the tenant's own first-party clients: is_first_party=1
		// so they skip the consent screen (add-oidc-consent).
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO application_oidc_configs
			   (app_id, tenant_id, client_id, created_at, token_authn_method, subject_type,
			    scopes, redirect_uris, grant_types, response_types, post_logout_redirect_uris, is_first_party)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
			app.id, bs.tenantID, app.clientID, now, publicClientAuthMethod, publicSubjectType,
			app.scopes, string(app.redirectURIs), string(app.grantTypes),
			string(app.responseTypes), string(app.postLogoutRedirectURIs),
		); err != nil {
			return fmt.Errorf("insert oidc config for %q: %w", app.name, err)
		}
	}
	return nil
}

// seedProviderConfig inserts the tenant's OIDC provider config and primary domain.
func seedProviderConfig(ctx context.Context, tx bun.Tx, bs *bootstrapData, domain, issuer string) error {
	// resource_indicators is a MySQL JSON column, and the driver sends a []byte as
	// a binary string, which MySQL refuses to read as JSON. Bind it as a string.
	resources, err := toJSON(oidc.SeedResourceIndicators)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO oidc_provider_configs (tenant_id, issuer, resource_indicators) VALUES (?, ?, ?)`,
		bs.tenantID, issuer, string(resources),
	); err != nil {
		return fmt.Errorf("insert provider config: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO tenant_domains (domain, tenant_id, is_primary, is_verified, state)
		 VALUES (?, ?, 1, 1, 1)`,
		domain, bs.tenantID,
	); err != nil {
		return fmt.Errorf("insert tenant domain: %w", err)
	}
	return nil
}

// seedSigningKeys inserts the active signing key (serves JWKS now) and a standby
// key for the next rotation (state=2 inactive, no active_at — flip to state=1 to
// promote).
//
// public_key is a MySQL JSON column, and the driver sends a []byte as a binary
// string, which MySQL refuses to read as JSON. The public half is therefore
// bound as a string. private_key is a BLOB and stays bytes.
func seedSigningKeys(ctx context.Context, tx bun.Tx, bs *bootstrapData) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO oidc_keys (id, tenant_id, key_use, algorithm, state, public_key, private_key, active_at)
		 VALUES (?, ?, 1, ?, 1, ?, ?, CURRENT_TIMESTAMP(3))`,
		bs.activeKey.id, bs.tenantID, bs.alg, string(bs.activeKey.publicJWK), bs.activeKey.privateBlob,
	); err != nil {
		return fmt.Errorf("insert active signing key: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO oidc_keys (id, tenant_id, key_use, algorithm, state, public_key, private_key)
		 VALUES (?, ?, 1, ?, 2, ?, ?)`,
		bs.standbyKey.id, bs.tenantID, bs.alg, string(bs.standbyKey.publicJWK), bs.standbyKey.privateBlob,
	); err != nil {
		return fmt.Errorf("insert standby signing key: %w", err)
	}
	return nil
}

// seedAuthPolicyDefault inserts the tenant-wide auth-policy default row
// (org_id = ”) populated from the code-default constants. Env is not readable in
// a goose migration, so this seeding lives in bootstrap/app code, not the
// migration (move-auth-settings-to-db). pw_deny_list is left NULL (no default
// deny-list); the numeric knobs are seeded so the console shows editable values.
func seedAuthPolicyDefault(ctx context.Context, tx bun.Tx, tenantID string) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO auth_policy_settings
		   (tenant_id, org_id, lockout_threshold, lockout_window_ms, lockout_cooldown_ms,
		    pw_min_length, pw_min_classes, pw_check_breach,
		    recovery_reset_ttl_ms, recovery_verify_ttl_ms)
		 VALUES (?, '', ?, ?, ?, ?, ?, ?, ?, ?)`,
		tenantID,
		authpolicy.DefaultLockoutThreshold,
		int(authpolicy.DefaultLockoutWindow/time.Millisecond),
		int(authpolicy.DefaultLockoutCooldown/time.Millisecond),
		authpolicy.DefaultPwMinLength,
		authpolicy.DefaultPwMinClasses,
		authpolicy.DefaultPwCheckBreach,
		int(authpolicy.DefaultRecoveryResetTTL/time.Millisecond),
		int(authpolicy.DefaultRecoveryVerifyTTL/time.Millisecond),
	); err != nil {
		return fmt.Errorf("seed auth policy default: %w", err)
	}
	return nil
}

// builtinScope is a seeded OIDC scope and its standard claim mappers. Kept in
// sync with migration 00020 (existing-tenant backfill) — the two must seed the
// same set so new and pre-existing tenants advertise identical builtins.
type builtinScope struct {
	name        string
	displayName string
	description string
	isDefault   bool
	mappers     []builtinMapper
}

// builtinMapper is a std-attribute (source_type=1) claim mapper delivered to
// UserInfo only, matching the Change-1 fixed resolver.
type builtinMapper struct{ claim, sourceKey string }

var builtinScopes = []builtinScope{
	{"openid", "OpenID", "Subject identifier (required for OIDC).", true, nil},
	{"profile", "Profile", "Basic profile: name, username, locale.", true, []builtinMapper{
		{"name", "name"}, {"given_name", "given_name"}, {"family_name", "family_name"},
		{"preferred_username", "preferred_username"}, {"locale", "locale"}, {"updated_at", "updated_at"},
	}},
	{"email", "Email", "Email address and its verification status.", true, []builtinMapper{
		{"email", "email"}, {"email_verified", "email_verified"},
	}},
	{"offline_access", "Offline access", "Issue a refresh token for offline access.", false, nil},
}

// seedBuiltinScopes inserts the builtin scopes and their standard claim mappers
// for one tenant inside the bootstrap transaction (source_type=1 std attr,
// UserInfo only).
func seedBuiltinScopes(ctx context.Context, tx bun.Tx, tenantID string) error {
	for _, sc := range builtinScopes {
		scopeID := utils.NewUUIDv7()
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO oidc_scopes
			   (id, tenant_id, name, display_name, description, is_enabled, is_default, is_builtin)
			 VALUES (?, ?, ?, ?, ?, 1, ?, 1)`,
			scopeID, tenantID, sc.name, sc.displayName, sc.description, sc.isDefault,
		); err != nil {
			return fmt.Errorf("seed builtin scope %q: %w", sc.name, err)
		}
		for _, m := range sc.mappers {
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO oidc_claim_mappers
				   (id, tenant_id, scope_id, claim_name, source_type, source_key, in_id_token, in_userinfo, in_access_token)
				 VALUES (?, ?, ?, ?, 1, ?, 0, 1, 0)`,
				utils.NewUUIDv7(), tenantID, scopeID, m.claim, m.sourceKey,
			); err != nil {
				return fmt.Errorf("seed builtin mapper %q: %w", m.claim, err)
			}
		}
	}
	return nil
}

// checkNotBootstrapped returns an error if the instance is already initialized,
// or if the schema is missing (migrations not yet applied).
func checkNotBootstrapped(ctx context.Context, db *bun.DB) error {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_bootstrap`).Scan(&count)
	if err != nil {
		return fmt.Errorf("check bootstrap state (did you run 'migrate up'?): %w", err)
	}
	if count > 0 {
		return errors.New("this IAM instance is already initialized; bootstrap can only run once")
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Input gathering
// ─────────────────────────────────────────────────────────────────────────────

func resolveDomain(r *bufio.Reader, w io.Writer, flagVal string) (domain, issuer string, err error) {
	in := strings.TrimSpace(flagVal)
	if in == "" {
		fmt.Fprintln(w, "Default domain for the tenant / OIDC issuer.")
		fmt.Fprintln(w, "  Examples: auth.alphaomega.io   |   localhost:8080")
		in, err = promptLine(r, w, "Domain: ")
		if err != nil {
			return "", "", err
		}
	}
	return normalizeDomain(in)
}

// normalizeDomain reduces a user-entered domain or URL to a bare host (kept
// lowercased, port preserved) and derives the issuer URL. The scheme is https,
// except for loopback/localhost hosts where http is used for local development.
func normalizeDomain(in string) (domain, issuer string, err error) {
	in = strings.ToLower(strings.TrimSpace(in))
	if in == "" {
		return "", "", errors.New("domain is required")
	}
	if strings.Contains(in, "://") {
		u, e := url.Parse(in)
		if e != nil || u.Host == "" {
			return "", "", fmt.Errorf("invalid domain/url %q", in)
		}
		in = u.Host
	}
	in = strings.SplitN(in, "/", 2)[0] // drop any path
	if in == "" {
		return "", "", errors.New("domain is required")
	}

	host := in
	if h, _, e := net.SplitHostPort(in); e == nil {
		host = h
	}
	scheme := "https"
	if isLoopbackHost(host) {
		scheme = "http"
	}
	return in, scheme + "://" + in, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// resolveAppURL determines the origin of a seeded SPA client (console-ui /
// portal-ui). Precedence: the CLI flag wins outright; otherwise the operator is
// prompted, with the configured value (or the localhost fallback) offered as the
// Enter-to-accept default. An empty prompt response (including EOF, e.g. a piped
// CI run) takes that default. The chosen value is validated/normalized by
// normalizeAppURL; the redirect + post-logout URIs derive from it.
func resolveAppURL(r *bufio.Reader, w io.Writer, label, flagVal, cfgVal, fallback string) (string, error) {
	if v := strings.TrimSpace(flagVal); v != "" {
		return normalizeAppURL(v)
	}
	def := originOr(cfgVal, fallback)
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "%s origin — the redirect and post-logout URIs derive from this.\n", label)
	fmt.Fprintln(w, "  A bare host is fine (https assumed; http for localhost). Press Enter for the default.")
	entered, err := promptLine(r, w, fmt.Sprintf("%s URL [%s]: ", label, def))
	if err != nil {
		return "", err
	}
	if entered == "" {
		entered = def
	}
	return normalizeAppURL(entered)
}

// normalizeAppURL validates a supplied application URL or bare FQDN and reduces
// it to an origin (scheme://host[:port], trailing slash trimmed, any optional
// path preserved). The scheme and host are lowercased (both case-insensitive),
// while the path is left untouched. A bare host with no scheme is given https,
// except loopback hosts which get http for local development — matching the
// scheme rule in normalizeDomain. The redirect/post-logout URIs derive from this.
func normalizeAppURL(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" {
		return "", errors.New("application URL is required")
	}
	if !strings.Contains(in, "://") {
		hostPort, _, _ := strings.Cut(in, "/") // host[:port] before any path
		host := hostPort
		if h, _, e := net.SplitHostPort(hostPort); e == nil {
			host = h
		}
		scheme := "https"
		if isLoopbackHost(strings.ToLower(host)) {
			scheme = "http"
		}
		in = scheme + "://" + in
	}
	u, err := url.Parse(in)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid application URL %q", in)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("application URL %q must use http or https", in)
	}
	return strings.TrimRight(u.Scheme+"://"+strings.ToLower(u.Host)+u.Path, "/"), nil
}

func resolveAlgorithm(r *bufio.Reader, w io.Writer, flagVal string) (string, error) {
	if v := strings.TrimSpace(flagVal); v != "" {
		alg := canonicalAlg(v)
		if alg == "" {
			return "", fmt.Errorf("unsupported --alg %q", flagVal)
		}
		return alg, nil
	}

	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "OIDC signing key algorithm (no default — the keys are generated with your choice,")
	fmt.Fprintln(w, "and the provider signs with whatever you pick here):")
	fmt.Fprintln(w, "  1) RS256  (RSA-2048)")
	fmt.Fprintln(w, "  2) RS384  (RSA-3072)")
	fmt.Fprintln(w, "  3) RS512  (RSA-4096)")
	fmt.Fprintln(w, "  4) ES256  (P-256)")
	fmt.Fprintln(w, "  5) ES384  (P-384)")
	fmt.Fprintln(w, "  6) ES512  (P-521)")
	fmt.Fprintln(w, "  7) PS256  (RSA-2048, PSS)")
	fmt.Fprintln(w, "  8) PS384  (RSA-3072, PSS)")
	fmt.Fprintln(w, "  9) PS512  (RSA-4096, PSS)")
	choice, err := promptLine(r, w, "Choice (1-9 or algorithm name): ")
	if err != nil {
		return "", err
	}
	choice = strings.TrimSpace(choice)
	if choice == "" {
		return "", errors.New("algorithm is required: choose 1-9 or pass --alg (there is no default)")
	}
	byNum := map[string]string{
		"1": crypto.AlgRS256, "2": crypto.AlgRS384, "3": crypto.AlgRS512,
		"4": crypto.AlgES256, "5": crypto.AlgES384, "6": crypto.AlgES512,
		"7": crypto.AlgPS256, "8": crypto.AlgPS384, "9": crypto.AlgPS512,
	}
	if alg, ok := byNum[choice]; ok {
		return alg, nil
	}
	if alg := canonicalAlg(choice); alg != "" {
		return alg, nil
	}
	return "", fmt.Errorf("invalid algorithm choice %q", choice)
}

// canonicalAlg maps a case-insensitive algorithm name to its supported constant,
// returning "" if unsupported.
func canonicalAlg(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case crypto.AlgRS256:
		return crypto.AlgRS256
	case crypto.AlgRS384:
		return crypto.AlgRS384
	case crypto.AlgRS512:
		return crypto.AlgRS512
	case crypto.AlgES256:
		return crypto.AlgES256
	case crypto.AlgES384:
		return crypto.AlgES384
	case crypto.AlgES512:
		return crypto.AlgES512
	case crypto.AlgPS256:
		return crypto.AlgPS256
	case crypto.AlgPS384:
		return crypto.AlgPS384
	case crypto.AlgPS512:
		return crypto.AlgPS512
	default:
		return ""
	}
}

func resolveAdminEmail(r *bufio.Reader, w io.Writer, flagVal string) (string, error) {
	in := strings.TrimSpace(flagVal)
	if in == "" {
		fmt.Fprintln(w, "")
		var err error
		in, err = promptLine(r, w, "Default admin email: ")
		if err != nil {
			return "", err
		}
	}
	in = strings.TrimSpace(in)
	at := strings.IndexByte(in, '@')
	if at <= 0 || at == len(in)-1 || !strings.Contains(in[at+1:], ".") {
		return "", fmt.Errorf("invalid admin email %q", in)
	}
	return in, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Output
// ─────────────────────────────────────────────────────────────────────────────

func printPlan(w io.Writer, domain, issuer, alg, email, username, consoleURL, portalURL string, encrypted, loginUIPATConfigured bool) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "About to initialize this IAM instance with:")
	fmt.Fprintf(w, "  Tenant:        %s\n", bootstrapTenantName)
	fmt.Fprintf(w, "  Organization:  %s\n", bootstrapOrgName)
	fmt.Fprintf(w, "  Project:       %s\n", bootstrapProjectName)
	fmt.Fprintf(w, "  Domain:        %s\n", domain)
	fmt.Fprintf(w, "  OIDC issuer:   %s\n", issuer)
	fmt.Fprintf(w, "  Key algorithm: %s  (1 active + 1 standby for rotation)\n", alg)
	fmt.Fprintf(w, "  Admin user:    %s  (username: %s)\n", email, username)
	fmt.Fprintf(w, "  Applications:  console-ui (%s), portal-ui (%s)  [public SPA + PKCE]\n", consoleURL, portalURL)
	if loginUIPATConfigured {
		fmt.Fprintln(w, "  Login UI PAT:  already configured (AO_LOGIN_UI_PAT set — left untouched)")
	} else {
		fmt.Fprintln(w, "  Login UI PAT:  will generate a shared secret for the login-ui BFF (shown once)")
	}
	if !encrypted {
		fmt.Fprintln(w, "  WARNING: DATABASE_ENCRYPTION_KEY is unset — OIDC private keys will be stored UNENCRYPTED (dev only).")
	}
}

func printSummary(w io.Writer, bs *bootstrapData, domain, issuer, alg string, encrypted bool) {
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "✓ IAM bootstrap complete.")
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "  Tenant ID:        %s  (%s)\n", bs.tenantID, bootstrapTenantName)
	fmt.Fprintf(w, "  Organization ID:  %s\n", bs.orgID)
	fmt.Fprintf(w, "  Project ID:       %s\n", bs.projectID)
	fmt.Fprintf(w, "  Domain:           %s\n", domain)
	fmt.Fprintf(w, "  OIDC issuer:      %s\n", issuer)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Applications (OIDC client IDs):")
	for _, app := range bs.apps {
		fmt.Fprintf(w, "    %-11s client_id: %s\n", app.name+":", app.clientID)
	}
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "  Signing keys (%s):\n", alg)
	fmt.Fprintf(w, "    active:   %s  (kid, serving JWKS now)\n", bs.activeKey.id)
	fmt.Fprintf(w, "    standby:  %s  (kid, inactive — promote on next rotation)\n", bs.standbyKey.id)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  ── Admin credentials (shown ONCE — store them now) ──────────────")
	fmt.Fprintf(w, "    Username:        %s\n", bs.adminUsername)
	fmt.Fprintf(w, "    Email:           %s\n", bs.adminEmail)
	fmt.Fprintf(w, "    One-time pass:   %s\n", bs.adminPassword)
	fmt.Fprintln(w, "    (password change is required at first login)")
	fmt.Fprintln(w, "")
	if bs.loginUIPAT != "" {
		fmt.Fprintln(w, "  ── Login UI PAT (shown ONCE — store it now) ─────────────────────")
		fmt.Fprintf(w, "    AO_LOGIN_UI_PAT: %s\n", bs.loginUIPAT)
		fmt.Fprintln(w, "    Set this identical value in BOTH:")
		fmt.Fprintln(w, "      • the gateway environment  (AO_LOGIN_UI_PAT)")
		fmt.Fprintln(w, "      • web/login-ui/.env.local  (AO_LOGIN_UI_PAT)")
		fmt.Fprintln(w, "    The login API is not mounted until the gateway sees this value.")
	} else {
		fmt.Fprintln(w, "  Login UI PAT:      already configured (AO_LOGIN_UI_PAT set — none generated).")
	}
	if !encrypted {
		fmt.Fprintln(w, "")
		fmt.Fprintln(w, "  WARNING: private keys were stored UNENCRYPTED (DATABASE_ENCRYPTION_KEY unset).")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────────────────────

func promptLine(r *bufio.Reader, w io.Writer, label string) (string, error) {
	fmt.Fprint(w, label)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

func confirm(r *bufio.Reader, w io.Writer, label string) (bool, error) {
	ans, err := promptLine(r, w, label)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(ans) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// originOr returns v trimmed of a trailing slash, or fallback when v is empty.
func originOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimRight(strings.TrimSpace(v), "/")
}

func toJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}
	return b, nil
}

func init() {
	bootstrapCmd.Flags().StringVar(&bootstrapDomain, "domain", "", "default domain for tenant/OIDC issuer (skips the prompt)")
	bootstrapCmd.Flags().StringVar(&bootstrapAlg, "alg", "", "OIDC signing key algorithm: RS256/RS384/RS512/ES256/ES384/ES512/PS256/PS384/PS512 (skips the prompt)")
	bootstrapCmd.Flags().StringVar(&bootstrapAdminEmail, "admin-email", "", "default admin email (skips the prompt)")
	bootstrapCmd.Flags().StringVar(&bootstrapAdminUsername, "admin-username", "", "default admin username (default: admin email)")
	bootstrapCmd.Flags().StringVar(&bootstrapConsoleURL, "console-url", "", "console-ui origin for redirect/post-logout URIs, e.g. https://console.example.com (overrides config; default http://localhost:3002)")
	bootstrapCmd.Flags().StringVar(&bootstrapPortalURL, "portal-url", "", "portal-ui origin for redirect/post-logout URIs, e.g. https://portal.example.com (overrides config; default http://localhost:3001)")
}
