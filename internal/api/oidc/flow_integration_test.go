// Package oidc_test drives the assembled gateway end to end.
//
// The test builds the same routes the server builds, against a real MySQL and a
// real Redis, and then walks one person through one authorization code flow. It
// touches nothing inside a package: every step is an HTTP request, and almost
// every assertion reads the answer. Three facts of the flow are invisible from
// the outside, and the test reads those from the audit trail.
//
// The test needs a database that `bootstrap` already seeded. It reuses the
// bootstrapped tenant, provider config, signing keys and scopes, and it creates
// its own clients and its own person, so no secret comes in from outside.
//
// Run it with AO_TEST_INTEGRATION=1. Without that variable the test skips, so
// `go test ./...` stays green on a machine that runs neither service.
package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/uptrace/bun"

	apihttp "alphaomega/identitygateway/internal/api/http"
	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
	"alphaomega/identitygateway/internal/utils"
)

// integrationEnv turns the test on. The test skips when it is empty.
const integrationEnv = "AO_TEST_INTEGRATION"

// testLoginPAT is the login PAT of this test run. It credentials the login UI,
// and it lives only inside the test process.
const testLoginPAT = "flow-integration-test-pat"

// testTimeout bounds one request. A first request pays for the provider build,
// the key read and the connection pool, so the bound is generous.
const testTimeout = 15 * time.Second

// formType is how the token endpoint and its neighbours read a request body.
const formType = "application/x-www-form-urlencoded"

// flowScopes is what every authorization request of this test asks for.
const flowScopes = "openid profile email offline_access"

// gateway is the assembled gateway one test drives.
type gateway struct {
	app      *fiber.App
	cfg      *config.Config
	bdb      *bun.DB
	domain   string // the hostname that resolves the tenant
	tenantID string
}

// newGateway builds the routes the server builds, against the configured MySQL
// and Redis.
func newGateway(t *testing.T) *gateway {
	t.Helper()

	if os.Getenv(integrationEnv) == "" {
		t.Skipf("set %s=1 to run the end-to-end flow against MySQL and Redis", integrationEnv)
	}

	// The configuration lives at the repository root: .env and cmd/config.yaml.
	// The loader reads both from the working directory, so the test moves there.
	t.Chdir(repoRoot(t))

	// The login steps accept only the login UI, which presents this token. The
	// test sets its own, so the run needs no PAT in the environment. An
	// environment variable already set wins over the .env file, so this value
	// reaches the configuration.
	t.Setenv("AO_LOGIN_UI_PAT", testLoginPAT)

	cfg, err := config.InitConfig()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	log, _ := logger.NewObserved()

	bdb, err := db.NewDB(cfg.Database, log)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = bdb.Close() })

	rdb, err := cache.New(fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port), cfg.Redis.Password, nil)
	if err != nil {
		t.Fatalf("open redis: %v", err)
	}
	t.Cleanup(func() { _ = rdb.Close() })

	app := fiber.New(config.FiberConfig(cfg.Server.TrustedProxies, cfg.App.Name, cfg.Server.HeaderName))
	if err := apihttp.Routes(app, cfg, bdb, rdb, log); err != nil {
		t.Fatalf("mount routes: %v", err)
	}
	app.Use(apihttp.NotFoundHandler)

	row := primaryDomain(t, bdb)
	return &gateway{app: app, cfg: cfg, bdb: bdb, domain: row.Domain, tenantID: row.TenantID}
}

// do sends one request to the gateway. The host decides the tenant, so every
// request carries the tenant domain. Each pair in header is a name and a value.
func (g *gateway) do(t *testing.T, method, target string, body io.Reader, header ...string) *http.Response {
	t.Helper()

	req := httptest.NewRequest(method, "http://"+g.domain+target, body)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}

	answer, err := g.app.Test(req, fiber.TestConfig{Timeout: testTimeout, FailOnTimeout: true})
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	t.Cleanup(func() { _ = answer.Body.Close() })
	return answer
}

// oidc sends one request to a protocol endpoint of the tenant.
func (g *gateway) oidc(t *testing.T, method, path string, body io.Reader, header ...string) *http.Response {
	t.Helper()
	return g.do(t, method, g.cfg.OIDC.PathPrefix+path, body, header...)
}

// login sends one login step. Only the login UI reaches these routes, so every
// step carries the login PAT, and every step after the first carries the
// session token.
func (g *gateway) login(t *testing.T, step, body, token string, into any) {
	t.Helper()

	answer := g.do(t, fiber.MethodPost, "/api/v1/login"+step, strings.NewReader(body),
		g.loginHeader(token, fiber.MIMEApplicationJSON)...)
	decode(t, answer, fiber.StatusOK, &envelope{Data: into})
}

// loginHeader is what every login step carries: the PAT of the login UI, the
// body type, and the session token once a session is open.
func (g *gateway) loginHeader(token, bodyType string) []string {
	header := []string{
		middlewares.LoginPATHeader, g.cfg.Auth.LoginPATs()[0],
		fiber.HeaderContentType, bodyType,
	}
	if token != "" {
		header = append(header, fiber.HeaderAuthorization, "Bearer "+token)
	}
	return header
}

// envelope is the answer shape every endpoint of this API writes. Only the data
// half carries the answer of a step.
type envelope struct {
	Data any `json:"data"`
}

// decode reads a JSON answer of the expected status.
func decode(t *testing.T, answer *http.Response, want int, into any) {
	t.Helper()

	body, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if answer.StatusCode != want {
		t.Fatalf("status %d, want %d: %s", answer.StatusCode, want, body)
	}
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("decode body: %v: %s", err, body)
	}
}

// readAll reads a body the test reports on.
func readAll(t *testing.T, answer *http.Response) string {
	t.Helper()

	body, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// repoRoot walks up from the test directory to the directory that holds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

// primaryDomain reads the hostname the tenant serves. The test sends it as the
// host of every request, which is how the gateway resolves the tenant.
func primaryDomain(t *testing.T, bdb *bun.DB) tenant.Domain {
	t.Helper()

	var row tenant.Domain
	err := bdb.NewSelect().
		Model(&row).
		Column("domain", "tenant_id").
		Where("state = 1").
		Where("is_verified = 1").
		OrderExpr("is_primary DESC").
		Limit(1).
		Scan(t.Context())
	if err != nil {
		t.Fatalf("read tenant domain: %v (run bootstrap first)", err)
	}
	return row
}

// clientFixture is one client this test owns. A secret makes the client
// confidential, and an empty secret makes it public.
type clientFixture struct {
	appID      string
	clientID   string
	secret     string
	redirect   string
	postLogout string
}

// fixture is what one run of the test owns: two clients and one person. Every
// row is created here and deleted when the test ends, so the run leaves the
// bootstrapped rows as it found them.
//
// Neither client is first party, so the flow reaches the consent screen. The
// redirect URIs name a host nothing listens on: the test reads a redirect, it
// never follows one.
type fixture struct {
	confidential clientFixture // holds a secret, so it can introspect and revoke
	public       clientFixture // holds none, so introspection refuses it

	userID   string
	username string
	email    string
	password string
}

func seedFixture(t *testing.T, gw *gateway) fixture {
	t.Helper()

	ctx := t.Context()
	run := utils.NewUUIDv7()

	password := randomString(t)
	passwordHash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	fx := fixture{
		confidential: newClientFixture(t, "confidential"),
		public:       newClientFixture(t, "public"),
		userID:       utils.NewUUIDv7(),
		username:     "flow-test-" + run,
		email:        "flow-test-" + run + "@example.test",
		password:     password,
	}
	fx.public.secret = ""

	// The tenant already holds an organization and a project, because bootstrap
	// seeded them. The fixture hangs off those, so it needs no hierarchy of its
	// own.
	var orgID, projectID string
	if err := gw.bdb.NewSelect().Table("organizations").Column("id").
		Where("tenant_id = ?", gw.tenantID).Limit(1).Scan(ctx, &orgID); err != nil {
		t.Fatalf("read organization: %v (run bootstrap first)", err)
	}
	if err := gw.bdb.NewSelect().Table("projects").Column("id").
		Where("tenant_id = ?", gw.tenantID).Limit(1).Scan(ctx, &projectID); err != nil {
		t.Fatalf("read project: %v (run bootstrap first)", err)
	}

	exec := func(label, query string, args ...any) {
		if _, err := gw.bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	}

	for _, cl := range []clientFixture{fx.confidential, fx.public} {
		method, secretHash := "none", ""
		if cl.secret != "" {
			method = "client_secret_basic"
			if secretHash, err = crypto.HashPassword(cl.secret); err != nil {
				t.Fatalf("hash client secret: %v", err)
			}
		}

		exec("insert application",
			`INSERT INTO applications (id, tenant_id, project_id, name, app_type, state)
			 VALUES (?, ?, ?, ?, 1, 1)`,
			cl.appID, gw.tenantID, projectID, "flow-test-"+cl.appID)
		exec("insert client",
			`INSERT INTO application_oidc_configs
			   (app_id, tenant_id, client_id, created_at, secret, token_authn_method, subject_type,
			    scopes, redirect_uris, grant_types, response_types, post_logout_redirect_uris,
			    is_first_party)
			 VALUES (?, ?, ?, ?, ?, ?, 'public', ?, ?, ?, ?, ?, 0)`,
			cl.appID, gw.tenantID, cl.clientID, time.Now(), secretHash, method, flowScopes,
			jsonList(t, cl.redirect),
			jsonList(t, "authorization_code", "refresh_token"),
			jsonList(t, "code"),
			jsonList(t, cl.postLogout))
	}

	exec("insert user",
		`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
		 VALUES (?, ?, ?, ?, 1, 1)`,
		fx.userID, gw.tenantID, orgID, fx.username)
	exec("insert person",
		`INSERT INTO user_humans
		   (user_id, tenant_id, first_name, last_name, display_name, preferred_language,
		    email, is_email_verified, password_hash, password_change_required)
		 VALUES (?, ?, 'Flow', 'Test', 'Flow Test', 'en', ?, 1, ?, 0)`,
		fx.userID, gw.tenantID, fx.email, passwordHash)

	t.Cleanup(func() { deleteFixture(t, gw, fx) })
	return fx
}

// newClientFixture builds one client row this test owns. Every client starts
// confidential, and the caller drops the secret to make one public.
func newClientFixture(t *testing.T, role string) clientFixture {
	t.Helper()

	appID := utils.NewUUIDv7()
	return clientFixture{
		appID:      appID,
		clientID:   utils.NewUUIDv7(),
		secret:     randomString(t),
		redirect:   "http://127.0.0.1:9/" + role + "/callback",
		postLogout: "http://127.0.0.1:9/" + role + "/signed-out",
	}
}

// deleteFixture removes everything one run created: the rows the flow wrote and
// then the fixture itself. The audit trail records facts, so its rows stay.
func deleteFixture(t *testing.T, gw *gateway, fx fixture) {
	t.Helper()

	// t.Context is already cancelled when a cleanup runs, so the deletes take a
	// context of their own.
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	clients := []string{fx.confidential.clientID, fx.public.clientID}
	apps := []string{fx.confidential.appID, fx.public.appID}

	for _, del := range []struct {
		table string
		where string
		arg   any
	}{
		{"oidc_superseded_refresh_tokens",
			"grant_id IN (SELECT id FROM oidc_grants WHERE client_id IN (?))", bun.In(clients)},
		{"oidc_grants", "client_id IN (?)", bun.In(clients)},
		{"oidc_sessions", "client_id IN (?)", bun.In(clients)},
		{"oidc_user_consents", "user_id = ?", fx.userID},
		{"login_sessions", "user_id = ?", fx.userID},
		{"user_humans", "user_id = ?", fx.userID},
		{"users", "id = ?", fx.userID},
		{"application_oidc_configs", "app_id IN (?)", bun.In(apps)},
		{"applications", "id IN (?)", bun.In(apps)},
	} {
		query := fmt.Sprintf("DELETE FROM %s WHERE %s", del.table, del.where)
		if _, err := gw.bdb.NewRaw(query, del.arg).Exec(ctx); err != nil {
			t.Errorf("clean up %s: %v", del.table, err)
		}
	}
}

// jsonList is how the client columns hold a list of strings.
func jsonList(t *testing.T, values ...string) string {
	t.Helper()

	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("encode %v: %v", values, err)
	}
	return string(encoded)
}

// discovery is the part of the discovery document the flow reads.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// tokens is what the token endpoint answers with.
type tokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// TestAuthorizationCodeFlow walks one authorization code flow from discovery to
// logout. Each step depends on the one before it, so the steps run in order and
// share the state the earlier steps produced.
func TestAuthorizationCodeFlow(t *testing.T) {
	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// The audit trail is append-only and holds the rows of every earlier run, so
	// each count below reads the rows this run wrote.
	started := time.Now()

	var doc discovery
	t.Run("discovery", func(t *testing.T) {
		decode(t, gw.do(t, fiber.MethodGet, "/.well-known/openid-configuration", nil), fiber.StatusOK, &doc)

		if doc.Issuer == "" {
			t.Fatal("issuer is empty")
		}

		// Every endpoint of this tenant sits under the shared prefix, and only
		// discovery itself sits at the root.
		base := doc.Issuer + gw.cfg.OIDC.PathPrefix
		for name, got := range map[string]string{
			"/authorize":  doc.AuthorizationEndpoint,
			"/token":      doc.TokenEndpoint,
			"/userinfo":   doc.UserinfoEndpoint,
			"/jwks":       doc.JwksURI,
			"/introspect": doc.IntrospectionEndpoint,
			"/revoke":     doc.RevocationEndpoint,
			"/logout":     doc.EndSessionEndpoint,
		} {
			if want := base + name; got != want {
				t.Errorf("endpoint %s is %q, want %q", name, got, want)
			}
		}
	})

	auth := gw.startAuthorization(t, fx.confidential)
	t.Run("authorize", func(t *testing.T) {
		// Nobody is signed in, so the request waits at the login UI. The login
		// UI reads the authn session id off the query.
		if auth.request == "" {
			t.Fatal("the redirect carries no authRequest")
		}
	})

	var token string // the login session token, rotated at each step
	t.Run("sign in", func(t *testing.T) {
		var opened struct {
			SessionID    string `json:"sessionId"`
			SessionToken string `json:"sessionToken"`
		}
		gw.login(t, "/identifier", fmt.Sprintf(`{"identifier":%q}`, fx.email), "", &opened)
		if opened.SessionID == "" || opened.SessionToken == "" {
			t.Fatalf("identifier answered %+v", opened)
		}

		var verified struct {
			SessionToken string `json:"sessionToken"`
		}
		gw.login(t, "/password", fmt.Sprintf(`{"password":%q}`, fx.password), opened.SessionToken, &verified)
		if verified.SessionToken == "" {
			t.Fatal("password answered no session token")
		}
		if verified.SessionToken == opened.SessionToken {
			t.Error("the session token was not rotated")
		}
		token = verified.SessionToken
	})

	var code string
	t.Run("consent", func(t *testing.T) {
		// The client is not first party, so the person answers the consent
		// screen before the request finishes.
		var asked struct {
			ConsentRequired bool `json:"consentRequired"`
			Client          struct {
				ClientID string `json:"clientId"`
			} `json:"client"`
			Scopes []struct {
				Name string `json:"name"`
			} `json:"scopes"`
		}
		gw.login(t, "/complete", fmt.Sprintf(`{"authRequest":%q}`, auth.request), token, &asked)
		if !asked.ConsentRequired {
			t.Fatal("the consent screen was skipped")
		}
		if asked.Client.ClientID != fx.confidential.clientID {
			t.Errorf("consent names client %q, want %q", asked.Client.ClientID, fx.confidential.clientID)
		}
		if len(asked.Scopes) == 0 {
			t.Error("the consent screen names no scope")
		}

		var approved struct {
			RedirectTo string `json:"redirectTo"`
		}
		gw.login(t, "/consent",
			fmt.Sprintf(`{"authRequest":%q,"approved":true}`, auth.request), token, &approved)
		if approved.RedirectTo == "" {
			t.Fatal("consent answered no redirect")
		}

		code = gw.resume(t, fx.confidential, auth, approved.RedirectTo)
	})

	var issued tokens
	t.Run("token", func(t *testing.T) {
		issued = gw.token(t, fx.confidential, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {fx.confidential.redirect},
			"code_verifier": {auth.verifier},
		})
		if issued.AccessToken == "" || issued.IDToken == "" || issued.RefreshToken == "" {
			t.Fatalf("token answered %+v", issued)
		}

		claims := jwtClaims(t, issued.IDToken)
		for name, want := range map[string]string{
			"iss":   doc.Issuer,
			"aud":   fx.confidential.clientID,
			"sub":   fx.userID,
			"nonce": auth.nonce,
		} {
			if got, _ := claims[name].(string); got != want {
				t.Errorf("id_token %s is %q, want %q", name, got, want)
			}
		}

		// The sid claim names the login session. A later logout reads it, and
		// that is how signing out of one application reaches the other.
		if sid, _ := claims["sid"].(string); sid == "" {
			t.Error("id_token carries no sid")
		}
	})

	t.Run("userinfo", func(t *testing.T) {
		// The tenant releases the profile and email claims through userinfo,
		// because every builtin claim mapper delivers there.
		var claims map[string]any
		answer := gw.oidc(t, fiber.MethodGet, "/userinfo", nil,
			fiber.HeaderAuthorization, "Bearer "+issued.AccessToken)
		decode(t, answer, fiber.StatusOK, &claims)

		for name, want := range map[string]any{
			"sub":                fx.userID,
			"email":              fx.email,
			"email_verified":     true,
			"given_name":         "Flow",
			"family_name":        "Test",
			"name":               "Flow Test",
			"preferred_username": fx.username,
		} {
			if got := claims[name]; got != want {
				t.Errorf("userinfo %s is %v, want %v", name, got, want)
			}
		}
	})

	var refreshed tokens
	t.Run("refresh", func(t *testing.T) {
		refreshed = gw.token(t, fx.confidential, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {issued.RefreshToken},
		})
		if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
			t.Fatalf("refresh answered %+v", refreshed)
		}

		// Rotation is what makes a replay detectable: the token the client
		// presented is dead, and the answer carries its replacement.
		if refreshed.RefreshToken == issued.RefreshToken {
			t.Error("the refresh token was not rotated")
		}
	})

	t.Run("replay the refresh token", func(t *testing.T) {
		// The client presents the token the rotation already replaced. That is
		// proof of a leak, so the whole grant dies.
		var refused struct {
			Error string `json:"error"`
		}
		answer := gw.oidc(t, fiber.MethodPost, "/token",
			strings.NewReader(url.Values{
				"grant_type":    {"refresh_token"},
				"refresh_token": {issued.RefreshToken},
			}.Encode()),
			fiber.HeaderContentType, formType,
			fiber.HeaderAuthorization, basicAuth(fx.confidential))
		decode(t, answer, fiber.StatusBadRequest, &refused)
		if refused.Error != "invalid_grant" {
			t.Errorf("error is %q, want %q", refused.Error, "invalid_grant")
		}

		// The grant is revoked, so the access token the last refresh issued
		// buys nothing any more.
		gw.expectDeadToken(t, refreshed.AccessToken)

		// The replay itself leaves no other trace, so the trail is the only
		// place it can be read back.
		if got := countAudit(t, gw, "token.refresh_reused", started); got != 1 {
			t.Errorf("%d token.refresh_reused rows, want 1", got)
		}
	})

	// The person is still signed in, and the consent is recorded, so each
	// authorization below finishes without the consent screen.
	var second, forPublic tokens
	t.Run("sign in again", func(t *testing.T) {
		second = gw.grant(t, fx.confidential, token)
		forPublic = gw.grant(t, fx.public, token)
	})

	t.Run("introspect", func(t *testing.T) {
		// A confidential client reads its own token.
		var info struct {
			Active   bool   `json:"active"`
			Subject  string `json:"sub"`
			ClientID string `json:"client_id"`
		}
		decode(t, gw.introspect(t, fx.confidential, second.AccessToken), fiber.StatusOK, &info)
		if !info.Active {
			t.Fatal("the token reads as inactive")
		}
		if info.Subject != fx.userID {
			t.Errorf("sub is %q, want %q", info.Subject, fx.userID)
		}
		if info.ClientID != fx.confidential.clientID {
			t.Errorf("client_id is %q, want %q", info.ClientID, fx.confidential.clientID)
		}

		// A public client holds no secret, so anybody can present its id. It
		// never reads a token.
		answer := gw.introspect(t, fx.public, forPublic.AccessToken)
		if answer.StatusCode < fiber.StatusBadRequest {
			t.Errorf("a public client introspected and got %d: %s",
				answer.StatusCode, readAll(t, answer))
		}
	})

	t.Run("revoke", func(t *testing.T) {
		answer := gw.oidc(t, fiber.MethodPost, "/revoke",
			strings.NewReader(url.Values{"token": {second.AccessToken}}.Encode()),
			fiber.HeaderContentType, formType,
			fiber.HeaderAuthorization, basicAuth(fx.confidential))
		if answer.StatusCode != fiber.StatusOK {
			t.Fatalf("status %d, want %d: %s", answer.StatusCode, fiber.StatusOK, readAll(t, answer))
		}

		// Revoking an access token ends the whole grant, so the client reads
		// its own token as inactive from this moment.
		var info struct {
			Active bool `json:"active"`
		}
		decode(t, gw.introspect(t, fx.confidential, second.AccessToken), fiber.StatusOK, &info)
		if info.Active {
			t.Error("the revoked token still reads as active")
		}
	})

	// One more grant of the confidential client, so the logout below has a
	// second application to sign the person out of.
	third := gw.grant(t, fx.confidential, token)

	t.Run("logout", func(t *testing.T) {
		// The public client ends the sign-in, and names the ID token it holds.
		query := url.Values{
			"id_token_hint":            {forPublic.IDToken},
			"post_logout_redirect_uri": {fx.public.postLogout},
		}
		answer := gw.oidc(t, fiber.MethodGet, "/logout?"+query.Encode(), nil)
		if answer.StatusCode != fiber.StatusSeeOther && answer.StatusCode != fiber.StatusFound {
			t.Fatalf("status %d, want a redirect: %s", answer.StatusCode, readAll(t, answer))
		}
		if got := answer.Header.Get(fiber.HeaderLocation); got != fx.public.postLogout {
			t.Errorf("redirect is %q, want %q", got, fx.public.postLogout)
		}

		// The login session is gone, so the login UI reports nobody signed in.
		var status struct {
			Active bool `json:"active"`
		}
		decode(t, gw.do(t, fiber.MethodGet, "/api/v1/login/session", nil,
			gw.loginHeader(token, fiber.MIMEApplicationJSON)...), fiber.StatusOK, &envelope{Data: &status})
		if status.Active {
			t.Error("the login session outlived the logout")
		}

		// Signing out of one application signs the person out of the other:
		// every grant of that sign-in is revoked, not only the one that asked.
		gw.expectDeadToken(t, forPublic.AccessToken)
		gw.expectDeadToken(t, third.AccessToken)

		if got := countAudit(t, gw, "logout.succeeded", started); got != 1 {
			t.Errorf("%d logout.succeeded rows, want 1", got)
		}
	})
}

// authorization is one authorization request in flight: the authn session the
// login UI signs in against, and the values the answer is checked with.
type authorization struct {
	request  string
	verifier string
	state    string
	nonce    string
}

// startAuthorization asks for a code and stops where the browser stops: at the
// login UI, with the authn session named on the query.
//
// The verifier proves at the token endpoint that the client that redeems the
// code is the client that asked for it.
func (g *gateway) startAuthorization(t *testing.T, cl clientFixture) authorization {
	t.Helper()

	auth := authorization{verifier: randomString(t), state: randomString(t), nonce: randomString(t)}
	query := url.Values{
		"client_id":             {cl.clientID},
		"redirect_uri":          {cl.redirect},
		"response_type":         {"code"},
		"scope":                 {flowScopes},
		"state":                 {auth.state},
		"nonce":                 {auth.nonce},
		"code_challenge":        {s256(auth.verifier)},
		"code_challenge_method": {"S256"},
	}

	answer := g.oidc(t, fiber.MethodGet, "/authorize?"+query.Encode(), nil)
	if answer.StatusCode != fiber.StatusSeeOther {
		t.Fatalf("status %d, want %d: %s", answer.StatusCode, fiber.StatusSeeOther, readAll(t, answer))
	}

	location, err := url.Parse(answer.Header.Get(fiber.HeaderLocation))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if want := g.cfg.App.LoginURL + "/identifier"; location.Scheme+"://"+location.Host+location.Path != want {
		t.Fatalf("redirect is %q, want %q", location, want)
	}

	auth.request = location.Query().Get("authRequest")
	return auth
}

// resume carries the browser back to the protocol engine, which answers the
// client with the authorization code.
func (g *gateway) resume(t *testing.T, cl clientFixture, auth authorization, redirectTo string) string {
	t.Helper()

	resumed, err := url.Parse(redirectTo)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	answer := g.do(t, fiber.MethodGet, resumed.RequestURI(), nil)
	if answer.StatusCode != fiber.StatusSeeOther {
		t.Fatalf("status %d, want %d: %s", answer.StatusCode, fiber.StatusSeeOther, readAll(t, answer))
	}

	back, err := url.Parse(answer.Header.Get(fiber.HeaderLocation))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	if got := back.Scheme + "://" + back.Host + back.Path; got != cl.redirect {
		t.Fatalf("redirect is %q, want %q", got, cl.redirect)
	}
	if got := back.Query().Get("state"); got != auth.state {
		t.Errorf("state is %q, want %q", got, auth.state)
	}

	code := back.Query().Get("code")
	if code == "" {
		t.Fatalf("no code on %q", back)
	}
	return code
}

// grant runs one whole authorization for a person who is already signed in, and
// returns what the token endpoint issued.
func (g *gateway) grant(t *testing.T, cl clientFixture, loginToken string) tokens {
	t.Helper()

	auth := g.startAuthorization(t, cl)

	var finished struct {
		RedirectTo      string `json:"redirectTo"`
		ConsentRequired bool   `json:"consentRequired"`
	}
	g.login(t, "/complete", fmt.Sprintf(`{"authRequest":%q}`, auth.request), loginToken, &finished)

	// Consent is recorded for one client, so a client the person has not
	// answered for yet still asks. A client that already holds the consent goes
	// straight to the redirect.
	if finished.ConsentRequired {
		g.login(t, "/consent",
			fmt.Sprintf(`{"authRequest":%q,"approved":true}`, auth.request), loginToken, &finished)
	}

	code := g.resume(t, cl, auth, finished.RedirectTo)
	return g.token(t, cl, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {cl.redirect},
		"code_verifier": {auth.verifier},
	})
}

// token calls the token endpoint. A confidential client presents its secret
// with HTTP basic authentication, and a public client presents its id alone.
func (g *gateway) token(t *testing.T, cl clientFixture, form url.Values) tokens {
	t.Helper()

	header := []string{fiber.HeaderContentType, formType}
	if cl.secret == "" {
		form.Set("client_id", cl.clientID)
	} else {
		header = append(header, fiber.HeaderAuthorization, basicAuth(cl))
	}

	var issued tokens
	decode(t, g.oidc(t, fiber.MethodPost, "/token", strings.NewReader(form.Encode()), header...),
		fiber.StatusOK, &issued)
	return issued
}

// introspect asks the gateway what one token is, as one client.
func (g *gateway) introspect(t *testing.T, cl clientFixture, token string) *http.Response {
	t.Helper()

	form := url.Values{"token": {token}}
	header := []string{fiber.HeaderContentType, formType}
	if cl.secret == "" {
		form.Set("client_id", cl.clientID)
	} else {
		header = append(header, fiber.HeaderAuthorization, basicAuth(cl))
	}

	return g.oidc(t, fiber.MethodPost, "/introspect", strings.NewReader(form.Encode()), header...)
}

// expectDeadToken reads userinfo with one access token and expects a refusal.
// The engine refuses a token whose grant is revoked, so this is how a
// revocation is read back from the outside.
func (g *gateway) expectDeadToken(t *testing.T, accessToken string) {
	t.Helper()

	answer := g.oidc(t, fiber.MethodGet, "/userinfo", nil,
		fiber.HeaderAuthorization, "Bearer "+accessToken)
	if answer.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("userinfo status %d, want %d: %s",
			answer.StatusCode, fiber.StatusUnauthorized, readAll(t, answer))
	}
}

// countRows counts the rows of one table that match one condition.
func countRows(t *testing.T, gw *gateway, table, where string, args ...any) int {
	t.Helper()

	count, err := gw.bdb.NewSelect().Table(table).Where(where, args...).Count(t.Context())
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

// countAudit counts the trail rows this run wrote for one action.
//
// The recorder stamps every row in UTC, and the driver renders a time in the
// zone that time carries, so the bound is given in UTC too. A local bound would
// read as a wall clock the column never holds.
func countAudit(t *testing.T, gw *gateway, action string, since time.Time) int {
	t.Helper()

	return countRows(t, gw, "audit_events",
		"tenant_id = ? AND action = ? AND created_at >= ?", gw.tenantID, action, since.UTC())
}

// basicAuth is how a confidential client presents its credentials.
func basicAuth(cl clientFixture) string {
	pair := url.QueryEscape(cl.clientID) + ":" + url.QueryEscape(cl.secret)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(pair))
}

// jwtClaims reads the claim set of one signed token.
//
// The signature is not verified here. The engine verifies it on every call that
// presents the token, so a token this test then spends is a token the engine
// accepted.
func jwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("read claims: %v", err)
	}
	return claims
}

// randomString is one unguessable value: a state, a nonce, a PKCE verifier, or
// a secret of the fixture.
func randomString(t *testing.T) string {
	t.Helper()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("read random: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// s256 is the PKCE challenge of one verifier.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
