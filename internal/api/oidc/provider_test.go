package oidc

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"go.uber.org/zap/zapcore"

	aooidc "alphaomega/identitygateway/internal/oidc"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	testIssuer      = "https://auth.acme.test"
	testTenantID    = "tenant-1"
	testKID         = "key-1"
	testClientID    = "console-ui"
	testRedirectURI = "https://console.acme.test/callback"
)

// testClient is the client an authorization request names. It is the smallest
// client the protocol engine accepts: one redirect URI, the code response type,
// and the authentication method the caller states.
func testClient(authn goidc.AuthnMethod) goidc.Client {
	return goidc.Client{
		ID: testClientID,
		ClientMeta: goidc.ClientMeta{
			RedirectURIs:     []string{testRedirectURI},
			GrantTypes:       []goidc.GrantType{goidc.GrantAuthorizationCode},
			ResponseTypes:    []goidc.ResponseType{goidc.ResponseTypeCode},
			ScopeIDs:         "openid",
			TokenAuthnMethod: authn,
		},
	}
}

// clientFinder answers with testClient for the client id the tests use, and
// reports every other id as unknown.
func clientFinder(authn goidc.AuthnMethod) ClientFinder {
	return func(_ context.Context, _, clientID string) (goidc.Client, error) {
		if clientID != testClientID {
			return goidc.Client{}, aooidc.ErrClientNotFound
		}
		return testClient(authn), nil
	}
}

// testJWK generates one key and returns its public half, so a test states the
// key set a tenant publishes.
func testJWK(t *testing.T, alg, kid string) goidc.JSONWebKey {
	t.Helper()

	public, _ := testKeyPair(t, alg, kid)
	return public
}

// testKeyPair generates one key and returns both halves as JWK, with the kid
// the row would carry.
func testKeyPair(t *testing.T, alg, kid string) (goidc.JSONWebKey, goidc.JSONWebKey) {
	t.Helper()

	publicJWK, privateJWK, err := aocrypto.Generate(alg)
	if err != nil {
		t.Fatalf("generate %s key: %v", alg, err)
	}

	var public, private goidc.JSONWebKey
	if err := json.Unmarshal(publicJWK, &public); err != nil {
		t.Fatalf("decode public JWK: %v", err)
	}
	if err := json.Unmarshal(privateJWK, &private); err != nil {
		t.Fatalf("decode private JWK: %v", err)
	}
	public.KeyID = kid
	private.KeyID = kid
	return public, private
}

// testDeps builds the provider dependencies over a freshly generated key, so
// the test needs no database and no bootstrap.
func testDeps(t *testing.T) Deps {
	t.Helper()

	public, private := testKeyPair(t, aocrypto.AlgES256, testKID)

	return Deps{
		PathPrefix: "/oidc/v1",
		JWKS: func(context.Context) (goidc.JSONWebKeySet, error) {
			return goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{public}}, nil
		},
		Signer: func(context.Context, goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
			return testKID, private.Key.(crypto.Signer), nil
		},
		Client:  clientFinder(goidc.AuthnMethodSecretBasic),
		Storage: newMemoryStore().funcs(),
		Log:     logger.New(),
	}
}

// testConfig is the provider config of a tenant that serves. Every knob comes
// from the row, so the test states them all.
func testConfig() aooidc.ProviderConfig {
	refresh := 2592000
	return aooidc.ProviderConfig{
		TenantID:                      testTenantID,
		Issuer:                        testIssuer,
		State:                         1,
		RequirePKCE:                   true,
		AuthorizationCodeLifetimeSecs: 60,
		AccessTokenType:               aooidc.AccessTokenTypeJWT,
		AccessTokenLifetimeSecs:       900,
		IDTokenLifetimeSecs:           900,
		RefreshTokenLifetimeSecs:      &refresh,
	}
}

// get runs one request against the built provider and returns the decoded body.
func get(t *testing.T, handler http.Handler, path string) (int, map[string]any) {
	t.Helper()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, testIssuer+path, nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return rec.Code, body
}

// authorize runs one authorization request and returns where the provider sent
// the browser. A request the provider refuses redirects to the client with an
// error, so the outcome reads from the location.
func authorize(t *testing.T, handler http.Handler, query url.Values) *url.URL {
	t.Helper()

	rec := httptest.NewRecorder()
	target := testIssuer + "/oidc/v1/authorize?" + query.Encode()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect of %s: %v", target, err)
	}
	if location.String() == "" {
		t.Fatalf("authorize gave status %d and no redirect, body %s", rec.Code, rec.Body.String())
	}
	return location
}

// TestBuild_Discovery covers the document a client reads first. The issuer, the
// endpoints, and the advertised flows must match the tenant's row.
func TestBuild_Discovery(t *testing.T) {
	p, err := Build(context.Background(), testTenantID, testConfig(), testDeps(t))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}

	code, doc := get(t, p.Handler(), "/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("discovery gives status %d, want %d", code, http.StatusOK)
	}

	want := map[string]string{
		"issuer":                 testIssuer,
		"jwks_uri":               testIssuer + "/oidc/v1/jwks",
		"authorization_endpoint": testIssuer + "/oidc/v1/authorize",
		"token_endpoint":         testIssuer + "/oidc/v1/token",
		"userinfo_endpoint":      testIssuer + "/oidc/v1/userinfo",
	}
	for field, value := range want {
		if doc[field] != value {
			t.Errorf("discovery %s is %v, want %q", field, doc[field], value)
		}
	}

	assertHolds(t, doc, "grant_types_supported", "authorization_code", "refresh_token")
	assertHolds(t, doc, "code_challenge_methods_supported", "S256")
	assertHolds(t, doc, "response_types_supported", "code")
	assertHolds(t, doc, "token_endpoint_auth_methods_supported",
		"client_secret_basic", "client_secret_post", "none")
}

// TestBuild_JWKS covers the key set the endpoint serves. The public half is
// published and the private half never leaves the database.
func TestBuild_JWKS(t *testing.T) {
	p, err := Build(context.Background(), testTenantID, testConfig(), testDeps(t))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}

	code, doc := get(t, p.Handler(), "/oidc/v1/jwks")
	if code != http.StatusOK {
		t.Fatalf("jwks gives status %d, want %d", code, http.StatusOK)
	}

	keys, ok := doc["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("jwks holds %v, want one key", doc["keys"])
	}
	key, _ := keys[0].(map[string]any)
	if key["kid"] != testKID {
		t.Errorf("jwks kid is %v, want %q", key["kid"], testKID)
	}
	if _, found := key["d"]; found {
		t.Error("jwks published the private half of the key")
	}
}

// TestBuild_PKCEIsOptionalPerTenant covers the require_pkce column, through an
// authorization request that carries no code challenge. A tenant that requires
// PKCE refuses it. A tenant that does not require it lets the request reach the
// authentication policy, which is the stub that fails with login_required.
//
// A public client is the exception. The protocol engine always requires PKCE
// from a client that holds no secret, whatever the column says, so the column
// can relax the rule for a confidential client only.
func TestBuild_PKCEIsOptionalPerTenant(t *testing.T) {
	cases := []struct {
		name        string
		requirePKCE bool
		authn       goidc.AuthnMethod
		wantError   string
	}{
		{
			name:        "required of a confidential client",
			requirePKCE: true,
			authn:       goidc.AuthnMethodSecretBasic,
			wantError:   "invalid_request",
		},
		{
			name:        "optional for a confidential client",
			requirePKCE: false,
			authn:       goidc.AuthnMethodSecretBasic,
			wantError:   "login_required",
		},
		{
			name:        "always required of a public client",
			requirePKCE: false,
			authn:       goidc.AuthnMethodNone,
			wantError:   "invalid_request",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.RequirePKCE = tc.requirePKCE
			deps := testDeps(t)
			deps.Client = clientFinder(tc.authn)

			p, err := Build(context.Background(), testTenantID, cfg, deps)
			if err != nil {
				t.Fatalf("build provider: %v", err)
			}

			location := authorize(t, p.Handler(), url.Values{
				"client_id":     {testClientID},
				"redirect_uri":  {testRedirectURI},
				"response_type": {"code"},
				"scope":         {"openid"},
			})
			if got := location.Query().Get("error"); got != tc.wantError {
				t.Errorf("authorize without a code challenge gives error %q, want %q", got, tc.wantError)
			}
		})
	}
}

// TestBuild_PKCERefusesPlain covers the challenge method. PKCE is optional for a
// confidential client, but a client that does use it must use S256, so a plain
// challenge is refused rather than downgraded.
func TestBuild_PKCERefusesPlain(t *testing.T) {
	cfg := testConfig()
	cfg.RequirePKCE = false

	p, err := Build(context.Background(), testTenantID, cfg, testDeps(t))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}

	location := authorize(t, p.Handler(), url.Values{
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {"a-plain-verifier"},
		"code_challenge_method": {"plain"},
	})
	if got := location.Query().Get("error"); got != "invalid_request" {
		t.Errorf("authorize with a plain challenge gives error %q, want %q", got, "invalid_request")
	}
}

// TestBuild_ResourceIndicators covers the resource_indicators column, through an
// authorization request that names a resource. The tenant declares the
// identifiers its clients can ask for, so an identifier the tenant does not
// declare is refused with invalid_target.
//
// The indicator is enabled and not required. A request that names no resource
// therefore passes, and it yields a token with no aud, which every resource
// server refuses. A tenant with an empty list runs without the indicator, so
// every resource passes.
//
// login_required is the pass outcome: the request reached the authentication
// policy, which is the stub that fails there.
func TestBuild_ResourceIndicators(t *testing.T) {
	cases := []struct {
		name      string
		declared  []string
		resource  string
		wantError string
	}{
		{
			name:      "a declared resource passes",
			declared:  []string{aooidc.ResourceAdminAPI, aooidc.ResourceAccountAPI},
			resource:  aooidc.ResourceAdminAPI,
			wantError: "login_required",
		},
		{
			name:      "an undeclared resource is refused",
			declared:  []string{aooidc.ResourceAccountAPI},
			resource:  aooidc.ResourceAdminAPI,
			wantError: "invalid_target",
		},
		{
			name:      "no resource is not required",
			declared:  []string{aooidc.ResourceAdminAPI},
			resource:  "",
			wantError: "login_required",
		},
		{
			name:      "an empty list leaves the indicator off",
			declared:  nil,
			resource:  "urn:anything:at-all",
			wantError: "login_required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.RequirePKCE = false
			cfg.ResourceIndicators = tc.declared

			p, err := Build(context.Background(), testTenantID, cfg, testDeps(t))
			if err != nil {
				t.Fatalf("build provider: %v", err)
			}

			query := url.Values{
				"client_id":     {testClientID},
				"redirect_uri":  {testRedirectURI},
				"response_type": {"code"},
				"scope":         {"openid"},
			}
			if tc.resource != "" {
				query.Set("resource", tc.resource)
			}

			location := authorize(t, p.Handler(), query)
			if got := location.Query().Get("error"); got != tc.wantError {
				t.Errorf("authorize with resource %q gives error %q, want %q",
					tc.resource, got, tc.wantError)
			}
		})
	}
}

// TestBuild_AdvertisesSignableAlgsOnly covers a tenant whose key set publishes
// an inactive key. The key set carries active and inactive keys, because an
// inactive key still verifies an old token, but only an active key signs a new
// one. Discovery must advertise the algorithms the tenant can sign with, or a
// client picks one and the token endpoint fails.
func TestBuild_AdvertisesSignableAlgsOnly(t *testing.T) {
	deps := testDeps(t)
	activeJWKS, _ := deps.JWKS(context.Background())
	inactive := testJWK(t, aocrypto.AlgRS256, "key-2")

	deps.JWKS = func(context.Context) (goidc.JSONWebKeySet, error) {
		return goidc.JSONWebKeySet{Keys: append(activeJWKS.Keys, inactive)}, nil
	}
	signer := deps.Signer
	deps.Signer = func(ctx context.Context, alg goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
		if alg != goidc.SignatureAlgorithm(aocrypto.AlgES256) {
			return "", nil, aooidc.ErrNoSigningKey
		}
		return signer(ctx, alg)
	}

	p, err := Build(context.Background(), testTenantID, testConfig(), deps)
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}

	_, doc := get(t, p.Handler(), "/.well-known/openid-configuration")
	algs := values(doc["id_token_signing_alg_values_supported"])
	if len(algs) != 1 || algs[0] != aocrypto.AlgES256 {
		t.Errorf("discovery advertises %v, want only %q", algs, aocrypto.AlgES256)
	}
}

// TestBuild_DefaultRefreshLifetime covers a tenant that stores no refresh token
// lifetime. A null column reads as the shipped default, never as a disabled
// grant, so discovery still advertises the refresh grant.
func TestBuild_DefaultRefreshLifetime(t *testing.T) {
	cfg := testConfig()
	cfg.RefreshTokenLifetimeSecs = nil

	p, err := Build(context.Background(), testTenantID, cfg, testDeps(t))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}

	_, doc := get(t, p.Handler(), "/.well-known/openid-configuration")
	assertHolds(t, doc, "grant_types_supported", "refresh_token")
}

// TestBuild_TokenAdminEndpoints covers introspection and revocation. Both are
// enabled, so the discovery document names them and a client can find them.
func TestBuild_TokenAdminEndpoints(t *testing.T) {
	p, err := Build(context.Background(), testTenantID, testConfig(), testDeps(t))
	if err != nil {
		t.Fatalf("build provider: %v", err)
	}

	_, doc := get(t, p.Handler(), "/.well-known/openid-configuration")
	want := map[string]string{
		"introspection_endpoint": testIssuer + "/oidc/v1/introspect",
		"revocation_endpoint":    testIssuer + "/oidc/v1/revoke",
	}
	for field, value := range want {
		if doc[field] != value {
			t.Errorf("discovery %s is %v, want %q", field, doc[field], value)
		}
	}
}

// TestBuild_OpaqueAccessToken covers a tenant row that asks for an opaque
// access token. Only a JWT access token is implemented, so the build fails
// rather than issuing a token the resource server cannot read.
func TestBuild_OpaqueAccessToken(t *testing.T) {
	cfg := testConfig()
	cfg.AccessTokenType = aooidc.AccessTokenTypeOpaque

	if _, err := Build(context.Background(), testTenantID, cfg, testDeps(t)); !errors.Is(err, ErrOpaqueAccessToken) {
		t.Fatalf("build gives %v, want ErrOpaqueAccessToken", err)
	}
}

// TestBuild_LogsNoErrorItReturns covers where a failure is logged. Build returns
// its error to the handler, which logs it once and answers the client. A log
// line here as well would report every broken tenant twice.
func TestBuild_LogsNoErrorItReturns(t *testing.T) {
	failures := map[string]func(*aooidc.ProviderConfig, *Deps){
		"opaque access token": func(cfg *aooidc.ProviderConfig, _ *Deps) {
			cfg.AccessTokenType = aooidc.AccessTokenTypeOpaque
		},
		"no signing key": func(_ *aooidc.ProviderConfig, deps *Deps) {
			deps.JWKS = func(context.Context) (goidc.JSONWebKeySet, error) {
				return goidc.JSONWebKeySet{}, nil
			}
		},
	}

	for name, breakIt := range failures {
		t.Run(name, func(t *testing.T) {
			log, logs := logger.NewObserved()
			cfg := testConfig()
			deps := testDeps(t)
			deps.Log = log
			breakIt(&cfg, &deps)

			if _, err := Build(context.Background(), testTenantID, cfg, deps); err == nil {
				t.Fatal("build succeeded, want it to fail")
			}
			if got := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); got != 0 {
				t.Errorf("build logged %d errors, want 0 because the handler logs it", got)
			}
		})
	}
}

// TestBuild_NoSigningKey covers a tenant whose key set is empty. The provider
// cannot sign a token, so the build fails.
func TestBuild_NoSigningKey(t *testing.T) {
	deps := testDeps(t)
	deps.JWKS = func(context.Context) (goidc.JSONWebKeySet, error) { return goidc.JSONWebKeySet{}, nil }

	if _, err := Build(context.Background(), testTenantID, testConfig(), deps); !errors.Is(err, ErrNoSignatureAlg) {
		t.Fatalf("build gives %v, want ErrNoSignatureAlg", err)
	}
}

// assertHolds checks that a discovery array carries every wanted value.
func assertHolds(t *testing.T, doc map[string]any, field string, wanted ...string) {
	t.Helper()

	got := values(doc[field])
	for _, want := range wanted {
		found := false
		for _, value := range got {
			if value == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("discovery %s is %v, want it to hold %q", field, got, want)
		}
	}
}

// values reads a discovery array as strings.
func values(raw any) []string {
	list, _ := raw.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if value, ok := item.(string); ok {
			out = append(out, value)
		}
	}
	return out
}
