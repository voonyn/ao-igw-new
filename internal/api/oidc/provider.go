package oidc

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/luikyv/go-oidc/pkg/goidc"
	"github.com/luikyv/go-oidc/pkg/provider"

	"alphaomega/identitygateway/internal/audit"
	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrOpaqueAccessToken reports a tenant row that asks for an opaque access
// token. Only a JWT access token is implemented, so the build fails rather than
// issuing a token no resource server can read.
var ErrOpaqueAccessToken = errors.New("opaque access tokens are not supported")

// ErrNoSignatureAlg reports that the tenant publishes no signature algorithm.
// The provider cannot sign a token, so it never serves.
var ErrNoSignatureAlg = errors.New("tenant has no signature algorithm")

// defaultRefreshTokenLifetimeSecs is what a null refresh_token_lifetime_secs
// reads as. It repeats the column default migration 00037 shipped, because
// that migration deliberately left existing rows null. An unset lifetime must
// never reach goidc, which stamps no expiry at all on the refresh token.
const defaultRefreshTokenLifetimeSecs = 2592000

// Deps is the database side of one tenant's provider. Every field is a function
// value, so a test builds a provider without a database.
type Deps struct {
	// PathPrefix namespaces every endpoint except discovery, which the
	// specification fixes at /.well-known/openid-configuration.
	PathPrefix string

	// LoginURL is the base URL of the login UI. An empty value leaves the
	// handoff unbuilt, and every authorization request fails with
	// login_required.
	LoginURL string

	// ACRPrefix is the URN the two assurance levels are built on. The tenant
	// advertises both of them, and the finalize step writes one of them onto
	// every sign-in, so both read one deployment setting.
	ACRPrefix string

	JWKS    goidc.JWKSFunc
	Signer  goidc.SignerFunc
	Client  ClientFinder
	Storage StorageFuncs
	Audit   *audit.Recorder
	Log     logger.Logger

	// Terminate ends one login session. A nil value leaves RP-initiated logout
	// unbuilt, and the tenant then advertises no logout endpoint.
	Terminate Terminator

	// Scopes names the scopes the tenant advertises. A nil value leaves the
	// goidc default set in place.
	Scopes ScopeFinder

	// Claims reads the claims of one person. A nil value releases the standard
	// claims alone.
	Claims ClaimsFinder
}

// ScopeFinder reads the scopes one tenant advertises.
type ScopeFinder func(ctx context.Context) ([]string, error)

// Build makes the protocol engine of one tenant. Every knob comes from the
// tenant's provider config row, never from the environment.
//
// Build logs no error. It returns every failure to the handler, which logs it
// once and answers the client.
func Build(ctx context.Context, tenantID string, cfg aooidc.ProviderConfig, deps Deps) (*provider.Provider, error) {
	deps.Log.Debug("build provider",
		logger.String("tenant_id", tenantID),
		logger.String("issuer", cfg.Issuer),
		logger.RequestID(ctx))

	if cfg.AccessTokenType == aooidc.AccessTokenTypeOpaque {
		return nil, fmt.Errorf("%w: tenant %s", ErrOpaqueAccessToken, tenantID)
	}

	jwks, err := deps.JWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("read key set of tenant %s: %w", tenantID, err)
	}
	algs := signatureAlgs(ctx, jwks, deps.Signer)
	if len(algs) == 0 {
		return nil, fmt.Errorf("%w: tenant %s", ErrNoSignatureAlg, tenantID)
	}

	storage := NewStorageManager(tenantID, deps.Storage, deps.Audit, deps.Log)
	clients := NewClientManager(tenantID, deps.Client, deps.Log)

	pkce := []provider.PKCEOption{}
	if cfg.RequirePKCE {
		pkce = append(pkce, provider.WithPKCERequired())
	}

	opts := []provider.Option{
		provider.WithPathPrefix(deps.PathPrefix),
		provider.WithSigner(deps.Signer),
		provider.WithAuthCodeGrant(
			provider.AuthCodeGrantConfig{
				Manager:       storage,
				ResponseTypes: []goidc.ResponseType{goidc.ResponseTypeCode},
			},
			provider.WithAuthCodeLifetime(cfg.AuthorizationCodeLifetimeSecs),
			provider.WithPKCE([]goidc.CodeChallengeMethod{goidc.CodeChallengeMethodSHA256}, pkce...),
			provider.WithAuthPolicies(authPolicy(deps)),
		),
		provider.WithSecretBasicAuthn(),
		provider.WithSecretPostAuthn(),
		provider.WithNoneAuthn(),
		provider.WithClientSecretVerifier(aooidc.VerifyClientSecret),
		provider.WithIDTokenLifetime(cfg.IDTokenLifetimeSecs),
		provider.WithTokenOptions(jwtTokenOptions(algs[0], cfg.AccessTokenLifetimeSecs)),
		provider.WithDCR(clients, provider.WithDCRInitialTokenValidator(RefuseRegistration)),
		provider.WithErrorHandler(ErrorLogger(tenantID, deps.Log)),
		provider.WithTokenIntrospection(IntrospectionAllowed),
		// Any authenticated client can revoke. The engine authenticates the
		// client before it calls this, and it refuses a token that belongs to
		// another client, so no further rule is needed here.
		//
		// The access token is a JWT, which no store holds. Revocation is
		// therefore effective only when it ends the whole grant.
		provider.WithTokenRevocation(
			func(context.Context, *goidc.Client) bool { return true },
			provider.WithTokenRevocationRevokeGrantOnAccessToken()),
		// Both assurance levels are advertised, so a client can ask for either
		// one. Asking is a voluntary hint: it never raises the bar of the
		// sign-in, and the acr claim reports what the person actually proved. A
		// client that needs two factors reads the claim back and decides for
		// itself. See docs/adr/0010.
		//
		// goidc refuses a request that names a level outside this list, which is
		// what advertising a closed set means. A client that asks for a level
		// this gateway does not measure is told so, rather than receiving a
		// token that silently answers something else.
		provider.WithACRs(
			goidc.ACR(acrValue(deps.ACRPrefix, acrOneFactor)),
			goidc.ACR(acrValue(deps.ACRPrefix, acrMultiFactor))),
	}

	if deps.Audit != nil {
		opts = append(opts, provider.WithTokenHandler(tokenAudit(tenantID, deps.Audit)))
	}

	if deps.Terminate != nil {
		opts = append(opts, provider.WithLogout(
			provider.LogoutConfig{
				Manager:    passingLogoutSessions{},
				HandleFunc: DefaultPostLogout(deps.LoginURL, deps.Log),
			},
			provider.WithLogoutPolicies(LogoutPolicy(tenantID, LogoutDeps{
				Terminate: deps.Terminate,
				Grants:    deps.Storage.GrantsByLoginSession,
				Revoke:    storage.SaveGrant,
				Audit:     deps.Audit,
				Log:       deps.Log,
			}))))
	}

	// RFC 8707. The tenant declares the resource identifiers its clients can ask
	// for, and the requested value lands in the access token aud. The indicator
	// is enabled and not required: a client that sends no resource receives a
	// token with no aud, and every resource server refuses that token. A tenant
	// with an empty list runs without the indicator.
	if len(cfg.ResourceIndicators) > 0 {
		resources := make([]goidc.ResourceIndicator, 0, len(cfg.ResourceIndicators))
		for _, r := range cfg.ResourceIndicators {
			resources = append(resources, goidc.ResourceIndicator(r))
		}
		opts = append(opts, provider.WithResourceIndicators(resources))
	}

	if deps.Scopes != nil {
		names, err := deps.Scopes(ctx)
		if err != nil {
			return nil, fmt.Errorf("read scopes of tenant %s: %w", tenantID, err)
		}
		scopes := make([]goidc.Scope, 0, len(names))
		for _, name := range names {
			scopes = append(scopes, goidc.NewScope(name))
		}
		opts = append(opts, provider.WithScopes(scopes...))
	}

	if deps.Claims != nil {
		opts = append(opts,
			provider.WithIDTokenClaims(IDTokenClaims(tenantID, deps.Claims, deps.Log)),
			provider.WithUserInfoClaims(UserInfoClaims(tenantID, deps.Claims, deps.Log)))
	}

	refreshLifetime := defaultRefreshTokenLifetimeSecs
	if cfg.RefreshTokenLifetimeSecs != nil {
		refreshLifetime = *cfg.RefreshTokenLifetimeSecs
	}
	// Rotation is what makes a replay detectable: the store retains the digest
	// of the token each refresh replaces, and a second use of that token
	// revokes the grant. See internal/oidc/storage_repo.go.
	opts = append(opts, provider.WithRefreshTokenGrant(storage,
		provider.WithRefreshTokenLifetime(refreshLifetime),
		provider.WithRefreshTokenRotation()))

	p, err := provider.New(provider.Config{
		Issuer:      cfg.Issuer,
		Manager:     storage,
		JWKS:        deps.JWKS,
		IDTokenAlgs: algs,
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("build provider of tenant %s: %w", tenantID, err)
	}

	deps.Log.Debug("built provider",
		logger.String("tenant_id", tenantID),
		logger.String("issuer", cfg.Issuer),
		logger.RequestID(ctx))
	return p, nil
}

// Builder makes the HTTP handler of one tenant. The registry caches what it
// returns, and a test replaces it with a counter.
type Builder func(ctx context.Context, tenantID string, cfg aooidc.ProviderConfig) (http.Handler, error)

// Services are the domain services a provider reads. The router hands them
// over here, so no package outside this one names a goidc type.
type Services struct {
	PathPrefix string
	LoginURL   string
	ACRPrefix  string
	Keys       *aooidc.KeyService
	Clients    *aooidc.ClientService
	Storage    *aooidc.StorageRepository
	Scopes     *aooidc.ScopeService
	Claims     *aooidc.ClaimsService
	Audit      *audit.Recorder
	Log        logger.Logger

	// Terminate ends one login session. A nil value leaves RP-initiated logout
	// unbuilt.
	Terminate Terminator
}

// NewBuilder returns the Builder the registry caches. It binds each tenant to
// the domain services and answers with the HTTP handler that tenant serves.
func NewBuilder(svc Services) Builder {
	return func(ctx context.Context, tenantID string, cfg aooidc.ProviderConfig) (http.Handler, error) {
		p, err := Build(ctx, tenantID, cfg, svc.deps(tenantID))
		if err != nil {
			return nil, err
		}
		return p.Handler(), nil
	}
}

// deps binds one tenant to the domain services. Every store method takes the
// tenant id, and the provider is built per tenant, so the id is bound once here.
func (s Services) deps(tenantID string) Deps {
	deps := Deps{
		PathPrefix: s.PathPrefix,
		LoginURL:   s.LoginURL,
		ACRPrefix:  s.ACRPrefix,
		Audit:      s.Audit,
		Terminate:  s.Terminate,
		JWKS: func(ctx context.Context) (goidc.JSONWebKeySet, error) {
			return s.Keys.PublicKeySet(ctx, tenantID)
		},
		Signer: func(ctx context.Context, alg goidc.SignatureAlgorithm) (string, crypto.Signer, error) {
			return s.Keys.Signer(ctx, tenantID, alg)
		},
		Client: s.Clients.FindByClientID,
		Storage: StorageFuncs{
			SaveGrant:            s.Storage.SaveGrant,
			Grant:                s.Storage.FindGrant,
			GrantByAuthCode:      s.Storage.FindGrantByAuthCode,
			GrantByRefreshToken:  s.Storage.FindGrantByRefreshToken,
			GrantsByLoginSession: s.Storage.FindGrantsByLoginSession,
			SaveSession:          s.Storage.SaveSession,
			Session:              s.Storage.FindSession,
		},
		Log: s.Log,
	}

	if s.Scopes != nil {
		deps.Scopes = func(ctx context.Context) ([]string, error) {
			return s.Scopes.Advertised(ctx, tenantID)
		}
	}
	if s.Claims != nil {
		deps.Claims = s.Claims.Claims
	}
	return deps
}

// signatureAlgs reads the algorithms the tenant can sign a new token with, in
// the order the key set holds them. The first one signs new tokens, and the key
// set puts the active key first.
//
// The key set also publishes inactive keys, so an old token still verifies, but
// an inactive key never signs. Each algorithm is therefore offered to the
// signer, and only the ones it accepts are advertised. Advertising an algorithm
// with no active key would fail a client at the token endpoint.
func signatureAlgs(ctx context.Context, jwks goidc.JSONWebKeySet, sign goidc.SignerFunc) []goidc.SignatureAlgorithm {
	algs := make([]goidc.SignatureAlgorithm, 0, len(jwks.Keys))
	for _, key := range jwks.Keys {
		alg := goidc.SignatureAlgorithm(key.Algorithm)
		if alg == "" || slices.Contains(algs, alg) {
			continue
		}
		if _, _, err := sign(ctx, alg); err != nil {
			continue
		}
		algs = append(algs, alg)
	}
	return algs
}

// jwtTokenOptions issues every access token as a JWT of the tenant's lifetime,
// signed by the tenant's active key.
func jwtTokenOptions(alg goidc.SignatureAlgorithm, lifetimeSecs int) goidc.TokenOptionsFunc {
	return func(context.Context, *goidc.Grant, *goidc.Client) goidc.TokenOptions {
		return goidc.NewJWTTokenOptions(alg, lifetimeSecs)
	}
}

// authPolicy is how the tenant authenticates a person. It is the login handoff
// when a login UI is configured, and the refusal below otherwise.
func authPolicy(deps Deps) goidc.AuthnPolicy {
	if deps.LoginURL == "" {
		return loginRequiredPolicy()
	}
	return LoginPolicy(deps.LoginURL, deps.Log)
}

// loginRequiredPolicy answers when no login UI is configured. It fails every
// authorization request with login_required, so an authorization endpoint that
// reaches it answers the client instead of hanging.
func loginRequiredPolicy() goidc.AuthnPolicy {
	return goidc.NewPolicy("login-required-stub",
		func(*http.Request, *goidc.AuthnSession, *goidc.Client) bool { return true },
		func(http.ResponseWriter, *http.Request, *goidc.AuthnSession, *goidc.Client) (goidc.Status, error) {
			return goidc.StatusFailure, goidc.NewError(goidc.ErrorCodeLoginRequired, "login is not implemented yet")
		})
}
