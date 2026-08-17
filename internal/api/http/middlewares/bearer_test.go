package middlewares

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/gofiber/fiber/v3"
	"github.com/luikyv/go-oidc/pkg/goidc"

	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	bearerIssuer   = "https://auth.acme.com"
	bearerTenantID = "tenant-1"
	bearerSubject  = "user-1"
)

// bearerKey makes one signing key of a tenant: the public half for the key set
// the middleware verifies against, and a signer for the token the test mints.
func bearerKey(t *testing.T, kid string) (goidc.JSONWebKey, jose.Signer) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key %s: %v", kid, err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatalf("build signer %s: %v", kid, err)
	}

	public := goidc.JSONWebKey{
		Key:       priv.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	return public, signer
}

// mintToken mints one access token. Every claim the middleware checks is a
// parameter, so a test states the one it bends.
func mintToken(t *testing.T, signer jose.Signer, issuer, audience string, expires time.Time) string {
	t.Helper()

	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Subject:  bearerSubject,
		Issuer:   issuer,
		Audience: jwt.Audience{audience},
		Expiry:   jwt.NewNumericDate(expires),
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}
	return raw
}

// bearerApp mounts the bearer middleware behind a stub that stands in for the
// tenant middleware. The route reports the subject, so a pass proves that the
// handler can read who is calling.
func bearerApp(keys goidc.JSONWebKeySet) *fiber.App {
	app := fiber.New()
	app.Use(func(c fiber.Ctx) error {
		c.Locals(tenantLocalsKey, TenantContext{
			TenantID: bearerTenantID,
			Config:   aooidc.ProviderConfig{Issuer: bearerIssuer},
		})
		return c.Next()
	})
	app.Use(Bearer(
		func(context.Context, string) (goidc.JSONWebKeySet, error) { return keys, nil },
		aooidc.ResourceAdminAPI,
		logger.New(),
	))
	app.Get("/", func(c fiber.Ctx) error {
		subject, ok := SubjectFrom(c)
		if !ok {
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return c.SendString(subject)
	})
	return app
}

// TestBearer covers the five outcomes of the guard on the admin API: one token
// it admits, and four it refuses. Each refusal answers 401 with the slug
// unauthenticated, so the console cannot tell them apart and an attacker learns
// nothing from the answer.
func TestBearer(t *testing.T) {
	public, signer := bearerKey(t, "kid-1")
	_, foreign := bearerKey(t, "kid-1") // same kid, another key: a bad signature
	keys := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{public}}

	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)

	cases := []struct {
		name       string
		header     string
		wantStatus int
	}{
		{
			name:       "a valid token is admitted",
			header:     "Bearer " + mintToken(t, signer, bearerIssuer, aooidc.ResourceAdminAPI, future),
			wantStatus: fiber.StatusOK,
		},
		{
			name:       "an expired token is refused",
			header:     "Bearer " + mintToken(t, signer, bearerIssuer, aooidc.ResourceAdminAPI, past),
			wantStatus: fiber.StatusUnauthorized,
		},
		{
			name:       "a token for another audience is refused",
			header:     "Bearer " + mintToken(t, signer, bearerIssuer, aooidc.ResourceAccountAPI, future),
			wantStatus: fiber.StatusUnauthorized,
		},
		{
			name:       "a token signed by another key is refused",
			header:     "Bearer " + mintToken(t, foreign, bearerIssuer, aooidc.ResourceAdminAPI, future),
			wantStatus: fiber.StatusUnauthorized,
		},
		{
			name:       "a missing header is refused",
			header:     "",
			wantStatus: fiber.StatusUnauthorized,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", bearerIssuer+"/", nil)
			if tc.header != "" {
				req.Header.Set(fiber.HeaderAuthorization, tc.header)
			}

			res, err := bearerApp(keys).Test(req)
			if err != nil {
				t.Fatalf("call the route: %v", err)
			}
			body, _ := io.ReadAll(res.Body)

			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status is %d, want %d, body %s", res.StatusCode, tc.wantStatus, body)
			}
			if tc.wantStatus == fiber.StatusOK {
				if string(body) != bearerSubject {
					t.Errorf("the handler read subject %q, want %q", body, bearerSubject)
				}
				return
			}

			var envelope struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(body, &envelope); err != nil {
				t.Fatalf("decode the error envelope: %v", err)
			}
			if envelope.Error != "unauthenticated" {
				t.Errorf("the error slug is %q, want %q", envelope.Error, "unauthenticated")
			}
		})
	}
}

// TestBearer_KeyWithoutAlg covers a published key that names no algorithm,
// which RFC 7517 permits. The guard reads the algorithm from the key itself, so
// a valid token is still admitted and the tenant does not lose the admin API.
func TestBearer_KeyWithoutAlg(t *testing.T) {
	public, signer := bearerKey(t, "kid-1")
	public.Algorithm = ""
	keys := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{public}}

	raw := mintToken(t, signer, bearerIssuer, aooidc.ResourceAdminAPI, time.Now().Add(time.Hour))
	req := httptest.NewRequest("GET", bearerIssuer+"/", nil)
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+raw)

	res, err := bearerApp(keys).Test(req)
	if err != nil {
		t.Fatalf("call the route: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status is %d, want %d, body %s", res.StatusCode, fiber.StatusOK, body)
	}
}

// TestBearer_IssuerMismatch covers a token another issuer signed with a key this
// tenant publishes. The signature alone is not enough: iss must name the tenant.
func TestBearer_IssuerMismatch(t *testing.T) {
	public, signer := bearerKey(t, "kid-1")
	keys := goidc.JSONWebKeySet{Keys: []goidc.JSONWebKey{public}}

	raw := mintToken(t, signer, "https://auth.other.com", aooidc.ResourceAdminAPI, time.Now().Add(time.Hour))
	req := httptest.NewRequest("GET", bearerIssuer+"/", nil)
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+raw)

	res, err := bearerApp(keys).Test(req)
	if err != nil {
		t.Fatalf("call the route: %v", err)
	}
	if res.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("status is %d, want 401", res.StatusCode)
	}
}
