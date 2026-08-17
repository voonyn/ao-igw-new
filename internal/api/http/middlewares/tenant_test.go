package middlewares

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// TestNormalizeHost covers the shapes a host arrives in: mixed case, a trailing
// dot from a fully qualified name, and a trusted header that carries a URL
// instead of a bare host.
func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Auth.Acme.COM", "auth.acme.com"},
		{"auth.acme.com.", "auth.acme.com"},
		{"  localhost:8080  ", "localhost:8080"},
		{"https://auth.acme.com/oidc/v1", "auth.acme.com"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeHost(c.in); got != c.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestVerifyIssuerHost covers the guard that stops a tenant from answering on a
// host its issuer does not name. Every token that tenant signs carries the
// issuer, so a mismatch is a misconfiguration, not a variant.
func TestVerifyIssuerHost(t *testing.T) {
	if err := verifyIssuerHost("https://auth.acme.com", "auth.acme.com"); err != nil {
		t.Errorf("matching host is rejected: %v", err)
	}
	if err := verifyIssuerHost("http://localhost:8080", "localhost:8080"); err != nil {
		t.Errorf("matching host with a port is rejected: %v", err)
	}
	if err := verifyIssuerHost("https://auth.acme.com", "auth.other.com"); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("error is %v, want ErrIssuerMismatch", err)
	}
	if err := verifyIssuerHost("auth.acme.com", "auth.acme.com"); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("an issuer without a scheme gives %v, want ErrIssuerMismatch", err)
	}
}

// testApp mounts the tenant middleware on a route that answers 200 and reports
// the host the lookup received.
func testApp(t *testing.T, lookup Lookup, header string) *fiber.App {
	t.Helper()

	app := fiber.New()
	app.Use(Tenant(lookup, header, logger.New()))
	app.Get("/", func(c fiber.Ctx) error {
		tc, ok := TenantFrom(c)
		if !ok {
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return c.SendString(tc.TenantID)
	})
	return app
}

// TestTenantMiddleware_ResolvesHost covers the normal path: the request host
// names the tenant, and the handler reads the tenant from the request.
func TestTenantMiddleware_ResolvesHost(t *testing.T) {
	var seen string
	lookup := func(_ context.Context, host string) (TenantContext, error) {
		seen = host
		return TenantContext{
			TenantID: "tenant-1",
			Config:   oidc.ProviderConfig{Issuer: "https://auth.acme.com"},
		}, nil
	}

	req := httptest.NewRequest("GET", "http://auth.acme.com/", nil)
	res, err := testApp(t, lookup, "").Test(req)
	if err != nil {
		t.Fatalf("call the route: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status is %d, want 200", res.StatusCode)
	}
	if seen != "auth.acme.com" {
		t.Errorf("the lookup received host %q, want %q", seen, "auth.acme.com")
	}
}

// TestTenantMiddleware_TrustedHeader covers the local development override: the
// configured header names the host, and the request host is ignored.
func TestTenantMiddleware_TrustedHeader(t *testing.T) {
	var seen string
	lookup := func(_ context.Context, host string) (TenantContext, error) {
		seen = host
		return TenantContext{
			TenantID: "tenant-1",
			Config:   oidc.ProviderConfig{Issuer: "http://localhost:8080"},
		}, nil
	}

	req := httptest.NewRequest("GET", "http://127.0.0.1:3000/", nil)
	req.Header.Set("X-AO-Tenant", "LOCALHOST:8080")
	res, err := testApp(t, lookup, "X-AO-Tenant").Test(req)
	if err != nil {
		t.Fatalf("call the route: %v", err)
	}
	if res.StatusCode != fiber.StatusOK {
		t.Fatalf("status is %d, want 200", res.StatusCode)
	}
	if seen != "localhost:8080" {
		t.Errorf("the lookup received host %q, want %q", seen, "localhost:8080")
	}
}

// TestTenantMiddleware_UnknownHost covers a host no tenant owns. The gateway
// must not disclose that the host is unknown to it in any other way than 404.
func TestTenantMiddleware_UnknownHost(t *testing.T) {
	lookup := func(context.Context, string) (TenantContext, error) {
		return TenantContext{}, tenant.ErrDomainNotFound
	}

	req := httptest.NewRequest("GET", "http://nobody.example/", nil)
	res, err := testApp(t, lookup, "").Test(req)
	if err != nil {
		t.Fatalf("call the route: %v", err)
	}
	if res.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status is %d, want 404", res.StatusCode)
	}
}

// TestTenantMiddleware_IssuerMismatch covers a tenant reached on a domain its
// issuer does not name.
func TestTenantMiddleware_IssuerMismatch(t *testing.T) {
	lookup := func(context.Context, string) (TenantContext, error) {
		return TenantContext{
			TenantID: "tenant-1",
			Config:   oidc.ProviderConfig{Issuer: "https://auth.acme.com"},
		}, nil
	}

	req := httptest.NewRequest("GET", "http://old.acme.com/", nil)
	res, err := testApp(t, lookup, "").Test(req)
	if err != nil {
		t.Fatalf("call the route: %v", err)
	}
	if res.StatusCode != fiber.StatusNotFound {
		t.Fatalf("status is %d, want 404", res.StatusCode)
	}
}
