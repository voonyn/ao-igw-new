package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	aooidc "alphaomega/identitygateway/internal/api/oidc"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

const (
	testHost   = "auth.acme.test"
	testIssuer = "https://" + testHost
)

// oidcApp mounts the OIDC endpoints over a stub tenant lookup and a stub
// provider build, so the test needs no database and no signing key. The stub
// provider answers every path with the tenant it was built for.
func oidcApp(t *testing.T) *fiber.App {
	t.Helper()

	return oidcAppWithBuild(t, okBuild, logger.New())
}

// okBuild is the stub provider. It answers every path with the tenant it was
// built for, so a test reads which tenant a request reached.
func okBuild(_ context.Context, tenantID string, _ oidc.ProviderConfig) (http.Handler, error) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"tenant_id": tenantID, "path": r.URL.Path})
	}), nil
}

// oidcAppWithBuild mounts the OIDC endpoints over a stated provider build, so a
// test can state what the build does, including how it fails. The request id
// middleware is mounted as the server mounts it, so the log lines carry the id.
func oidcAppWithBuild(t *testing.T, build aooidc.Builder, log logger.Logger) *fiber.App {
	t.Helper()

	lookup := func(_ context.Context, host string) (middlewares.TenantContext, error) {
		if host != testHost {
			return middlewares.TenantContext{}, tenant.ErrDomainNotFound
		}
		return middlewares.TenantContext{
			TenantID: "tenant-1",
			Config:   oidc.ProviderConfig{TenantID: "tenant-1", Issuer: testIssuer, State: 1},
		}, nil
	}

	// PassLocalsToContext is what carries the request id into the request
	// context, so the test app is built the way the server builds it.
	app := fiber.New(fiber.Config{PassLocalsToContext: true})
	app.Use(requestid.New())
	// The test has no database, so the transaction middleware runs the request
	// on the caller's context.
	runNow := func(ctx context.Context, fn func(context.Context) error) error { return fn(ctx) }
	mountOIDC(app, "/oidc/v1", middlewares.Tenant(lookup, "", log), aooidc.NewRegistry(build, log), runNow, log)
	app.Use(NotFoundHandler)
	return app
}

// send runs one GET against the app and returns the status and the body.
func send(t *testing.T, app *fiber.App, host, path string) (int, map[string]string) {
	t.Helper()

	return sendMethod(t, app, fiber.MethodGet, host, path)
}

// sendMethod runs one request of any method against the app.
func sendMethod(t *testing.T, app *fiber.App, method, host, path string) (int, map[string]string) {
	t.Helper()

	req := httptest.NewRequest(method, "http://"+host+path, nil)
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("request %s: %v", path, err)
	}
	defer res.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", path, err)
	}
	var body map[string]string
	_ = json.Unmarshal(raw, &body)
	return res.StatusCode, body
}

// TestMountOIDC_ServesTheTenantProvider covers the two paths S6 delivers:
// discovery at the root, and the protocol endpoints under the prefix. Both
// reach the provider of the tenant the host names, with the full path intact.
func TestMountOIDC_ServesTheTenantProvider(t *testing.T) {
	app := oidcApp(t)

	paths := []string{"/.well-known/openid-configuration", "/oidc/v1/jwks"}
	for _, path := range paths {
		status, body := send(t, app, testHost, path)
		if status != fiber.StatusOK {
			t.Fatalf("GET %s gives status %d, want %d", path, status, fiber.StatusOK)
		}
		if body["tenant_id"] != "tenant-1" {
			t.Errorf("GET %s reached tenant %q, want %q", path, body["tenant_id"], "tenant-1")
		}
		if body["path"] != path {
			t.Errorf("GET %s reached the provider as %q, want the full path", path, body["path"])
		}
	}
}

// TestMountOIDC_RefusesClientRegistration covers the registration endpoints.
// Dynamic client registration is out of scope, and the protocol engine serves
// the registration management endpoints as soon as it holds a client store, so
// the mount refuses them. A client is created by an operator, never over HTTP.
func TestMountOIDC_RefusesClientRegistration(t *testing.T) {
	app := oidcApp(t)

	methods := []string{fiber.MethodGet, fiber.MethodPut, fiber.MethodDelete}
	for _, method := range methods {
		status, _ := sendMethod(t, app, method, testHost, "/oidc/v1/register/console-ui")
		if status != fiber.StatusNotFound {
			t.Errorf("%s /oidc/v1/register/console-ui gives status %d, want %d",
				method, status, fiber.StatusNotFound)
		}
	}
}

// TestMountOIDC_BrokenTenantConfig covers a tenant whose row cannot build a
// provider. The tenant exists, so the answer is not 404, and the gateway itself
// is healthy, so it is not 500 either. The tenant cannot serve, which is 503.
// Any other build failure stays 500.
func TestMountOIDC_BrokenTenantConfig(t *testing.T) {
	cases := []struct {
		name       string
		buildErr   error
		wantStatus int
	}{
		{
			name:       "the row asks for an opaque access token",
			buildErr:   fmt.Errorf("tenant tenant-1: %w", aooidc.ErrOpaqueAccessToken),
			wantStatus: fiber.StatusServiceUnavailable,
		},
		{
			name:       "the tenant has no signing key",
			buildErr:   fmt.Errorf("tenant tenant-1: %w", aooidc.ErrNoSignatureAlg),
			wantStatus: fiber.StatusServiceUnavailable,
		},
		{
			name:       "the database is unreachable",
			buildErr:   errors.New("dial tcp: connection refused"),
			wantStatus: fiber.StatusInternalServerError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app := oidcAppWithBuild(t, func(context.Context, string, oidc.ProviderConfig) (http.Handler, error) {
				return nil, tc.buildErr
			}, logger.New())

			status, _ := send(t, app, testHost, "/oidc/v1/jwks")
			if status != tc.wantStatus {
				t.Errorf("GET /oidc/v1/jwks gives status %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

// TestMountOIDC_LogsCarryTheRequestID covers troubleshooting. Every line the
// OIDC path logs must name the request it belongs to, or no engineer can follow
// one request through the layers.
func TestMountOIDC_LogsCarryTheRequestID(t *testing.T) {
	const requestID = "req-42"

	log, logs := logger.NewObserved()
	app := oidcAppWithBuild(t, okBuild, log)

	req := httptest.NewRequest(fiber.MethodGet, "http://"+testHost+"/oidc/v1/jwks", nil)
	req.Header.Set(fiber.HeaderXRequestID, requestID)
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck

	entries := logs.All()
	if len(entries) == 0 {
		t.Fatal("the request logged nothing, want the layers to log their entry and exit")
	}
	for _, entry := range entries {
		if entry.ContextMap()["request_id"] != requestID {
			t.Errorf("%q logged at %s carries request_id %v, want %q",
				entry.Message, entry.Level, entry.ContextMap()["request_id"], requestID)
		}
	}
}

// TestMountOIDC_UnknownHost covers a host no tenant owns. The answer is 404 on
// every OIDC path, so the response never says which tenants exist.
func TestMountOIDC_UnknownHost(t *testing.T) {
	app := oidcApp(t)

	paths := []string{"/.well-known/openid-configuration", "/oidc/v1/jwks"}
	for _, path := range paths {
		status, _ := send(t, app, "nobody.example", path)
		if status != fiber.StatusNotFound {
			t.Errorf("GET %s on an unknown host gives status %d, want %d", path, status, fiber.StatusNotFound)
		}
	}
}
