package middlewares

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"go.uber.org/zap/zapcore"

	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
	"go.uber.org/zap/zaptest/observer"
)

// logApp mounts the request log in front of one route that answers with status.
// The tenant is put on the request by hand, because the tenant middleware needs
// a database and this test does not.
func logApp(t *testing.T, status int, tenantID string) (*fiber.App, *observer.ObservedLogs) {
	t.Helper()

	log, logs := logger.NewObserved()
	app := fiber.New()
	app.Use(requestid.New())
	app.Use(RequestLog(log))
	app.Get("/api/v1/login/session", func(c fiber.Ctx) error {
		if tenantID != "" {
			c.Locals(tenantLocalsKey, TenantContext{TenantID: tenantID, Config: oidc.ProviderConfig{}})
		}
		return c.SendStatus(status)
	})
	return app, logs
}

// callLogged runs one request through the app.
func callLogged(t *testing.T, app *fiber.App) {
	t.Helper()

	res, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/api/v1/login/session", nil))
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
}

// fields turns one recorded entry into a map, so a test reads a field by name.
func fields(t *testing.T, entry observer.LoggedEntry) map[string]any {
	t.Helper()

	return entry.ContextMap()
}

// TestRequestLog covers the rule that every request leaves exactly one info
// line, and that the line carries what an engineer needs to find the request.
func TestRequestLog(t *testing.T) {
	app, logs := logApp(t, fiber.StatusOK, "tenant-1")

	callLogged(t, app)

	entries := logs.FilterLevelExact(zapcore.InfoLevel).All()
	if len(entries) != 1 {
		t.Fatalf("request logged %d info lines, want 1", len(entries))
	}

	got := fields(t, entries[0])
	if got["method"] != fiber.MethodGet {
		t.Errorf("method is %v, want %s", got["method"], fiber.MethodGet)
	}
	if got["path"] != "/api/v1/login/session" {
		t.Errorf("path is %v, want /api/v1/login/session", got["path"])
	}
	if got["status"] != int64(fiber.StatusOK) {
		t.Errorf("status is %v, want %d", got["status"], fiber.StatusOK)
	}
	if got["tenant_id"] != "tenant-1" {
		t.Errorf("tenant id is %v, want tenant-1", got["tenant_id"])
	}
	if id, ok := got["request_id"].(string); !ok || id == "" {
		t.Errorf("request id is %v, want the id the requestid middleware set", got["request_id"])
	}
	if _, ok := got["duration"]; !ok {
		t.Error("the line carries no duration")
	}
}

// TestRequestLog_Failed covers a request the route refused. It is logged at
// info like any other, because the middleware reports the answer and never
// decides that an answer is an error.
func TestRequestLog_Failed(t *testing.T) {
	app, logs := logApp(t, fiber.StatusUnauthorized, "")

	callLogged(t, app)

	entries := logs.FilterLevelExact(zapcore.InfoLevel).All()
	if len(entries) != 1 {
		t.Fatalf("request logged %d info lines, want 1", len(entries))
	}
	if got := fields(t, entries[0]); got["status"] != int64(fiber.StatusUnauthorized) {
		t.Errorf("status is %v, want %d", got["status"], fiber.StatusUnauthorized)
	}
}
