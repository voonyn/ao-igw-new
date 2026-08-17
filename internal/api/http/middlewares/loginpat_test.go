package middlewares

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/platform/logger"
)

// patApp mounts the middleware in front of one route that answers 200.
func patApp(t *testing.T, pats []string) *fiber.App {
	t.Helper()

	log, _ := logger.NewObserved()
	app := fiber.New()
	app.Get("/api/v1/login/session", LoginPAT(pats, log), func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

// callWithPAT runs one request and returns its status.
func callWithPAT(t *testing.T, app *fiber.App, header string, presented string) int {
	t.Helper()

	req := httptest.NewRequest(fiber.MethodGet, "/api/v1/login/session", nil)
	if header != "" {
		req.Header.Set(header, presented)
	}
	res, err := app.Test(req)
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck
	return res.StatusCode
}

// TestLoginPAT covers the two answers of the check: an accepted token reaches
// the route, and everything else stops at 401.
func TestLoginPAT(t *testing.T) {
	app := patApp(t, []string{"the-old-pat", "the-new-pat"})

	cases := []struct {
		name      string
		header    string
		presented string
		want      int
	}{
		{"the token in rotation", LoginPATHeader, "the-old-pat", fiber.StatusOK},
		{"the new token", LoginPATHeader, "the-new-pat", fiber.StatusOK},
		{"a token nobody issued", LoginPATHeader, "a-guess", fiber.StatusUnauthorized},
		{"an empty token", LoginPATHeader, "", fiber.StatusUnauthorized},
		{"no header at all", "", "", fiber.StatusUnauthorized},
	}
	for _, c := range cases {
		if got := callWithPAT(t, app, c.header, c.presented); got != c.want {
			t.Errorf("%s gives %d, want %d", c.name, got, c.want)
		}
	}
}

// TestLoginPAT_NoneConfigured covers a gateway with no token configured. The
// login steps are then closed, rather than open to everyone.
func TestLoginPAT_NoneConfigured(t *testing.T) {
	app := patApp(t, nil)

	if got := callWithPAT(t, app, LoginPATHeader, "any-token"); got != fiber.StatusUnauthorized {
		t.Errorf("status is %d, want %d", got, fiber.StatusUnauthorized)
	}
}
