package oidc

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// TestErrSessionNotFoundMaps covers the rule that a domain registers its own
// sentinels. This package declares ErrSessionNotFound, so the mapper answers
// for it here, with no other domain imported.
//
// The login UI named an authorization request the gateway does not hold, so the
// request is bad, not the credentials.
func TestErrSessionNotFoundMaps(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return response.Fail(c, fmt.Errorf("read authn session: %w", ErrSessionNotFound))
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != fiber.StatusBadRequest {
		t.Errorf("status is %d, want %d", res.StatusCode, fiber.StatusBadRequest)
	}
}
