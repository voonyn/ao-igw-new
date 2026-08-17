package oidc

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// TestErrInteractionRequiredMaps covers the rule that a domain registers its
// own sentinels. This package declares ErrInteractionRequired, so the mapper
// answers for it here, with no other domain imported.
//
// The login UI reads the 401 and renders the sign-in flow.
func TestErrInteractionRequiredMaps(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return response.Fail(c, fmt.Errorf("complete login: %w", ErrInteractionRequired))
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != fiber.StatusUnauthorized {
		t.Errorf("status is %d, want %d", res.StatusCode, fiber.StatusUnauthorized)
	}
}
