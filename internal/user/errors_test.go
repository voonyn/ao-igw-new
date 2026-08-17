package user

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// TestErrNotFoundMaps covers the rule that a domain registers its own
// sentinels. This package owns ErrNotFound, so the mapper answers for it here,
// with no other domain imported.
//
// A person who typed an identifier nobody holds gets 401, the same answer a
// wrong password gets. The response never says which people a tenant holds.
func TestErrNotFoundMaps(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return response.Fail(c, fmt.Errorf("read user: %w", ErrNotFound))
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
