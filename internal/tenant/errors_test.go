package tenant

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
)

// TestErrLastLocalOwnerMaps covers the slug of the first guard rail of
// docs/specs/0002-directory-sign-in.md.
//
// Two other domains raise this sentinel: the membership write that revokes a
// role, and the identity provider write that claims a domain. Both answer the
// slug this package registers, so the console branches on one string wherever
// the refusal comes from.
func TestErrLastLocalOwnerMaps(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return response.Fail(c, fmt.Errorf("revoke a membership: %w", ErrLastLocalOwner))
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != fiber.StatusConflict {
		t.Errorf("status is %d, want %d", res.StatusCode, fiber.StatusConflict)
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if body.Error != "last_local_owner" {
		t.Errorf("the answer carries the slug %q, want last_local_owner", body.Error)
	}
}
