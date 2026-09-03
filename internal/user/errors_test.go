package user

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
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

// TestErrDirectoryNoEntryMaps covers the answer a person reads when no single
// directory entry proves them.
//
// The state is permanent: no live active Identity Link, more than one, a search
// that matched none, or a search that matched two. It is not a directory that is
// down for a moment, so the answer is 409 and never the 503 the outage answers,
// and the message tells the person to ask an administrator.
func TestErrDirectoryNoEntryMaps(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return response.Fail(c, fmt.Errorf("re-prove the person: %w", ErrDirectoryNoEntry))
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
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("read the body: %v", err)
	}
	if body.Error != "directory_no_entry" {
		t.Errorf("the slug is %q, want %q", body.Error, "directory_no_entry")
	}
	if body.Error == "directory_unavailable" {
		t.Error("a permanent state borrowed the slug of a transient one")
	}
	if !strings.Contains(strings.ToLower(body.Message), "administrator") {
		t.Errorf("the message is %q, want one that names an administrator", body.Message)
	}
	if strings.Contains(strings.ToLower(body.Message), "try again") {
		t.Errorf("the message is %q, want one that never says to try again", body.Message)
	}
}

// TestErrPasswordNotLocalMaps covers the slug both password paths of this domain
// answer with. The self-service change and the administrative reset refuse the
// same person, so one sentinel and one slug serve both.
//
// The mapper is registered once, for the whole package. The admin handler and
// the account handler read the same rule.
func TestErrPasswordNotLocalMaps(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return response.Fail(c, fmt.Errorf("reset the password of a user: %w", ErrPasswordNotLocal))
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
		t.Fatalf("read the body: %v", err)
	}
	if body.Error != "password_not_local" {
		t.Errorf("the slug is %q, want %q", body.Error, "password_not_local")
	}
}
