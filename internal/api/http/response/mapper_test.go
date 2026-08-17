package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
)

var errRegistered = errors.New("registered sentinel")

func init() {
	Map(errRegistered, fiber.StatusUnauthorized, "unauthenticated", "Unauthorized")
}

// TestFailMapsARegisteredSentinel covers the mapper. A wrapped sentinel still
// matches, because the table compares with errors.Is.
func TestFailMapsARegisteredSentinel(t *testing.T) {
	app := fiber.New()
	app.Get("/x", func(c fiber.Ctx) error {
		return Fail(c, fmt.Errorf("session %s: %w", "session-1", errRegistered))
	})

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if answer.StatusCode != fiber.StatusUnauthorized {
		t.Fatalf("the status is %d, want %d", answer.StatusCode, fiber.StatusUnauthorized)
	}

	var envelope struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(answer.Body).Decode(&envelope); err != nil {
		t.Fatalf("the answer is not the envelope: %v", err)
	}
	if envelope.Code != fiber.StatusUnauthorized || envelope.Status != "error" {
		t.Errorf("the envelope is %+v, want a 401 error envelope", envelope)
	}
	if envelope.Error != "unauthenticated" {
		t.Errorf("the slug is %q, want the registered slug", envelope.Error)
	}
	if envelope.Message == "session-1" {
		t.Error("the answer leaks the wrapped text")
	}
}

// TestErrorCarriesASlug covers the default slug. Every error answer carries the
// field, so a client always has one field to branch on.
func TestErrorCarriesASlug(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{fiber.StatusNotFound, "not_found"},
		{fiber.StatusUnauthorized, "unauthenticated"},
		{fiber.StatusInternalServerError, "internal_server_error"},
	} {
		app := fiber.New()
		app.Get("/x", func(c fiber.Ctx) error {
			return Error(c, tc.status, "message", nil)
		})

		answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil))
		if err != nil {
			t.Fatalf("test request: %v", err)
		}

		var envelope struct {
			Error  string `json:"error"`
			Errors any    `json:"errors"`
		}
		if err := json.NewDecoder(answer.Body).Decode(&envelope); err != nil {
			t.Fatalf("the answer is not the envelope: %v", err)
		}
		answer.Body.Close()

		if envelope.Error != tc.want {
			t.Errorf("the slug of %d is %q, want %q", tc.status, envelope.Error, tc.want)
		}
		if envelope.Errors != nil {
			t.Errorf("the %d answer carries errors %v, want the field absent", tc.status, envelope.Errors)
		}
	}
}

// TestFailReturnsAnUnregisteredError covers the fallthrough. The mapper answers
// nothing, so the error reaches ErrorHandler, which writes the 500 envelope.
func TestFailReturnsAnUnregisteredError(t *testing.T) {
	unknown := errors.New("unknown")

	app := fiber.New()
	app.Get("/x", func(c fiber.Ctx) error {
		if err := Fail(c, unknown); !errors.Is(err, unknown) {
			t.Errorf("Fail gave %v, want the error unchanged", err)
		}
		return nil
	})

	if _, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x", nil)); err != nil {
		t.Fatalf("test request: %v", err)
	}
}
