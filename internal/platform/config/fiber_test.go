package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// TestFiberConfigWrapsAnUnhandledError pins the last envelope. A handler that
// returns an error it did not map itself still answers the standard envelope,
// and the answer never carries the wrapped text, which names internal ids.
func TestFiberConfigWrapsAnUnhandledError(t *testing.T) {
	app := fiber.New(FiberConfig(nil, "test", "test"))
	app.Get("/boom", func(fiber.Ctx) error {
		return fmt.Errorf("login session %s of tenant %s: sealed", "session-1", "tenant-1")
	})

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/boom", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if answer.StatusCode != fiber.StatusInternalServerError {
		t.Errorf("the status is %d, want %d", answer.StatusCode, fiber.StatusInternalServerError)
	}

	body, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if strings.Contains(string(body), "session-1") || strings.Contains(string(body), "tenant-1") {
		t.Errorf("the answer leaks the wrapped text: %s", body)
	}

	var envelope struct {
		Code    int    `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("the answer is not the envelope: %s", body)
	}
	if envelope.Code != fiber.StatusInternalServerError || envelope.Status != "error" || envelope.Message == "" {
		t.Errorf("the envelope is %+v, want a 500 error envelope", envelope)
	}
}

// TestFiberConfigKeepsAFiberErrorStatus pins the routing errors. Fiber raises
// 404 as a *fiber.Error, and the envelope must carry that status, not 500.
func TestFiberConfigKeepsAFiberErrorStatus(t *testing.T) {
	app := fiber.New(FiberConfig(nil, "test", "test"))

	answer, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/nowhere", nil))
	if err != nil {
		t.Fatalf("test request: %v", err)
	}
	defer answer.Body.Close()

	if answer.StatusCode != fiber.StatusNotFound {
		t.Errorf("the status is %d, want %d", answer.StatusCode, fiber.StatusNotFound)
	}

	var envelope struct {
		Code   int    `json:"code"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(answer.Body).Decode(&envelope); err != nil {
		t.Fatalf("the answer is not the envelope: %v", err)
	}
	if envelope.Code != fiber.StatusNotFound || envelope.Status != "error" {
		t.Errorf("the envelope is %+v, want a 404 error envelope", envelope)
	}
}
