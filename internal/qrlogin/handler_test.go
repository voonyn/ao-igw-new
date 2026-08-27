package qrlogin

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/platform/config"
)

// callbackTestPath is where the test mounts the push. The real address is
// configured, and this test asks what the route answers, not where it sits.
const callbackTestPath = "/di/callback"

// callbackApp mounts the push callback on the real Fiber configuration, so the
// bind and the validate tags run exactly as they do in the gateway.
func callbackApp(t *testing.T) *fiber.App {
	t.Helper()

	svc, _ := testService(t)
	app := fiber.New(config.FiberConfig(nil, "qrlogin-test", ""))
	CallbackRoute(app, callbackTestPath, func(c fiber.Ctx) error { return c.Next() }, NewHandler(svc))
	return app
}

// postCallback sends one body at the push callback and reads the status and the
// slug back.
func postCallback(t *testing.T, app *fiber.App, body string) (int, string) {
	t.Helper()

	req := httptest.NewRequest(fiber.MethodPost, callbackTestPath, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return resp.StatusCode, out.Error
}

// TestCallbackAnswersOneRefusal pins what the push callback discloses. The body
// is a third party's, so it is validated here, and every refusal reads alike.
//
// A tolerated body answers 200 whether it matched a transaction or not. Only a
// body the gateway cannot use at all is refused, and the refusal names no field.
func TestCallbackAnswersOneRefusal(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantSlug   string
	}{
		{
			name:       "a push that names a transaction",
			body:       `{"stateWord":"0","presentationId":"presentation-1","DecodedVpToken":{"Username":"person@example.com"}}`,
			wantStatus: fiber.StatusOK,
		},
		{
			name:       "a body that is not JSON",
			body:       "not json",
			wantStatus: fiber.StatusBadRequest,
			wantSlug:   "invalid_request",
		},
		{
			name:       "a body that names no transaction",
			body:       `{"message":"success"}`,
			wantStatus: fiber.StatusBadRequest,
			wantSlug:   "invalid_request",
		},
		{
			// The Scan Verifier mints the identifier and the column holds 64
			// characters. A longer one names no row that can exist, and it is
			// refused before it reaches the database or the log.
			name:       "an identifier longer than the column",
			body:       `{"presentationId":"` + strings.Repeat("a", 65) + `"}`,
			wantStatus: fiber.StatusBadRequest,
			wantSlug:   "invalid_request",
		},
		{
			name:       "a presented name longer than the column",
			body:       `{"presentationId":"presentation-1","DecodedVpToken":{"Username":"` + strings.Repeat("a", 256) + `"}}`,
			wantStatus: fiber.StatusBadRequest,
			wantSlug:   "invalid_request",
		},
	}

	app := callbackApp(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, slug := postCallback(t, app, tt.body)
			if status != tt.wantStatus {
				t.Errorf("status = %d, want %d", status, tt.wantStatus)
			}
			if slug != tt.wantSlug {
				t.Errorf("slug = %q, want %q", slug, tt.wantSlug)
			}
		})
	}
}
