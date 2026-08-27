package middlewares

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/platform/logger"
)

// basicHeader renders one HTTP Basic credential the way a caller presents it.
func basicHeader(clientID, clientSecret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
}

// TestStaticBasic covers the gate on the push callback of the Scan Verifier. The
// endpoint signs a person in when it succeeds, so only the exact credential
// passes.
func TestStaticBasic(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   int
	}{
		{
			name:   "the configured credential passes",
			header: basicHeader("callback_id", "callback_secret"),
			want:   fiber.StatusOK,
		},
		{
			name:   "a wrong secret is refused",
			header: basicHeader("callback_id", "another_secret"),
			want:   fiber.StatusUnauthorized,
		},
		{
			name:   "a wrong client id is refused",
			header: basicHeader("another_id", "callback_secret"),
			want:   fiber.StatusUnauthorized,
		},
		{
			name:   "an absent header is refused",
			header: "",
			want:   fiber.StatusUnauthorized,
		},
		{
			// The comparison is over bytes. A credential that differs only in
			// case is a different credential.
			name:   "a credential that differs only in case is refused",
			header: basicHeader("CALLBACK_ID", "CALLBACK_SECRET"),
			want:   fiber.StatusUnauthorized,
		},
		{
			name:   "another scheme is refused",
			header: "Bearer callback_id:callback_secret",
			want:   fiber.StatusUnauthorized,
		},
		{
			name:   "a header that is not base64 is refused",
			header: "Basic not-base-64-$$$",
			want:   fiber.StatusUnauthorized,
		},
	}

	log, _ := logger.NewObserved()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			app.Post("/callback",
				StaticBasic("callback_id", "callback_secret", log),
				func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

			req := httptest.NewRequest(http.MethodPost, "/callback", nil)
			if tt.header != "" {
				req.Header.Set(fiber.HeaderAuthorization, tt.header)
			}
			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("send the request: %v", err)
			}
			defer resp.Body.Close() //nolint:errcheck

			if resp.StatusCode != tt.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.want)
			}
		})
	}
}

// TestStaticBasicRefusesAnEmptyConfiguration covers the gate a deployment
// configured nothing on. It fails closed, so a route mounted by mistake refuses
// every caller instead of admitting one that presents nothing.
func TestStaticBasicRefusesAnEmptyConfiguration(t *testing.T) {
	log, _ := logger.NewObserved()
	app := fiber.New()
	app.Post("/callback",
		StaticBasic("", "", log),
		func(c fiber.Ctx) error { return c.SendStatus(fiber.StatusOK) })

	for _, header := range []string{"", basicHeader("", "")} {
		req := httptest.NewRequest(http.MethodPost, "/callback", nil)
		if header != "" {
			req.Header.Set(fiber.HeaderAuthorization, header)
		}
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("send the request: %v", err)
		}
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != fiber.StatusUnauthorized {
			t.Errorf("status = %d for header %q, want %d", resp.StatusCode, header, fiber.StatusUnauthorized)
		}
	}
}
