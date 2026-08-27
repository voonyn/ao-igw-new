package http

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/logger"
)

// TestQRLoginMountsOnlyWithAScanVerifier pins the switch. With the integration
// off, none of the three routes exist, so the sign-in front end offers no dead
// option and the push callback cannot be reached at all.
func TestQRLoginMountsOnlyWithAScanVerifier(t *testing.T) {
	paths := []string{qrLoginPrefix + "/start", qrLoginPrefix + "/poll", qrCallbackPath}

	tests := []struct {
		name string
		cfg  config.DIConfig
		want bool
	}{
		{name: "a complete configuration mounts the routes", cfg: completeDI(), want: true},
		{name: "the switch off mounts nothing", cfg: config.DIConfig{}, want: false},
		{
			name: "an incomplete configuration mounts nothing",
			cfg:  config.DIConfig{Enabled: true, BaseURL: "https://verifier.example"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, _ := logger.NewObserved()
			app := fiber.New()
			loginGroup := app.Group(loginPrefix, passThrough)

			// The service and the client are never called here. The test asks what
			// was mounted, and nothing else.
			if digitalIdentityOn(tt.cfg, log) {
				mountQRLogin(app, loginGroup, tt.cfg, nil, nil, nil, nil, log)
			}
			app.Use(NotFoundHandler)

			mounted := map[string]bool{}
			for _, route := range app.GetRoutes() {
				if route.Method == fiber.MethodPost {
					mounted[route.Path] = true
				}
			}
			for _, path := range paths {
				if mounted[path] != tt.want {
					t.Errorf("%s mounted = %v, want %v", path, mounted[path], tt.want)
				}
			}

			// With the integration off, the push callback answers 404 and not 401.
			// A refusal would say that the endpoint is there.
			if !tt.want {
				resp, err := app.Test(httptest.NewRequest(fiber.MethodPost, qrCallbackPath, nil))
				if err != nil {
					t.Fatalf("request: %v", err)
				}
				defer resp.Body.Close() //nolint:errcheck
				if resp.StatusCode != fiber.StatusNotFound {
					t.Errorf("status = %d, want 404", resp.StatusCode)
				}
			}
		})
	}
}

// passThrough stands in for the tenant middleware. This test asks which routes
// were mounted, never what they answer.
func passThrough(c fiber.Ctx) error { return c.Next() }
