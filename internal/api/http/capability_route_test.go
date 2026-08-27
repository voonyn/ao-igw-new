package http

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/logger"
)

// completeDI is a Digital Identity configuration that starts: an address, one
// outbound pair, and one callback pair.
func completeDI() config.DIConfig {
	return config.DIConfig{
		Enabled:              true,
		BaseURL:              "https://verifier.example",
		ClientID:             "spass_iam",
		ClientSecret:         "s3cr3t",
		CallbackClientID:     "callback_id",
		CallbackClientSecret: "callback_secret",
	}
}

// TestCapabilityEndpointAnswersTheSwitch pins the one answer both front ends
// read. The capability names the integration and not one flow.
func TestCapabilityEndpointAnswersTheSwitch(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.DIConfig
		want bool
	}{
		{
			name: "a complete configuration is on",
			cfg:  completeDI(),
			want: true,
		},
		{
			name: "the switch off is off",
			cfg:  config.DIConfig{},
			want: false,
		},
		{
			name: "an incomplete configuration is off",
			cfg:  config.DIConfig{Enabled: true, BaseURL: "https://verifier.example"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			mountCapabilities(app, digitalIdentityOn(tt.cfg, logger.New()))

			resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, capabilitiesPath, nil))
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close() //nolint:errcheck
			if resp.StatusCode != fiber.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			var out struct {
				Data struct {
					DigitalIdentity bool `json:"digitalIdentity"`
				} `json:"data"`
			}
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
			if out.Data.DigitalIdentity != tt.want {
				t.Errorf("digitalIdentity = %v, want %v", out.Data.DigitalIdentity, tt.want)
			}
		})
	}
}

// TestDigitalIdentityRefusesAndLogsTheReason pins the two refusals an operator
// must be able to read from the log: a credential pair set on one half only, and
// absent callback credentials.
func TestDigitalIdentityRefusesAndLogsTheReason(t *testing.T) {
	tests := []struct {
		name string
		cfg  func() config.DIConfig
	}{
		{
			name: "an outbound pair set on one half only",
			cfg: func() config.DIConfig {
				c := completeDI()
				c.ClientSecret = ""
				return c
			},
		},
		{
			name: "a callback pair set on one half only",
			cfg: func() config.DIConfig {
				c := completeDI()
				c.CallbackClientSecret = ""
				return c
			},
		},
		{
			name: "absent callback credentials",
			cfg: func() config.DIConfig {
				c := completeDI()
				c.CallbackClientID, c.CallbackClientSecret = "", ""
				return c
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, logs := logger.NewObserved()
			if digitalIdentityOn(tt.cfg(), log) {
				t.Fatal("the integration started on an incomplete configuration")
			}
			if logs.Len() == 0 {
				t.Fatal("the refusal was not logged")
			}
			// The reason reaches the operator, and no credential reaches the line.
			for _, entry := range logs.All() {
				line := entry.Message + fieldText(entry.Context)
				if !strings.Contains(line, "di.") {
					t.Errorf("the log line names no reason: %s", line)
				}
				if strings.Contains(line, "s3cr3t") || strings.Contains(line, "callback_secret") {
					t.Errorf("a credential reached the log line: %s", line)
				}
			}
		})
	}
}

// fieldText renders the fields of one log entry as text, so a test reads what an
// operator reads.
func fieldText(fields []logger.Field) string {
	out := ""
	for _, f := range fields {
		out += f.String
		if err, ok := f.Interface.(error); ok {
			out += err.Error()
		}
	}
	return out
}
