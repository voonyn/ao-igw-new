package config

import (
	"crypto/tls"
	"time"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v3"
	"github.com/spf13/viper"

	"alphaomega/identitygateway/internal/api/http/response"
)

// Connection timeouts guard the internet-facing server against slow-client
// (slowloris) resource exhaustion on the public OIDC endpoints. They are
// generous enough for normal OIDC redirects/token exchanges but bounded so a
// client cannot hold a connection open indefinitely.
const (
	serverReadTimeout  = 15 * time.Second
	serverWriteTimeout = 30 * time.Second
	serverIdleTimeout  = 90 * time.Second
)

// FiberConfig builds the Fiber config. trustedProxies, appName, and serverHeader
// are threaded in from the typed config rather than read via viper here: viper's
// key normalization ("Server.TrustedProxies" → "server.trustedproxies",
// "Server.HeaderName" → "server.headername") does not match the snake_case config
// keys, so a viper read would silently yield an empty allow-list and an unset
// ServerHeader/AppName.
func FiberConfig(trustedProxies []string, appName, serverHeader string) fiber.Config {
	return fiber.Config{
		AppName:       appName,
		ServerHeader:  serverHeader,
		JSONEncoder:   sonic.Marshal,
		JSONDecoder:   sonic.Unmarshal,
		CaseSensitive: true,

		// Every c.Bind().Body(&req) validates the `validate:` tags here.
		StructValidator: newStructValidator(),

		// The last stop for an error no handler mapped. Without it, Fiber
		// writes the raw wrapped text as the body and the response envelope
		// escapes on every unhandled path.
		ErrorHandler: response.ErrorHandler,

		// Copy the request locals into the request context, so the request id
		// reaches a layer that holds only a context.Context. A repository never
		// sees fiber.Ctx, and every layer logs the request id.
		PassLocalsToContext: true,

		ReadTimeout:  serverReadTimeout,
		WriteTimeout: serverWriteTimeout,
		IdleTimeout:  serverIdleTimeout,

		// Trust the reverse proxy ONLY for the configured CIDRs. This makes
		// c.Hostname() (tenant resolution) honor X-Forwarded-Host and c.IP()
		// (rate-limit key + session audit IP) honor X-Forwarded-For, but *only*
		// when the immediate peer is a trusted proxy — a direct client cannot
		// spoof either. A `0.0.0.0/0` value trusts everyone, which is the same
		// as trusting no one: it lets any client forge these headers.
		TrustProxy:  true,
		ProxyHeader: fiber.HeaderXForwardedFor,
		TrustProxyConfig: fiber.TrustProxyConfig{
			Proxies: trustedProxies,
		},
	}
}

func FiberListenConfig() fiber.ListenConfig {
	return fiber.ListenConfig{
		EnablePrefork: viper.GetBool("Server.Prefork"),
		TLSConfigFunc: func(cfg *tls.Config) {
			cfg.MinVersion = tls.VersionTLS12
		},
		EnablePrintRoutes: true,
	}
}
