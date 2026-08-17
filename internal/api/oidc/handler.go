package oidc

import (
	"context"
	"errors"
	"net/http"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"alphaomega/identitygateway/internal/api/http/middlewares"
	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/platform/logger"
)

// Handler passes one request to the provider of its tenant. The protocol engine
// is a net/http handler, so adaptor bridges it into Fiber with the full request
// path intact.
//
// The tenant middleware runs first and answers a host no tenant owns, so every
// request that arrives here already names a tenant.
func Handler(reg *Registry, log logger.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx := c.Context()
		tc, _ := middlewares.TenantFrom(c)

		log.Debug("serve oidc request",
			logger.String("tenant_id", tc.TenantID),
			logger.String("path", c.Path()),
			RequestID(ctx))

		handler, err := reg.Handler(ctx, tc.TenantID, tc.Config)
		if err != nil {
			status := statusFor(err)
			log.Error("serve oidc request",
				logger.String("tenant_id", tc.TenantID),
				logger.String("path", c.Path()),
				logger.Int("status", status),
				RequestID(ctx),
				logger.Err(err))
			return response.Error(c, status, http.StatusText(status), nil)
		}

		log.Debug("served oidc request",
			logger.String("tenant_id", tc.TenantID),
			logger.String("path", c.Path()),
			RequestID(ctx))
		return adaptor.HTTPHandler(handler)(c)
	}
}

// statusFor turns a build failure into the status the client reads. A tenant
// whose row cannot build a provider exists but cannot serve, which is 503. Any
// other failure is the gateway's own, which is 500.
func statusFor(err error) int {
	switch {
	case errors.Is(err, ErrOpaqueAccessToken), errors.Is(err, ErrNoSignatureAlg):
		return fiber.StatusServiceUnavailable
	default:
		return fiber.StatusInternalServerError
	}
}

// RequestID reads the id the requestid middleware put on the request context,
// so a log line of any layer names the request it belongs to.
func RequestID(ctx context.Context) logger.Field {
	return logger.String("request_id", requestid.FromContext(ctx))
}
