package middlewares

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"alphaomega/identitygateway/internal/platform/logger"
)

// RequestLog writes one info line per request, after the answer is decided.
//
// The line is the entry point of every investigation: it names the request id
// the deeper debug lines carry, so one id ties the whole request together.
// Mount it directly after requestid.New(), so the id exists by then.
//
// The tenant is read after the handler ran, because the tenant middleware
// resolves it further down the chain.
//
// The line carries no credential: no password, no token, no secret, and no
// authorization code. The query string is left out for the same reason.
func RequestLog(log logger.Logger) fiber.Handler {
	return func(c fiber.Ctx) error {
		started := time.Now()

		err := c.Next()

		fields := []logger.Field{
			logger.String("method", c.Method()),
			logger.String("path", c.Path()),
			logger.Int("status", statusOf(c, err)),
			logger.Duration("duration", time.Since(started)),
			logger.String("request_id", requestid.FromContext(c)),
			logger.String("ip", c.IP()),
		}
		if tc, ok := TenantFrom(c); ok {
			fields = append(fields, logger.String("tenant_id", tc.TenantID))
		}
		log.Info("request", fields...)

		return err
	}
}

// statusOf reports the status the client reads. A handler that returned an
// error has not written its answer yet, so the status of the response is still
// the default one. The error handler answers such a request, and it reads the
// same two values this does.
func statusOf(c fiber.Ctx, err error) int {
	if err == nil {
		return c.Response().StatusCode()
	}

	var fe *fiber.Error
	if errors.As(err, &fe) {
		return fe.Code
	}
	return fiber.StatusInternalServerError
}
