package oidc

import (
	"context"
	"errors"

	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/platform/logger"
)

// unknownErrorCode stands in when a failure carries no protocol error code. The
// engine wraps most failures as a protocol error, so this marks the rest.
const unknownErrorCode = "unknown"

// ErrorLogger logs a protocol failure once, where the engine stops it.
//
// The line carries the error code and nothing the engine wrote. A description
// the engine builds can quote the value that failed, and that value is
// sometimes an authorization code or a token, so the description never reaches
// a log line. The code, the tenant, and the request id are enough to find the
// failure.
func ErrorLogger(tenantID string, log logger.Logger) goidc.HandleErrorFunc {
	return func(ctx context.Context, err error) {
		log.Error("oidc request failed",
			logger.String("tenant_id", tenantID),
			logger.String("error_code", errorCode(err)),
			RequestID(ctx))
	}
}

// errorCode reads the protocol error code of a failure.
func errorCode(err error) string {
	var oidcErr goidc.Error
	if errors.As(err, &oidcErr) && oidcErr.Code != "" {
		return string(oidcErr.Code)
	}
	return unknownErrorCode
}
