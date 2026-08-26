package logger

import (
	"context"

	"github.com/gofiber/fiber/v3/middleware/requestid"
)

// RequestID reads the id the requestid middleware put on the request context
// and returns it as a log field, so a line of any layer names the request it
// belongs to. The helper lives here because every layer already imports this
// package, and a domain cannot import internal/api/http/middlewares: the tenant
// middleware imports internal/oidc, so the import would close a cycle.
//
// A context that carries no id, such as a background job, yields an empty
// value.
func RequestID(ctx context.Context) Field {
	return String("request_id", requestid.FromContext(ctx))
}
