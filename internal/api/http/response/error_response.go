package response

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v3"
)

// Error writes the standard JSON error envelope and returns the write error (if
// any) to the caller, which propagates it up Fiber's handler chain. The response
// package owns no logger, so it never logs here — the caller (which does hold the
// structured logger) is responsible for logging a failed write.
//
// The slug is derived from the status. A caller that answers a condition of its
// own names the slug itself with ErrorSlug.
func Error(c fiber.Ctx, statusCode int, message string, details any) error {
	return c.Status(statusCode).JSON(Failure{
		Code:    statusCode,
		Status:  "error",
		Message: message,
		Error:   slugFor(statusCode),
		Errors:  details,
	})
}

// ErrorSlug writes the error envelope with a machine-readable slug in `error`.
// The message is for a person, and the slug is what a client branches on, so a
// reworded message never changes behaviour.
func ErrorSlug(c fiber.Ctx, statusCode int, slug, message string) error {
	return c.Status(statusCode).JSON(Failure{
		Code:    statusCode,
		Status:  "error",
		Message: message,
		Error:   slug,
	})
}

// slugFor names the default slug of a status, for an answer that carries no
// slug of its own. Every error answer carries a slug, so a client always has
// one field to branch on.
//
// 401 is the exception: its status text is "Unauthorized", but the gateway
// answers "unauthenticated", the slug the bearer guard already writes.
func slugFor(statusCode int) string {
	if statusCode == fiber.StatusUnauthorized {
		return "unauthenticated"
	}
	return strings.ReplaceAll(strings.ToLower(http.StatusText(statusCode)), " ", "_")
}
