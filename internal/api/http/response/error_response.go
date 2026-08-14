package response

import (
	"github.com/gofiber/fiber/v3"
)

// Error writes the standard JSON error envelope and returns the write error (if
// any) to the caller, which propagates it up Fiber's handler chain. The response
// package owns no logger, so it never logs here — the caller (which does hold the
// structured logger) is responsible for logging a failed write.
func Error(c fiber.Ctx, statusCode int, message string, details any) error {
	if details != nil {
		return c.Status(statusCode).JSON(ErrorDetails{
			Code:    statusCode,
			Status:  "error",
			Message: message,
			Errors:  details,
		})
	}
	return c.Status(statusCode).JSON(Common{
		Code:    statusCode,
		Status:  "error",
		Message: message,
	})
}
