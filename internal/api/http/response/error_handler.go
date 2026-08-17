package response

import (
	"errors"

	"github.com/gofiber/fiber/v3"
)

// ErrorHandler is Fiber's last stop. A handler that returns an error it did not
// map itself lands here, and the answer is still the standard envelope.
//
// The wrapped text never reaches the body, because it names internal ids. A
// *fiber.Error keeps its own status and its own message, which the framework
// wrote: that is how 404 and 405 answer their own code instead of 500.
//
// The response package owns no logger, so it never logs here. The layer where
// the error stopped bubbling already logged it.
func ErrorHandler(c fiber.Ctx, err error) error {
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return Error(c, fiberErr.Code, fiberErr.Message, nil)
	}
	return Error(c, fiber.StatusInternalServerError, "Internal Server Error", nil)
}
