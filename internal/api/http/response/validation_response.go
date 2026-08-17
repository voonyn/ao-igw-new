package response

import (
	"errors"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
)

// Validation writes 422 with one message per rejected field:
//
//	{"code":422,"status":"error","message":"Validation failed",
//	 "error":"unprocessable_entity",
//	 "errors":{"identifier":"identifier is required"}}
//
// If err is not a validator error, it writes 400 with no field detail, because
// the request body itself failed to parse.
func Validation(c fiber.Ctx, err error) error {
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		return Error(c, fiber.StatusBadRequest, "Invalid request body", nil)
	}

	fields := make(map[string]string, len(verrs))
	for _, fe := range verrs {
		fields[fe.Field()] = message(fe)
	}

	return Error(c, fiber.StatusUnprocessableEntity, "Validation failed", fields)
}

func message(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return fe.Field() + " is required"
	case "email":
		return fe.Field() + " must be a valid email address"
	case "min":
		return fe.Field() + " must be at least " + fe.Param() + " characters"
	case "max":
		return fe.Field() + " must be at most " + fe.Param() + " characters"
	case "oneof":
		return fe.Field() + " must be one of: " + fe.Param()
	default:
		return fe.Field() + " failed the " + fe.Tag() + " rule"
	}
}
