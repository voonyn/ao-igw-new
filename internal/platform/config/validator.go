package config

import (
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
)

// structValidator adapts go-playground/validator to Fiber's StructValidator hook,
// so `c.Bind().Body(&req)` validates the `validate:` tags automatically and no
// handler has to call the validator by hand.
type structValidator struct {
	validate *validator.Validate
}

func newStructValidator() *structValidator {
	v := validator.New(validator.WithRequiredStructEnabled())

	// Report the JSON field name ("authRequest"), not the Go field name
	// ("AuthRequest"), so API error messages match the request body.
	v.RegisterTagNameFunc(func(f reflect.StructField) string {
		name := strings.SplitN(f.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})

	return &structValidator{validate: v}
}

func (sv *structValidator) Validate(out any) error {
	return sv.validate.Struct(out)
}
