package oidc

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestProviderConfigBodyRules covers the tags on the provider body. The backend
// is the enforcement point, so the rules are proved here and not in the console.
//
// A lifetime of zero is refused. Nothing downstream reads it as "off": the
// engine falls back to its own default, so a form that stored it would report a
// setting the tenant does not have.
func TestProviderConfigBodyRules(t *testing.T) {
	v := validator.New(validator.WithRequiredStructEnabled())

	lifetime := func(secs int) ProviderConfigBody {
		return ProviderConfigBody{AccessTokenLifetime: &secs}
	}
	format := func(name string) ProviderConfigBody {
		return ProviderConfigBody{AccessTokenType: &name}
	}

	cases := []struct {
		name  string
		body  ProviderConfigBody
		valid bool
	}{
		{"an empty body changes nothing", ProviderConfigBody{}, true},
		{"one second", lifetime(1), true},
		{"one year", lifetime(31536000), true},
		{"zero", lifetime(0), false},
		{"more than one year", lifetime(31536001), false},
		{"the JWT format", format(AccessTokenNameJWT), true},
		{"the opaque format", format(AccessTokenNameOpaque), true},
		{"a format nobody serves", format("PASETO"), false},
	}

	for _, c := range cases {
		err := v.Struct(c.body)
		if c.valid && err != nil {
			t.Errorf("%s reads %v, want a valid body", c.name, err)
		}
		if !c.valid && err == nil {
			t.Errorf("%s is accepted, want a refusal", c.name)
		}
	}
}
