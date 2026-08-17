package oidc

import (
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestScopeBodyRules covers the tags on the scope body. The backend is the
// enforcement point, so the rules are proved here and not in the console.
//
// The name is the scope string a client asks for. An OAuth scope is a
// space-delimited token of printable ASCII, so a name carrying a space, a quote,
// or a backslash could not be requested at all.
func TestScopeBodyRules(t *testing.T) {
	v := validator.New(validator.WithRequiredStructEnabled())

	body := func(name string) ScopeBody {
		return ScopeBody{Name: name, IsEnabled: true}
	}

	cases := []struct {
		name  string
		body  ScopeBody
		valid bool
	}{
		{"a plain name", body("groups"), true},
		{"a namespaced name", body("urn:acme:groups"), true},
		{"no name at all", body(""), false},
		{"two names with a space", body("groups roles"), false},
		{"a quoted name", body(`say"what`), false},
		{"an escaped name", body(`back\slash`), false},
		{"a name outside ASCII", body("gruppé"), false},
		{"a name past the column", body(strings.Repeat("a", 192)), false},
		{"words past the column", ScopeBody{
			Name: "groups", DisplayName: strings.Repeat("a", 256),
		}, false},
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
