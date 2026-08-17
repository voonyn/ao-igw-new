package tenant

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestAddDomainBodyRules covers the tags on the one body this domain binds. The
// backend is the enforcement point, so the rule is proved here and not in the
// console.
//
// A bare host and a host with a port are both valid, and a URL is not: the
// lookup that resolves a request to its tenant compares a host, so a stored
// scheme or path would never match anything.
func TestAddDomainBodyRules(t *testing.T) {
	v := validator.New(validator.WithRequiredStructEnabled())

	cases := []struct {
		domain string
		valid  bool
	}{
		{"auth.acme.com", true},
		{"localhost:8080", true},
		{"", false},
		{"https://auth.acme.com", false},
		{"auth.acme.com/login", false},
		{"not a host", false},
	}

	for _, c := range cases {
		err := v.Struct(AddDomainBody{Domain: c.domain})
		if c.valid && err != nil {
			t.Errorf("%q reads %v, want a valid host", c.domain, err)
		}
		if !c.valid && err == nil {
			t.Errorf("%q is accepted, want a refusal", c.domain)
		}
	}
}
