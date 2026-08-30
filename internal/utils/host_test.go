package utils

import "testing"

// TestRegistrableDomain covers the answer a caller branches on: the part
// somebody buys, the multi-part public suffix, and the hosts that have no
// registrable domain at all.
func TestRegistrableDomain(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"acme.com", "acme.com"},
		{"auth.acme.com", "acme.com"},
		{"a.b.c.acme.com", "acme.com"},
		{"  Auth.ACME.com  ", "acme.com"},
		{"auth.acme.com:8443", "acme.com"},

		// co.uk is one public suffix, so the registrable domain keeps three
		// labels. A naive last-two-labels rule answers co.uk here and lets two
		// unrelated tenants look like one.
		{"auth.acme.co.uk", "acme.co.uk"},
		{"acme.co.uk", "acme.co.uk"},
		{"login.shop.acme.co.uk", "acme.co.uk"},

		// No registrable domain. A caller reads the empty answer as "cannot
		// tell" and skips the check.
		{"localhost", ""},
		{"localhost:3000", ""},
		{"127.0.0.1", ""},
		{"[::1]:3000", ""},
		{"co.uk", ""},
		{"com", ""},
		{"", ""},
	}

	for _, c := range cases {
		if got := RegistrableDomain(c.host); got != c.want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}
