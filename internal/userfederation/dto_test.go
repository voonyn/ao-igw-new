package userfederation

import (
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestBodyRules covers the tags on the federation body. The backend is the
// enforcement point, so the rules are proved here and not in the console.
//
// The plaintext confirmation is the one that matters most: mode 1 puts the
// password of every person on the wire in clear, so it is refused unless the
// request ticks the box.
func TestBodyRules(t *testing.T) {
	v := validator.New(validator.WithRequiredStructEnabled())

	with := func(edit func(*Body)) Body {
		b := body()
		edit(&b)
		return b
	}

	cases := []struct {
		name  string
		body  Body
		valid bool
	}{
		{"an LDAPS federation of one organization", body(), true},
		{"a plain bind without the confirmation", with(func(b *Body) {
			b.Mode, b.Servers = ModePlain, []string{"ldap://dc1.corp.example:389"}
		}), false},
		{"a plain bind the request confirms", with(func(b *Body) {
			b.Mode, b.Servers = ModePlain, []string{"ldap://dc1.corp.example:389"}
			b.ConfirmPlaintext = true
		}), true},
		{"a StartTLS bind needs no confirmation", with(func(b *Body) {
			b.Mode, b.Servers = ModeStartTLS, []string{"ldap://dc1.corp.example:389"}
		}), true},
		{"a transport nobody dials", with(func(b *Body) { b.Mode = 4 }), false},

		{"the tenant level with a default organization", with(func(b *Body) {
			b.OrgID, b.DefaultOrgID = "", testOrgID
		}), true},
		{"the tenant level with nowhere to create people", with(func(b *Body) {
			b.OrgID, b.DefaultOrgID = "", ""
		}), false},

		{"an absent bind password", with(func(b *Body) { b.BindPassword = nil }), true},
		{"an empty bind password clears the stored one", with(func(b *Body) {
			b.BindPassword = ptr("")
		}), true},

		{"no name", with(func(b *Body) { b.Name = "" }), false},
		{"no state", with(func(b *Body) { b.State = 0 }), false},
		{"a state nobody holds", with(func(b *Body) { b.State = 3 }), false},
		{"no server", with(func(b *Body) { b.Servers = nil }), false},
		{"a server that is not a URL", with(func(b *Body) { b.Servers = []string{"dc1.corp.example"} }), false},
		{"no bind account", with(func(b *Body) { b.BindDN = "" }), false},
		{"no search base", with(func(b *Body) { b.BaseDN = "" }), false},
		{"no object class", with(func(b *Body) { b.UserObjectClasses = nil }), false},
		{"no stable identifier to map", with(func(b *Body) { b.AttrID = "" }), false},
		{"no username to key the person", with(func(b *Body) { b.AttrUsername = "" }), false},
		{"a directory that publishes no mail attribute", with(func(b *Body) { b.AttrEmail = "" }), true},
		{"a timeout past a minute", with(func(b *Body) { b.TimeoutSeconds = 61 }), false},
		{"no claimed domain", with(func(b *Body) { b.Domains = nil }), true},
		{"a domain that is not a host", with(func(b *Body) { b.Domains = []string{"not a host"} }), false},
	}

	for _, c := range cases {
		err := v.Struct(c.body)
		if c.valid && err != nil {
			t.Errorf("%s reads %v, want a valid body", c.name, err)
		}
		if !c.valid && err == nil {
			t.Errorf("%s reads valid, want a refusal", c.name)
		}
	}
}
