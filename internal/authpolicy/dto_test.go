package authpolicy

import (
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestBodyRules covers the tags on the policy body. The backend is the
// enforcement point, so the rules are proved here and not in the console.
//
// An absent field is valid at every knob, because absent means "inherit". A
// present field is bounded, and zero is inside the bounds of the knobs that
// switch a rule off.
func TestBodyRules(t *testing.T) {
	v := validator.New(validator.WithRequiredStructEnabled())

	cases := []struct {
		name  string
		body  Body
		valid bool
	}{
		{"an empty body", Body{}, true},
		{"lockout switched off", Body{LockoutThreshold: ptr(0)}, true},
		{"a negative threshold", Body{LockoutThreshold: ptr(-1)}, false},
		{"a threshold past the ceiling", Body{LockoutThreshold: ptr(1001)}, false},
		{"a window of a month", Body{LockoutWindowSeconds: ptr(2592000)}, true},
		{"a window past a month", Body{LockoutWindowSeconds: ptr(2592001)}, false},
		{"a password longer than bcrypt reads", Body{PwMinLength: ptr(73)}, false},
		{"every character class", Body{PwMinClasses: ptr(4)}, true},
		{"more classes than exist", Body{PwMinClasses: ptr(5)}, false},
		{"a reset link of a minute", Body{RecoveryResetTtlSeconds: ptr(60)}, true},
		{"a reset link too short to use", Body{RecoveryResetTtlSeconds: ptr(59)}, false},
		{"an empty deny list", Body{PwDenyList: []string{}}, true},
		{"a denied word", Body{PwDenyList: []string{"password"}}, true},
		{"a denied word past the column", Body{
			PwDenyList: []string{strings.Repeat("a", 192)},
		}, false},
		{"the two switches", Body{PwCheckBreach: ptr(true), MfaRequired: ptr(false)}, true},
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
