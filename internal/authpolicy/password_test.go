package authpolicy

import (
	"errors"
	"testing"
)

// policy builds a resolved view with only the password rules set. Every other
// field of View is irrelevant to CheckPassword.
func policy(minLength, minClasses int, deny ...string) View {
	return View{PwMinLength: minLength, PwMinClasses: minClasses, PwDenyList: deny}
}

// TestCheckPasswordLength covers the minimum length, which is counted in runes.
// Eight accented characters are eight characters to the person who typed them,
// and a byte count would refuse them.
func TestCheckPasswordLength(t *testing.T) {
	cases := []struct {
		name    string
		plain   string
		refused bool
	}{
		{"shorter than the minimum", "short", true},
		{"exactly the minimum", "12345678", false},
		{"longer than the minimum", "123456789", false},
		{"eight multi-byte runes", "áéíóúàèì", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassword(policy(8, 0), tc.plain)
			if got := errors.Is(err, ErrWeakPassword); got != tc.refused {
				t.Errorf("refused = %v, want %v (err %v)", got, tc.refused, err)
			}
		})
	}
}

// TestCheckPasswordClasses covers the class count. The four classes are lower
// case, upper case, digits, and everything else.
func TestCheckPasswordClasses(t *testing.T) {
	cases := []struct {
		name       string
		plain      string
		minClasses int
		refused    bool
	}{
		{"one class where three are required", "aaaaaaaa", 3, true},
		{"two classes where three are required", "aaaaAAAA", 3, true},
		{"three classes where three are required", "aaaaAA11", 3, false},
		{"punctuation is the fourth class", "aaaAA11!", 4, false},
		{"no class rule admits anything long enough", "aaaaaaaa", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassword(policy(8, tc.minClasses), tc.plain)
			if got := errors.Is(err, ErrWeakPassword); got != tc.refused {
				t.Errorf("refused = %v, want %v (err %v)", got, tc.refused, err)
			}
		})
	}
}

// TestCheckPasswordDenyList covers the deny list. A word matches anywhere in the
// password and case does not matter, so a tenant that denies its product name
// refuses every password built around it.
func TestCheckPasswordDenyList(t *testing.T) {
	cases := []struct {
		name    string
		plain   string
		deny    []string
		refused bool
	}{
		{"exact match", "acmeacme", []string{"acme"}, true},
		{"match inside a longer password", "myAcme2024", []string{"acme"}, true},
		{"different case", "ACMEACME", []string{"acme"}, true},
		{"no match", "unrelated1", []string{"acme"}, false},
		{"empty word is ignored", "unrelated1", []string{""}, false},
		{"second word matches", "password1", []string{"acme", "password"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPassword(policy(8, 0, tc.deny...), tc.plain)
			if got := errors.Is(err, ErrWeakPassword); got != tc.refused {
				t.Errorf("refused = %v, want %v (err %v)", got, tc.refused, err)
			}
		})
	}
}

// TestCheckPasswordDefaultsAdmitAWeakPassword records what the shipped defaults
// actually enforce: eight characters and one class. A tenant that wants more
// sets it, and this test fails the day the defaults move.
func TestCheckPasswordDefaultsAdmitAWeakPassword(t *testing.T) {
	view := policy(DefaultPwMinLength, DefaultPwMinClasses)

	if err := CheckPassword(view, "aaaaaaaa"); err != nil {
		t.Errorf("the shipped defaults refused %q: %v", "aaaaaaaa", err)
	}
	if err := CheckPassword(view, "aaaaaaa"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("the shipped defaults admitted a seven-character password: %v", err)
	}
}
