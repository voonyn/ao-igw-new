package oidc_test

// This file drives what the ID token publishes about a sign-in, end to end, over
// HTTP, against the same routes the server mounts.
//
// A relying party reads three claims to learn how the person authenticated: amr
// names the factors, acr names the assurance level, and auth_time is the moment
// the person last proved a factor. See docs/adr/0010.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go
// and of mfa_challenge_flow_test.go, so it skips on the same environment
// variable and it creates its own person and its own client.

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/session"
)

// TestIDTokenPublishesHowThePersonAuthenticated walks one person to tokens
// twice: once with a password alone, and once with a password and a code from
// the Authenticator. The claims of each ID token say which of the two happened.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestIDTokenPublishesHowThePersonAuthenticated(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// The prefix is a deployment setting, so the two levels are built from what
	// the gateway is running with and never from a constant in the test.
	oneFactor := gw.cfg.OIDC.ACRPrefix + ":1fa"
	twoFactor := gw.cfg.OIDC.ACRPrefix + ":2fa"

	t.Run("discovery advertises both assurance levels", func(t *testing.T) {
		var doc discovery
		decode(t, gw.do(t, fiber.MethodGet, "/.well-known/openid-configuration", nil),
			fiber.StatusOK, &doc)

		for _, want := range []string{oneFactor, twoFactor} {
			if !slices.Contains(doc.ACRValuesSupported, want) {
				t.Errorf("acr_values_supported is %v, want %q in it", doc.ACRValuesSupported, want)
			}
		}
	})

	// The moment the run started, in whole seconds. Every auth_time below is
	// stamped after it.
	started := time.Now().Unix()

	var passwordOnly int64
	t.Run("a password sign-in reports one factor, whatever the client asked for", func(t *testing.T) {
		// The request asks for the higher level. Asking is voluntary here: it
		// raises no bar, it routes the person through no extra step, and the
		// claim below reports the one factor they actually proved. A client that
		// needs two reads the claim back and decides for itself.
		auth := gw.startAuthorization(t, fx.confidential, "acr_values", twoFactor)
		token, _ := signInToPassword(t, gw, fx)

		claims := jwtClaims(t, gw.finish(t, fx.confidential, auth, token).IDToken)
		assertAMR(t, claims, session.FactorPassword)
		assertACR(t, claims, oneFactor)

		passwordOnly = assertAuthTime(t, claims, started)
	})

	t.Run("a second factor reports both factors and the higher level", func(t *testing.T) {
		secret, _ := enrolFactor(t, gw, fx)

		// The activation spent the time step it was proved with, so the account
		// is put back to a step it has not spent.
		forgetSpentStep(t, gw, fx)

		auth := gw.startAuthorization(t, fx.confidential)
		token, _ := signInToPassword(t, gw, fx)

		atFreshStep(t)
		var challenged struct {
			SessionToken string `json:"sessionToken"`
		}
		gw.login(t, verifyPath, fmt.Sprintf(`{"code":%q}`, code(t, secret)), token, &challenged)
		if challenged.SessionToken == "" {
			t.Fatal("the challenge answered no session token")
		}

		claims := jwtClaims(t, gw.finish(t, fx.confidential, auth, challenged.SessionToken).IDToken)

		// The names are sorted, and mfa follows them. It says that the person
		// proved two factors, and acr says the same thing without the names.
		assertAMR(t, claims, session.FactorOTP, session.FactorPassword, "mfa")
		assertACR(t, claims, twoFactor)

		// The code was proved after the password, so this sign-in is the later
		// of the two.
		if at := assertAuthTime(t, claims, started); at < passwordOnly {
			t.Errorf("auth_time is %d, want %d or later", at, passwordOnly)
		}
	})
}

// assertAMR reads the amr claim and compares it with the factors the sign-in
// proved. JSON gives an array of any, so each name is read back as a string.
func assertAMR(t *testing.T, claims map[string]any, want ...string) {
	t.Helper()

	held, ok := claims["amr"].([]any)
	if !ok {
		t.Fatalf("amr is %v, want an array", claims["amr"])
	}

	got := make([]string, 0, len(held))
	for _, name := range held {
		text, ok := name.(string)
		if !ok {
			t.Fatalf("amr holds %v, want names", held)
		}
		got = append(got, text)
	}
	if !slices.Equal(got, want) {
		t.Errorf("amr is %v, want %v", got, want)
	}
}

// assertACR reads the acr claim and compares it with the assurance level the
// sign-in reached.
func assertACR(t *testing.T, claims map[string]any, want string) {
	t.Helper()

	if got, _ := claims["acr"].(string); got != want {
		t.Errorf("acr is %q, want %q", got, want)
	}
}

// assertAuthTime reads the auth_time claim and answers it in whole seconds. JSON
// gives a number, so it is read back as a float and rounded down.
func assertAuthTime(t *testing.T, claims map[string]any, notBefore int64) int64 {
	t.Helper()

	secs, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time is %v, want a number", claims["auth_time"])
	}
	at := int64(secs)
	if at < notBefore {
		t.Errorf("auth_time is %d, want %d or later", at, notBefore)
	}
	return at
}
