package oidc_test

// This file drives the two caps on second-factor guessing end to end, over HTTP,
// against the same routes the server mounts.
//
// Six digits is a million values, so a challenge that takes codes for ever is a
// challenge an attacker guesses through. Two caps bound it: one ends a sign-in
// after a few wrong codes, and one bounds the person across every sign-in they
// open.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"fmt"
	"testing"

	"github.com/gofiber/fiber/v3"
)

// The two numbers the gateway enforces. They are unexported constants of the
// login session domain and of the TOTP module, so this run spells them again.
//
// codesPerSignIn is how many wrong codes one Login Session takes. codesPerPerson
// is the trailing-window budget of one person, and it is three sign-ins' worth.
const (
	codesPerSignIn = 5
	codesPerPerson = 15
)

// wrongCode is a value the Authenticator of this person never shows. One in a
// million says otherwise, and every other flow test takes the same odds.
const wrongCode = "000000"

// TestSecondFactorGuessingCap proves both caps on one person who holds a Second
// Factor.
//
// The first cap ends a sign-in after codesPerSignIn wrong codes, and the answer
// tells the person to start again. The second cap is what makes ending a sign-in
// worthless: without it, an attacker who already holds the password answers one
// identifier step and one password step, and buys a fresh set of guesses for
// ever. The run spends the whole budget over three sign-ins and then proves that
// a fourth buys nothing.
//
// The steps depend on each other, so they run in order.
func TestSecondFactorGuessingCap(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// The person enrols by choice. Nothing here turns the MFA Requirement on, so
	// the challenges below are the factor the person holds.
	secret, _ := enrolFactor(t, gw, fx)

	signIns := codesPerPerson / codesPerSignIn
	for round := 1; round <= signIns; round++ {
		t.Run(fmt.Sprintf("sign-in %d ends after %d wrong codes", round, codesPerSignIn), func(t *testing.T) {
			token, _ := signInToPassword(t, gw, fx)

			// Every code before the last one is refused as a wrong code, and the
			// sign-in stands. A person who mistypes once keeps their session.
			for guess := 1; guess < codesPerSignIn; guess++ {
				refused := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, wrongCode), token,
					fiber.StatusUnauthorized)
				if refused != "invalid_credentials" {
					t.Fatalf("guess %d answered %q, want %q", guess, refused, "invalid_credentials")
				}
			}

			// The last one ends the sign-in. The answer names that condition, so
			// the login UI tells the person to start again instead of showing a
			// failure it cannot read.
			refused := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, wrongCode), token,
				fiber.StatusUnauthorized)
			if refused != "too_many_codes" {
				t.Fatalf("the last guess answered %q, want %q", refused, "too_many_codes")
			}

			// The session is terminated, so the token credentials nothing more.
			// A cap that left the token alive would end nothing.
			if again := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, wrongCode), token,
				fiber.StatusUnauthorized); again != "unauthenticated" {
				t.Errorf("the ended session answered %q, want %q", again, "unauthenticated")
			}
		})
	}

	t.Run("one refused sign-in is one audit row", func(t *testing.T) {
		// The wrong code is recorded on the failure that ends the sign-in, and
		// not on every attempt. A trail that held five rows per sign-in would
		// drown the reader in the noise of one person mistyping.
		failures := countRows(t, gw, "audit_events",
			"tenant_id = ? AND actor_id = ? AND action = ?", gw.tenantID, fx.userID, "login.failed")
		if failures != signIns {
			t.Errorf("the trail holds %d login.failed rows, want %d", failures, signIns)
		}
	})

	t.Run("a fresh sign-in buys no fresh guesses", func(t *testing.T) {
		// The whole point of the second cap. The sign-in opens, the password is
		// right, and the challenge still refuses: the budget is the one thing a
		// restart cannot reset.
		token, _ := signInToPassword(t, gw, fx)

		refused := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, wrongCode), token,
			fiber.StatusTooManyRequests)
		if refused != "rate_limited" {
			t.Errorf("the guess answered %q, want %q", refused, "rate_limited")
		}

		// The refusal costs the person nothing they can recover by waiting out a
		// session. It is the trailing window that must pass.
		if failures := countRows(t, gw, "audit_events",
			"tenant_id = ? AND actor_id = ? AND action = ?",
			gw.tenantID, fx.userID, "login.failed"); failures != signIns {
			t.Errorf("the refused attempt recorded a %d-th failure", failures)
		}
	})

	t.Run("a right code is refused while the budget is spent", func(t *testing.T) {
		// The budget is spent before the code is read, because a cap that counted
		// only wrong codes could not stop the right guess. This is that rule seen
		// from the outside.
		forgetSpentStep(t, gw, fx)
		atFreshStep(t)

		token, _ := signInToPassword(t, gw, fx)
		refused := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, code(t, secret)),
			token, fiber.StatusTooManyRequests)
		if refused != "rate_limited" {
			t.Errorf("the right code answered %q, want %q", refused, "rate_limited")
		}
	})

	t.Run("the budget is the person's own", func(t *testing.T) {
		// One person's guessing never locks another person out. The key names the
		// tenant and the person, so a shared counter cannot be used to deny
		// service to an account nobody attacked.
		other := seedFixture(t, gw)
		enrolFactor(t, gw, other)

		token, _ := signInToPassword(t, gw, other)
		refused := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, wrongCode), token,
			fiber.StatusUnauthorized)
		if refused != "invalid_credentials" {
			t.Errorf("the other person answered %q, want %q", refused, "invalid_credentials")
		}
	})
}
