package oidc_test

// This file proves the second-factor cases no single slice owns. Every case
// drives the mounted routes over HTTP, the way the earlier slices do.
//
// Three cases live here. Every sign-in second-factor address refuses a Login
// Session that proved no password. An organization override of the MFA
// Requirement decides the sign-in while the tenant default says the opposite. A
// person who holds a passkey and no TOTP Enrolment is sent to the passkey
// challenge and never to a TOTP one.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/utils"
)

// TestSecondFactorStepsRefuseASessionWithoutAPassword drives every sign-in
// second-factor address on a Login Session that answered the identifier step and
// nothing more.
//
// This is the account takeover guard. The session names the person from the
// identifier step onward. An address that read the person off the session
// without asking for the password would let anybody who knows an email address
// enrol a factor on that account, or answer the challenge of one.
//
// The person holds an active factor for this run, so no address below can refuse
// for want of an enrolment. The missing password is the only reason left, and the
// slug names it.
func TestSecondFactorStepsRefuseASessionWithoutAPassword(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)

	enrolFactor(t, gw, fx)
	forgetSpentStep(t, gw, fx)

	var opened struct {
		SessionToken string `json:"sessionToken"`
	}
	gw.login(t, "/identifier", fmt.Sprintf(`{"identifier":%q}`, fx.email), "", &opened)
	if opened.SessionToken == "" {
		t.Fatal("the identifier step answered no session token")
	}

	// The body of each request is what a person sends at that address. A wrong
	// code reaches no verification here, because the session is refused first.
	for _, step := range []struct {
		name string
		path string
		body string
	}{
		{"the enrolment start", enrolStartPath, "{}"},
		{"the enrolment activation", enrolActivatePath, `{"code":"000000"}`},
		{"the challenge", verifyPath, `{"code":"000000"}`},
	} {
		t.Run(step.name, func(t *testing.T) {
			refused := gw.refuse(t, step.path, step.body, opened.SessionToken,
				fiber.StatusUnauthorized)
			if refused != "unauthenticated" {
				t.Errorf("%s answered the slug %q, want %q", step.path, refused, "unauthenticated")
			}
		})
	}
}

// TestOrganizationOverrideDecidesTheRequirement proves that the sign-in reads
// both policy levels and that the organization override decides.
//
// Each direction stores the opposite value at the tenant default, so a gateway
// that read one level alone fails one of the two runs. The person holds no Second
// Factor throughout, so the requirement is the only thing that decides whether
// they owe an enrolment.
func TestOrganizationOverrideDecidesTheRequirement(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)

	t.Run("the override requires the factor the tenant default does not", func(t *testing.T) {
		setMFARequired(t, gw, "", false)
		setMFARequired(t, gw, fx.orgID, true)

		auth := gw.startAuthorization(t, fx.confidential)
		token, methods := signInToPassword(t, gw, fx)

		want := []string{session.StepEnrolPasskey, session.StepEnrolOTP}
		if !slices.Equal(methods, want) {
			t.Fatalf("methods is %v, want %v", methods, want)
		}

		// The step signal is the route forward, and the finalize step is the
		// enforcement. Both must read the override.
		refused := gw.refuse(t, completePath,
			fmt.Sprintf(`{"authRequest":%q}`, auth.request), token, fiber.StatusUnauthorized)
		if refused != "insufficient_factors" {
			t.Errorf("slug is %q, want %q", refused, "insufficient_factors")
		}
	})

	t.Run("the override drops the factor the tenant default requires", func(t *testing.T) {
		setMFARequired(t, gw, "", true)
		setMFARequired(t, gw, fx.orgID, false)

		auth := gw.startAuthorization(t, fx.confidential)
		token, methods := signInToPassword(t, gw, fx)

		if len(methods) != 0 {
			t.Fatalf("methods is %v, want none: the override asks for no factor", methods)
		}
		if issued := gw.finish(t, fx.confidential, auth, token); issued.AccessToken == "" {
			t.Fatal("the sign-in the override allows issued no token")
		}
	})
}

// TestAPasskeyIsNeverATOTPChallenge proves that a person who holds a passkey and
// no TOTP Enrolment reaches the passkey challenge, and never the TOTP one.
//
// The console renders one flag for both kinds of factor, and the derived column
// behind that flag counts both in one value. A step list built from that column
// could not say which challenge this person can answer, and it would send them
// to a TOTP challenge they hold no secret for.
//
// Each Factor is therefore read from the module that owns it. This test is what
// says so: the person holds a passkey row and no TOTP row, and one step is owed.
func TestAPasskeyIsNeverATOTPChallenge(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)
	givePasskey(t, gw, fx)

	if held := countRows(t, gw, "user_totp", "tenant_id = ? AND user_id = ?",
		gw.tenantID, fx.userID); held != 0 {
		t.Fatalf("the person holds %d totp rows, want none", held)
	}

	_, methods := signInToPassword(t, gw, fx)

	want := []string{session.StepChallengePasskey}
	if len(methods) != 1 || methods[0] != want[0] {
		t.Fatalf("methods is %v, want %v", methods, want)
	}
}

// heldFactorSlug is what both sign-in enrolment routes answer for a person who
// already holds a Second Factor. One rule reads as one value, so the sign-in
// front end handles it in one place.
const heldFactorSlug = "mfa_already_held"

// TestASignInNeverEnrolsBesideAHeldFactor drives both sign-in enrolment starts
// on a person who already holds a Second Factor, in both directions.
//
// This is the bypass the rule closes. The finalize gate re-reads the account on
// purpose, so a Factor an enrolment route records in the middle of a sign-in
// meets the challenge step the account owes. A person who holds the password
// alone would reach a token, and the device that protects the account would
// never be touched.
//
// Both directions run. The two routes carry one rule, and neither module reads
// the Factor the other owns, so a guard on one of them is half a fix.
//
// The refused start must also leave nothing behind. A pending row or a stored
// ceremony would be the same bypass one call later.
func TestASignInNeverEnrolsBesideAHeldFactor(t *testing.T) {
	skipUnlessIntegration(t)

	t.Run("a passkey holder is refused the totp enrolment", func(t *testing.T) {
		gw := newGateway(t)
		fx := seedFixture(t, gw)
		givePasskey(t, gw, fx)

		token, methods := signInToPassword(t, gw, fx)
		if !slices.Contains(methods, session.StepChallengePasskey) {
			t.Fatalf("methods is %v, want the passkey challenge among them", methods)
		}

		refused := gw.refuse(t, enrolStartPath, "{}", token, fiber.StatusConflict)
		if refused != heldFactorSlug {
			t.Errorf("slug is %q, want %q", refused, heldFactorSlug)
		}

		if held := countRows(t, gw, "user_totp", "tenant_id = ? AND user_id = ?",
			gw.tenantID, fx.userID); held != 0 {
			t.Errorf("the refused start left %d totp rows behind, want none", held)
		}
	})

	t.Run("a totp holder is refused the passkey enrolment", func(t *testing.T) {
		gw := newGateway(t)
		fx := seedFixture(t, gw)
		enrolFactor(t, gw, fx)
		forgetSpentStep(t, gw, fx)

		token, methods := signInToPassword(t, gw, fx)
		if !slices.Contains(methods, session.StepChallengeOTP) {
			t.Fatalf("methods is %v, want the otp challenge among them", methods)
		}

		// No Origin header is sent, the way the sign-in front end sends none.
		// The guard runs before the relying party is derived, so the refusal
		// below is the held Factor and never the origin.
		refused := gw.refuse(t, enrolPasskeyStartPath, "{}", token, fiber.StatusConflict)
		if refused != heldFactorSlug {
			t.Errorf("slug is %q, want %q", refused, heldFactorSlug)
		}

		if held := countRows(t, gw, "user_webauthn_credentials",
			"tenant_id = ? AND user_id = ?", gw.tenantID, fx.userID); held != 0 {
			t.Errorf("the refused start left %d passkey rows behind, want none", held)
		}
	})
}

// TestASignInNeverEnrolsOnAStaleCeremony drives the second half of each bypass:
// the person starts an enrolment while holding nothing, gains a Factor, and then
// finishes what the start left behind.
//
// The start refused on its own is half a fix. A pending TOTP row has no expiry,
// and a passkey ceremony lives for its TTL, so each start leaves something an
// account can still be enrolled with after it gains a Factor. That leftover is
// the same bypass, one call later.
func TestASignInNeverEnrolsOnAStaleCeremony(t *testing.T) {
	skipUnlessIntegration(t)

	t.Run("a pending totp enrolment is not activated beside a new passkey", func(t *testing.T) {
		gw := newGateway(t)
		fx := seedFixture(t, gw)

		// The person holds nothing here, so the start is allowed and it mints the
		// secret the activation below would prove.
		token, _ := signInToPassword(t, gw, fx)
		started := gw.enrolStart(t, token)
		if started.Secret == "" {
			t.Fatal("the start answered no secret")
		}

		// The Factor the account gains while the pending row sits there.
		givePasskey(t, gw, fx)

		refused := gw.refuse(t, enrolActivatePath,
			fmt.Sprintf(`{"code":%q}`, code(t, started.Secret)), token, fiber.StatusConflict)
		if refused != heldFactorSlug {
			t.Errorf("slug is %q, want %q", refused, heldFactorSlug)
		}

		if held := countRows(t, gw, "user_totp",
			"tenant_id = ? AND user_id = ? AND activated_at IS NOT NULL",
			gw.tenantID, fx.userID); held != 0 {
			t.Errorf("the refused activation left %d active totp rows behind", held)
		}
	})

	t.Run("a stale passkey ceremony is not finished beside a new totp factor", func(t *testing.T) {
		gw := newGateway(t)
		fx := seedFixture(t, gw)

		rpID, origin := registrableDomain(t, gw), "https://"+gw.domain

		// The person holds nothing here, so the start is allowed and it mints the
		// challenge the device signs below.
		token, _ := signInToPassword(t, gw, fx)
		device := newAuthenticator(t)
		options := gw.enrolPasskeyStart(t, token, origin)

		// The Factor the account gains while the browser prompt is open.
		enrolFactor(t, gw, fx)

		var refused struct {
			Error string `json:"error"`
		}
		decode(t, gw.enrolPasskeyFinish(t, token, origin,
			device.register(t, rpID, origin, options.PublicKey.Challenge)),
			fiber.StatusConflict, &refused)
		if refused.Error != heldFactorSlug {
			t.Errorf("slug is %q, want %q", refused.Error, heldFactorSlug)
		}

		if held := countRows(t, gw, "user_webauthn_credentials",
			"tenant_id = ? AND user_id = ?", gw.tenantID, fx.userID); held != 0 {
			t.Errorf("the refused finish left %d passkey rows behind", held)
		}
	})
}

// givePasskey writes one passkey row for the person, and removes it when the test
// ends. The fixture cleanup does not reach this table.
//
// The blob is an empty object, so this device can answer no challenge. The step
// signal is what this test reads, and the step signal counts rows. A ceremony
// that a real device answers is driven in passkey_challenge_flow_test.go.
func givePasskey(t *testing.T, gw *gateway, fx fixture) {
	t.Helper()

	credentialID := utils.NewUUIDv7()
	_, err := gw.bdb.ExecContext(t.Context(),
		`INSERT INTO user_webauthn_credentials (tenant_id, credential_id, user_id, rp_id, credential)
		 VALUES (?, ?, ?, ?, '{}')`, gw.tenantID, credentialID, fx.userID, gw.domain)
	if err != nil {
		t.Fatalf("register a passkey: %v", err)
	}

	t.Cleanup(func() {
		// t.Context is already cancelled when a cleanup runs, so the delete takes
		// a context of its own.
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		if _, err := gw.bdb.ExecContext(ctx,
			"DELETE FROM user_webauthn_credentials WHERE tenant_id = ? AND credential_id = ?",
			gw.tenantID, credentialID); err != nil {
			t.Errorf("remove the passkey: %v", err)
		}
	})

	// The derived column counts a live passkey row, so this is the state the
	// sign-in must not read.
	if held := countRows(t, gw, "user_webauthn_credentials",
		"tenant_id = ? AND user_id = ? AND deleted_at IS NULL",
		gw.tenantID, fx.userID); held != 1 {
		t.Fatalf("the person holds %d live passkeys, want one", held)
	}
}
