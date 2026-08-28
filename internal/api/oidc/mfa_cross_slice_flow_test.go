package oidc_test

// This file proves the second-factor cases no single slice owns. Every case
// drives the mounted routes over HTTP, the way the earlier slices do.
//
// Three cases live here. Every sign-in second-factor address refuses a Login
// Session that proved no password. An organization override of the MFA
// Requirement decides the sign-in while the tenant default says the opposite. A
// person who holds a passkey and no TOTP Enrolment is never sent to a TOTP
// challenge.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"context"
	"fmt"
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

		if len(methods) != 1 || methods[0] != session.StepEnrolOTP {
			t.Fatalf("methods is %v, want %v", methods, []string{session.StepEnrolOTP})
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
// no TOTP Enrolment signs in with their password alone.
//
// The console renders one flag for both kinds of factor, and the derived column
// behind that flag counts a passkey as a second factor. No passkey backend
// answers a sign-in, so a step that read the derived column would send this
// person to a TOTP challenge that nothing can answer, and the account would be
// shut out of the gateway.
func TestAPasskeyIsNeverATOTPChallenge(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)
	givePasskey(t, gw, fx)

	if held := countRows(t, gw, "user_totp", "tenant_id = ? AND user_id = ?",
		gw.tenantID, fx.userID); held != 0 {
		t.Fatalf("the person holds %d totp rows, want none", held)
	}

	auth := gw.startAuthorization(t, fx.confidential)
	token, methods := signInToPassword(t, gw, fx)

	if len(methods) != 0 {
		t.Fatalf("methods is %v, want none: the person holds no totp enrolment", methods)
	}
	if issued := gw.finish(t, fx.confidential, auth, token); issued.AccessToken == "" {
		t.Fatal("the sign-in issued no token")
	}
}

// givePasskey registers one passkey on the person, and removes it when the test
// ends. The fixture cleanup does not reach this table.
//
// The stored blob is a public key and metadata, so an empty object is enough.
// Nothing in a sign-in reads it, and that is what the test is about.
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
