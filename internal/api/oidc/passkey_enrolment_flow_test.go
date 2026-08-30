package oidc_test

// This file drives the Passkey half of forced enrolment end to end, over HTTP,
// against the same routes the server mounts.
//
// A person the MFA Requirement governs, holding no Second Factor, is offered
// both enrolments. They enrol a Passkey, and they reach a token with no second
// challenge: they proved the password, and the enrolment proved the device.
//
// The device is the software authenticator of authenticator_test.go. The
// production code gains no seam for it, and the real library verifies the
// answer.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go
// and of the two files beside it, so it skips on the same environment variable
// and it creates its own person and its own client.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/session"
)

// The two sign-in addresses this slice adds, inside the second-factor group.
const (
	enrolPasskeyStartPath  = "/mfa/passkey/enroll/start"
	enrolPasskeyFinishPath = "/mfa/passkey/enroll/finish"
)

// TestPasskeyForcedEnrolmentFlow walks one person from an authorization request
// to tokens, enrolling a Passkey in the middle because the policy demands a
// Second Factor.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestPasskeyForcedEnrolmentFlow(t *testing.T) {
	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// The requirement is an organization override, the way the TOTP run sets it.
	setMFARequired(t, gw, fx.orgID, true)

	// What the deployment derives from the verified host, and the origin the
	// browser calls from.
	origin := "https://" + gw.domain
	rpID := registrableDomain(t, gw)

	auth := gw.startAuthorization(t, fx.confidential)
	token, methods := signInToPassword(t, gw, fx)

	t.Run("the password answer names both enrolments, the passkey first", func(t *testing.T) {
		// A device with no authenticator must never dead-end, so both are named
		// every time and the screen renders both at once.
		want := []string{session.StepEnrolPasskey, session.StepEnrolOTP}
		if !slices.Equal(methods, want) {
			t.Fatalf("methods is %v, want %v", methods, want)
		}
	})

	t.Run("the finalize step refuses a person who skipped enrolment", func(t *testing.T) {
		// The step signal is the route forward, and this is the enforcement. An
		// enrolment step is matched by its exact name, so the password alone
		// answers neither of the two.
		refused := gw.refuse(t, completePath,
			fmt.Sprintf(`{"authRequest":%q}`, auth.request), token, fiber.StatusUnauthorized)
		if refused != "insufficient_factors" {
			t.Errorf("slug is %q, want %q", refused, "insufficient_factors")
		}
	})

	t.Run("a finish with no challenge behind it is refused", func(t *testing.T) {
		// A challenge that ran out its TTL and one that a finish already consumed
		// both read the same here: nothing is stored, and the person starts
		// again.
		device := newAuthenticator(t)
		answer := gw.enrolPasskeyFinish(t, token, origin,
			device.register(t, rpID, origin, wrongChallenge))

		var refused struct {
			Error string `json:"error"`
		}
		decode(t, answer, fiber.StatusConflict, &refused)
		if refused.Error != "passkey_challenge_expired" {
			t.Errorf("slug is %q, want %q", refused.Error, "passkey_challenge_expired")
		}
	})

	t.Run("the start names the derived rp id and the person", func(t *testing.T) {
		options := gw.enrolPasskeyStart(t, token, origin)
		if options.PublicKey.RelyingParty.ID != rpID {
			t.Errorf("the options name rp id %q, want %q",
				options.PublicKey.RelyingParty.ID, rpID)
		}
		if options.PublicKey.Challenge == "" {
			t.Error("the options carry no challenge")
		}
		if want := base64url(fx.userID); options.PublicKey.User.ID != want {
			t.Errorf("the user handle is %q, want %q", options.PublicKey.User.ID, want)
		}
		// The person holds no Passkey, so nothing is excluded.
		if len(options.PublicKey.ExcludeCredentials) != 0 {
			t.Errorf("the person holds no passkey and %s", options)
		}
	})

	// The abandoned ceremony. A person who cancelled the browser prompt starts
	// again, and the second start replaces the first.
	device := newAuthenticator(t)
	abandoned := gw.enrolPasskeyStart(t, token, origin)
	options := gw.enrolPasskeyStart(t, token, origin)

	t.Run("a second start replaces the pending ceremony", func(t *testing.T) {
		if abandoned.PublicKey.Challenge == options.PublicKey.Challenge {
			t.Fatal("the second start answered the challenge of the first")
		}
		// The abandoned challenge no longer proves anything, so a person who left
		// a prompt half done is not held to it.
		var refused struct {
			Error string `json:"error"`
		}
		decode(t, gw.enrolPasskeyFinish(t, token, origin,
			device.register(t, rpID, origin, abandoned.PublicKey.Challenge)),
			fiber.StatusUnauthorized, &refused)
		if refused.Error != "passkey_rejected" {
			t.Errorf("slug is %q, want %q", refused.Error, "passkey_rejected")
		}
	})

	// The enrolment that lands. The ceremony above was consumed by the refused
	// finish, so a fresh one runs here.
	enrolled := gw.enrolPasskeyStart(t, token, origin)

	var rotated string
	t.Run("an enrolment records the passkey and rotates the token", func(t *testing.T) {
		var signed struct {
			SessionToken string `json:"sessionToken"`
		}
		decode(t, gw.enrolPasskeyFinish(t, token, origin,
			device.register(t, rpID, origin, enrolled.PublicKey.Challenge)),
			fiber.StatusOK, &envelope{Data: &signed})

		if signed.SessionToken == "" || signed.SessionToken == token {
			t.Fatal("the enrolment did not rotate the session token")
		}
		rotated = signed.SessionToken

		// The token the browser held is dead. A rotation that left the old value
		// usable would leave a credential behind on every enrolment.
		if gw.refuse(t, enrolPasskeyStartPath, "", token, fiber.StatusUnauthorized) != "unauthenticated" {
			t.Error("the token the enrolment replaced still credentials a request")
		}

		if held := countRows(t, gw, "user_webauthn_credentials",
			"tenant_id = ? AND user_id = ? AND deleted_at IS NULL",
			gw.tenantID, fx.userID); held != 1 {
			t.Errorf("%d passkeys are stored, want 1", held)
		}
	})

	t.Run("the person continues with no second challenge", func(t *testing.T) {
		if rotated == "" {
			t.Skip("the enrolment above did not sign the person in")
		}

		// The enrolment proved possession of the device, so the gate is answered
		// and the authorization request the person arrived on completes.
		issued := gw.finish(t, fx.confidential, auth, rotated)
		if issued.AccessToken == "" || issued.IDToken == "" {
			t.Fatalf("the token endpoint answered %+v", issued)
		}
		assertAMR(t, jwtClaims(t, issued.IDToken),
			session.FactorPassword, session.FactorPasskey, "mfa")
	})

	t.Run("the next sign-in challenges the passkey it enrolled", func(t *testing.T) {
		// The account now holds a Factor, so the requirement is answered by a
		// challenge and the enrolment is never offered again.
		_, next := signInToPassword(t, gw, fx)
		want := []string{session.StepChallengePasskey}
		if !slices.Equal(next, want) {
			t.Fatalf("methods is %v, want %v", next, want)
		}
	})
}

// enrolPasskeyStart runs one sign-in enrolment start and reads the ceremony
// options.
func (g *gateway) enrolPasskeyStart(t *testing.T, token, origin string) registrationOptions {
	t.Helper()

	var options registrationOptions
	answer := g.do(t, fiber.MethodPost, loginPath(enrolPasskeyStartPath), nil,
		append(g.loginHeader(token, fiber.MIMEApplicationJSON),
			fiber.HeaderOrigin, origin)...)
	decode(t, answer, fiber.StatusOK, &envelope{Data: &options})
	return options
}

// enrolPasskeyFinish sends one registration answer. The caller decodes the
// response, because half the calls above expect a refusal.
func (g *gateway) enrolPasskeyFinish(
	t *testing.T, token, origin string, answer json.RawMessage,
) *http.Response {
	t.Helper()

	body, err := json.Marshal(map[string]any{"credential": answer})
	if err != nil {
		t.Fatalf("encode the finish body: %v", err)
	}

	return g.do(t, fiber.MethodPost, loginPath(enrolPasskeyFinishPath), bytes.NewReader(body),
		append(g.loginHeader(token, fiber.MIMEApplicationJSON), fiber.HeaderOrigin, origin)...)
}
