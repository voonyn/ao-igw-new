package oidc_test

// This file drives the Passkey challenge of the sign-in end to end, over HTTP,
// against the same routes the server mounts.
//
// It is the commit where a Passkey signs a person in. The password step names
// the step, the device answers it, and the ID token carries the Factor.
//
// The device is the software authenticator of authenticator_test.go. It
// registers through the portal and then signs in with the same key pair, which
// is what a real device does. The production code gains no seam for it, and the
// real library verifies every answer.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go
// and of mfa_challenge_flow_test.go, so it skips on the same environment
// variable and it creates its own people and its own clients.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/passkey"
	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/utils"
)

// The two sign-in addresses this slice adds, inside the second-factor group.
const (
	challengeStartPath  = "/mfa/passkey/challenge/start"
	challengeFinishPath = "/mfa/passkey/challenge/finish"
)

// failedAssertions is how many wrong answers the test sends before it sends a
// right one. A Login Session ends after five wrong codes, so a number above that
// is what proves a failed assertion is not counted as one.
const failedAssertions = 6

// signCounter is what the device reports once the successful assertions begin.
// A stored counter above zero is what a later, lower one can go back from.
const signCounter = 5

// TestPasskeyChallengeFlow signs one person in with a Passkey, and refuses every
// way of answering the challenge wrongly.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced. The wrong answers come first, so the successful
// sign-in below proves that none of them ended the Login Session.
func TestPasskeyChallengeFlow(t *testing.T) {
	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// What the deployment derives from the verified host, and the origin the
	// browser calls from. The tenant domain is a real registrable name, so the
	// RP ID is derived and no override is configured.
	origin := "https://" + gw.domain
	rpID := registrableDomain(t, gw)

	device := registerPasskey(t, gw, fx, origin)

	// The person the wrong-device case belongs to. They hold a Passkey of their
	// own, and it must never answer somebody else's challenge.
	other := seedFixture(t, gw)
	otherDevice := registerPasskey(t, gw, other, origin)

	auth := gw.startAuthorization(t, fx.confidential)
	token, methods := signInToPassword(t, gw, fx)

	t.Run("the password answer names the passkey challenge", func(t *testing.T) {
		// The person holds a Passkey and no TOTP Enrolment, so one step is owed
		// and it is the one the Factor is named for.
		want := []string{session.StepChallengePasskey}
		if len(methods) != 1 || methods[0] != want[0] {
			t.Fatalf("methods is %v, want %v", methods, want)
		}
	})

	t.Run("the finalize step refuses a person who skipped the challenge", func(t *testing.T) {
		// The step signal is the route forward, and this is the enforcement.
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
		answer := gw.challengeFinish(t, token, origin,
			device.assert(t, rpID, origin, wrongChallenge))

		var refused struct {
			Error string `json:"error"`
		}
		decode(t, answer, fiber.StatusConflict, &refused)
		if refused.Error != "passkey_challenge_expired" {
			t.Errorf("slug is %q, want %q", refused.Error, "passkey_challenge_expired")
		}
	})

	t.Run("the start names the rp id and the device the person holds", func(t *testing.T) {
		options := gw.challengeStart(t, token, origin)
		if options.PublicKey.RelyingPartyID != rpID {
			t.Errorf("the options name rp %q, want %q", options.PublicKey.RelyingPartyID, rpID)
		}
		if len(options.PublicKey.AllowCredentials) != 1 {
			t.Fatalf("the person holds one passkey and %s", options)
		}
		if got := options.PublicKey.AllowCredentials[0].ID; got != device.credentialID() {
			t.Errorf("the allow list names %q, want %q", got, device.credentialID())
		}
		if options.PublicKey.Challenge == "" {
			t.Error("the options carry no challenge")
		}
	})

	t.Run("the credential of another person is refused", func(t *testing.T) {
		options := gw.challengeStart(t, token, origin)
		answer := gw.challengeFinish(t, token, origin,
			otherDevice.assert(t, rpID, origin, options.PublicKey.Challenge))

		var refused struct {
			Error string `json:"error"`
		}
		decode(t, answer, fiber.StatusUnauthorized, &refused)
		if refused.Error != "passkey_unknown_credential" {
			t.Errorf("slug is %q, want %q", refused.Error, "passkey_unknown_credential")
		}
	})

	t.Run("a wrong answer never ends the sign-in", func(t *testing.T) {
		// A Login Session ends after five wrong codes. A signature is not a
		// guessable value, so a failed assertion must not spend one of those
		// five: a hostile page that could burn them would hold a free way to end
		// a person's sign-in.
		for i := range failedAssertions {
			gw.challengeStart(t, token, origin)

			var refused struct {
				Error string `json:"error"`
			}
			decode(t, gw.challengeFinish(t, token, origin,
				device.assert(t, rpID, origin, wrongChallenge)),
				fiber.StatusUnauthorized, &refused)

			if refused.Error != "passkey_rejected" {
				t.Fatalf("answer %d gave the slug %q, want %q", i+1, refused.Error, "passkey_rejected")
			}
		}
	})

	var rotated string
	t.Run("a successful assertion rotates the session token", func(t *testing.T) {
		// The device reports a counter above zero from here on, so the stored
		// blob carries one and the regression below has something to go back
		// from.
		device.count = signCounter

		options := gw.challengeStart(t, token, origin)

		var signed struct {
			SessionToken string `json:"sessionToken"`
		}
		decode(t, gw.challengeFinish(t, token, origin,
			device.assert(t, rpID, origin, options.PublicKey.Challenge)),
			fiber.StatusOK, &envelope{Data: &signed})

		if signed.SessionToken == "" || signed.SessionToken == token {
			t.Fatal("the challenge did not rotate the session token")
		}
		rotated = signed.SessionToken
	})

	t.Run("the id token carries webauthn and the acr is unchanged", func(t *testing.T) {
		if rotated == "" {
			t.Skip("the assertion above did not sign the person in")
		}

		claims := jwtClaims(t, gw.finish(t, fx.confidential, auth, rotated).IDToken)

		// The names are sorted, and mfa follows them. The Assurance Level counts
		// Factors and never names them, so two Factors read the same here as two
		// Factors of any other kind.
		assertAMR(t, claims, session.FactorPassword, session.FactorPasskey, "mfa")
		assertACR(t, claims, gw.cfg.OIDC.ACRPrefix+":2fa")
	})

	t.Run("a sign counter that goes backwards is not refused", func(t *testing.T) {
		// A counter below the stored one says the device may be a clone. The
		// gateway logs it and signs the person in: a synced passkey reports a
		// counter of its own on each device, and refusing here would shut out
		// every person whose keys sync.
		device.count = signCounter - 2

		options := gw.challengeStart(t, rotated, origin)

		var signed struct {
			SessionToken string `json:"sessionToken"`
		}
		decode(t, gw.challengeFinish(t, rotated, origin,
			device.assert(t, rpID, origin, options.PublicKey.Challenge)),
			fiber.StatusOK, &envelope{Data: &signed})

		if signed.SessionToken == "" {
			t.Fatal("the assertion answered no session token")
		}
		rotated = signed.SessionToken
	})

	t.Run("the passkey records the moment it was used", func(t *testing.T) {
		// The write-back rides the transaction the sign-in landed on, so a
		// sign-in the gateway reported is a last use the person can read.
		if held := countRows(t, gw, "user_webauthn_credentials",
			"tenant_id = ? AND user_id = ? AND last_used_at IS NOT NULL",
			gw.tenantID, fx.userID); held != 1 {
			t.Errorf("%d passkeys record a last use, want 1", held)
		}
	})

	t.Run("a ceremony start spends the shared guessing budget", func(t *testing.T) {
		// One budget covers both Second Factors, and a start is the request that
		// costs the gateway work. Without it, a session that proved a password
		// asks for challenges without end.
		//
		// It runs last, because it spends what every step above left. The bound
		// is well over the limit, so a budget that never refuses fails here
		// instead of looping.
		for range budgetProbes {
			answer := gw.do(t, fiber.MethodPost, loginPath(challengeStartPath), nil,
				gw.loginHeader(rotated, fiber.MIMEApplicationJSON)...)
			if answer.StatusCode != fiber.StatusTooManyRequests {
				continue
			}

			var refused struct {
				Error string `json:"error"`
			}
			decode(t, answer, fiber.StatusTooManyRequests, &refused)
			if refused.Error != "rate_limited" {
				t.Errorf("slug is %q, want %q", refused.Error, "rate_limited")
			}
			return
		}
		t.Errorf("%d ceremony starts never met the guessing budget", budgetProbes)
	})
}

// TestBothSecondFactorsAreOffered walks a person who holds a Passkey and a TOTP
// Enrolment, and proves the change to the finalize gate.
//
// This is the highest-risk case of the feature. The password answer names two
// challenge steps, the person answers one of them, and the gate must let that
// sign-in finish. A gate that demanded the exact name of every step would refuse
// a sign-in that is complete.
func TestBothSecondFactorsAreOffered(t *testing.T) {
	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// The Passkey first. Registration runs under an access token, and the token
	// endpoint refuses a sign-in that owes a Factor, so the person must hold none
	// while it runs.
	registerPasskey(t, gw, fx, "https://"+gw.domain)

	// The TOTP Enrolment beside it. The activation records the Factor on the
	// Login Session itself, so this sign-in never answers the passkey challenge
	// it was offered.
	secret := enrolBeside(t, gw, fx)
	forgetSpentStep(t, gw, fx)

	auth := gw.startAuthorization(t, fx.confidential)
	token, methods := signInToPassword(t, gw, fx)

	t.Run("both steps are named, the passkey first", func(t *testing.T) {
		want := []string{session.StepChallengePasskey, session.StepChallengeOTP}
		if len(methods) != 2 || methods[0] != want[0] || methods[1] != want[1] {
			t.Fatalf("methods is %v, want %v", methods, want)
		}
	})

	t.Run("the sign-in finishes on the factor the person chose", func(t *testing.T) {
		// The Authenticator answers, and the Passkey step is never run. The gate
		// reads a challenge step as met by any proved Second Factor, so the
		// sign-in below must reach a token.
		atFreshStep(t)

		var challenged struct {
			SessionToken string `json:"sessionToken"`
		}
		gw.login(t, verifyPath, fmt.Sprintf(`{"code":%q}`, code(t, secret)), token, &challenged)
		if challenged.SessionToken == "" {
			t.Fatal("the challenge answered no session token")
		}

		claims := jwtClaims(t, gw.finish(t, fx.confidential, auth, challenged.SessionToken).IDToken)
		assertAMR(t, claims, session.FactorOTP, session.FactorPassword, "mfa")
	})
}

// enrolBeside enrols a TOTP Second Factor on a person who already holds a
// Passkey, and answers the shared secret.
//
// It cannot use enrolFactor. That helper demands that the password answer names
// no step, which stops being true the moment the person holds any Factor.
func enrolBeside(t *testing.T, gw *gateway, fx fixture) string {
	t.Helper()

	token, methods := signInToPassword(t, gw, fx)
	if len(methods) != 1 || methods[0] != session.StepChallengePasskey {
		t.Fatalf("methods is %v, want %v", methods, []string{session.StepChallengePasskey})
	}

	started := gw.enrolStart(t, token)

	var activated struct {
		SessionToken string `json:"sessionToken"`
	}
	gw.login(t, enrolActivatePath,
		fmt.Sprintf(`{"code":%q}`, code(t, started.Secret)), token, &activated)
	if activated.SessionToken == "" {
		t.Fatal("the activation answered no session token")
	}
	return started.Secret
}

// wrongChallenge is a value no ceremony ever minted. A device that signs it
// produces a well formed answer to the wrong question, which is what a refused
// assertion is.
var wrongChallenge = base64.RawURLEncoding.EncodeToString([]byte("not-the-challenge"))

// assertionOptions is the half of the challenge options this test reads.
//
// The sign-in front end passes the whole object to the browser and reads no field
// out of it. The test reads these three, because they are what the assertions
// above are about: the RP ID the device answers under, the challenge it signs,
// and the devices it may answer with.
type assertionOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RelyingPartyID   string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

// String names the options in a failure message.
func (o assertionOptions) String() string {
	return fmt.Sprintf("rp %s, %d allowed", o.PublicKey.RelyingPartyID, len(o.PublicKey.AllowCredentials))
}

// challengeStart runs one challenge start and reads the ceremony options.
func (g *gateway) challengeStart(t *testing.T, token, origin string) assertionOptions {
	t.Helper()

	var options assertionOptions
	answer := g.do(t, fiber.MethodPost, loginPath(challengeStartPath), nil,
		append(g.loginHeader(token, fiber.MIMEApplicationJSON),
			fiber.HeaderOrigin, origin)...)
	decode(t, answer, fiber.StatusOK, &envelope{Data: &options})
	return options
}

// challengeFinish sends one assertion. The caller decodes the response, because
// most of the calls above expect a refusal.
func (g *gateway) challengeFinish(
	t *testing.T, token, origin string, answer json.RawMessage,
) *http.Response {
	t.Helper()

	body, err := json.Marshal(map[string]any{"credential": answer})
	if err != nil {
		t.Fatalf("encode the finish body: %v", err)
	}

	return g.do(t, fiber.MethodPost, loginPath(challengeFinishPath), bytes.NewReader(body),
		append(g.loginHeader(token, fiber.MIMEApplicationJSON), fiber.HeaderOrigin, origin)...)
}

// registerPasskey registers one software device on the account of one person,
// through the portal, and answers the device.
//
// It runs the real ceremony over HTTP. A row written straight into the table
// would carry no public key, and every assertion of it would fail for a reason
// that is not the one under test.
func registerPasskey(t *testing.T, gw *gateway, fx fixture, origin string) *authenticator {
	t.Helper()

	forAccount := fx.confidential
	forAccount.resource = oidc.ResourceAccountAPI

	portal := gw.signIn(t, fx, fx.password)
	held := gw.grant(t, forAccount, portal.token)

	device := newAuthenticator(t)
	options := gw.passkeyStart(t, held.AccessToken, origin)

	var registered passkey.View
	decode(t, gw.passkeyFinish(t, held.AccessToken, origin, "Laptop",
		device.register(t, registrableDomain(t, gw), origin, options.PublicKey.Challenge)),
		fiber.StatusCreated, &envelope{Data: &registered})

	if registered.ID != device.credentialID() {
		t.Fatalf("the registration named credential %q, want %q",
			registered.ID, device.credentialID())
	}
	return device
}

// registrableDomain is the RP ID this deployment derives from the verified host.
// The tenant domain is a real registrable name, so no override is configured and
// a host that derives nothing is a fixture this test cannot run against.
func registrableDomain(t *testing.T, gw *gateway) string {
	t.Helper()

	rpID := utils.RegistrableDomain(gw.domain)
	if rpID == "" {
		t.Fatalf("the tenant host %q has no registrable domain", gw.domain)
	}
	return rpID
}
