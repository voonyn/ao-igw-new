package oidc_test

// This file drives the second-factor challenge end to end, over HTTP, against
// the same routes the server mounts.
//
// A person who holds an active TOTP Enrolment answers a code after their
// password and signs in. A person without their phone redeems one Recovery Code
// instead. The MFA Requirement is left off for the whole run, so every challenge
// here is the factor the person holds, and nothing the policy asked for.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	rfc6238 "github.com/pquerna/otp/totp"

	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/session"
)

// verifyPath is where the sign-in front end answers the challenge, inside the
// login group. One address takes both kinds of value.
const verifyPath = "/mfa/verify"

// stepSeconds is the width of one TOTP time step. The gateway reads the same
// number, and a test that computed a code for another width would prove nothing.
const stepSeconds = 30

// stepHeadroom is how much of the current time step must be left before a test
// submits a code. A step that ended between the code and the request would move
// the window the gateway reads, and the run would fail for a reason the code
// under test is not responsible for.
const stepHeadroom = 5

// TestSecondFactorChallengeFlow walks one person who holds a Second Factor from
// an authorization request to tokens, twice: once with a code from the
// Authenticator, and once with a Recovery Code.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestSecondFactorChallengeFlow(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// The person enrols by choice. Nothing in this run turns the MFA Requirement
	// on, so the challenges below prove that an active factor is always
	// challenged, whatever the policy says. A person who chose to protect their
	// account keeps that protection when an administrator clears the flag.
	secret, codes := enrolFactor(t, gw, fx)

	// The activation spent the time step it was proved with. A person signing in
	// again arrives steps later, so the test puts the account in that state
	// instead of waiting for the clock.
	forgetSpentStep(t, gw, fx)

	auth := gw.startAuthorization(t, fx.confidential)
	token, methods := signInToPassword(t, gw, fx)

	t.Run("the password answer names the challenge", func(t *testing.T) {
		if len(methods) != 1 || methods[0] != session.FactorOTP {
			t.Fatalf("methods is %v, want %v", methods, []string{session.FactorOTP})
		}
	})

	t.Run("a wrong code is refused as a wrong code", func(t *testing.T) {
		// The slug the login UI renders as a wrong code. The unauthenticated slug
		// would tell the person their email or password was wrong, which it was
		// not.
		refused := gw.refuse(t, verifyPath, `{"code":"000000"}`, token, fiber.StatusUnauthorized)
		if refused != "invalid_credentials" {
			t.Errorf("slug is %q, want %q", refused, "invalid_credentials")
		}
	})

	// The code of the previous time step, which is what a phone whose clock
	// drifts by a few seconds shows.
	atFreshStep(t)
	drifted := codeAt(t, secret, time.Now().UTC().Add(-stepSeconds*time.Second))

	var challenged struct {
		SessionToken string `json:"sessionToken"`
	}
	gw.login(t, verifyPath, fmt.Sprintf(`{"code":%q}`, drifted), token, &challenged)

	t.Run("a code from the previous time step is accepted", func(t *testing.T) {
		if challenged.SessionToken == "" || challenged.SessionToken == token {
			t.Fatal("the challenge did not rotate the session token")
		}
		// The token the browser held is dead. A rotation that left the old value
		// usable would leave a credential behind on every challenge.
		if gw.refuse(t, verifyPath, `{"code":"000000"}`, token,
			fiber.StatusUnauthorized) != "unauthenticated" {
			t.Error("the token the challenge replaced still credentials a request")
		}
	})

	t.Run("the same code is refused on a second submission", func(t *testing.T) {
		// A fresh sign-in, so the refusal is the spent step and not the rotated
		// token. The comparison is "less than", so the step this code proved is
		// refused whether the clock has moved on or not.
		replay, _ := signInToPassword(t, gw, fx)
		refused := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, drifted), replay,
			fiber.StatusUnauthorized)
		if refused != "invalid_credentials" {
			t.Errorf("slug is %q, want %q", refused, "invalid_credentials")
		}
	})

	t.Run("the authorization request the person arrived on completes", func(t *testing.T) {
		issued := gw.finish(t, fx.confidential, auth, challenged.SessionToken)
		if issued.AccessToken == "" || issued.IDToken == "" {
			t.Fatalf("the token endpoint answered %+v", issued)
		}
		if sub, _ := jwtClaims(t, issued.IDToken)["sub"].(string); sub != fx.userID {
			t.Errorf("sub is %q, want the person %q", sub, fx.userID)
		}
	})

	t.Run("a recovery code signs the person in and is then spent", func(t *testing.T) {
		before := time.Now().UTC()
		auth := gw.startAuthorization(t, fx.confidential)
		token, methods := signInToPassword(t, gw, fx)
		if len(methods) != 1 || methods[0] != session.FactorOTP {
			t.Fatalf("methods is %v, want %v", methods, []string{session.FactorOTP})
		}

		var redeemed struct {
			SessionToken string `json:"sessionToken"`
		}
		gw.login(t, verifyPath, fmt.Sprintf(`{"code":%q}`, codes[0]), token, &redeemed)
		if redeemed.SessionToken == "" || redeemed.SessionToken == token {
			t.Fatal("the redemption did not rotate the session token")
		}

		// The row is gone, not marked. A code is consumed once.
		if held := recoveryCodesHeld(t, gw, fx); held != len(codes)-1 {
			t.Errorf("%d recovery codes remain, want %d", held, len(codes)-1)
		}
		if countAudit(t, gw, "mfa.recovery_code_used", before) == 0 {
			t.Error("no mfa.recovery_code_used event was recorded")
		}
		// The same Factor as a code from the Authenticator, so the sign-in that
		// follows passes the same gate.
		if countAudit(t, gw, "login.succeeded", before) == 0 {
			t.Error("no login.succeeded event was recorded")
		}

		issued := gw.finish(t, fx.confidential, auth, redeemed.SessionToken)
		if issued.AccessToken == "" || issued.IDToken == "" {
			t.Fatalf("the token endpoint answered %+v", issued)
		}
	})

	t.Run("a recovery code is refused the second time", func(t *testing.T) {
		token, _ := signInToPassword(t, gw, fx)
		refused := gw.refuse(t, verifyPath, fmt.Sprintf(`{"code":%q}`, codes[0]), token,
			fiber.StatusUnauthorized)
		if refused != "invalid_credentials" {
			t.Errorf("slug is %q, want %q", refused, "invalid_credentials")
		}
		if held := recoveryCodesHeld(t, gw, fx); held != len(codes)-1 {
			t.Errorf("%d recovery codes remain, want %d", held, len(codes)-1)
		}
	})

	t.Run("nothing happens automatically when the last code is spent", func(t *testing.T) {
		// The account is put one code from empty, so the last redemption is one
		// request and not eight sign-ins.
		keepOneRecoveryCode(t, gw, fx, codes[len(codes)-1])
		before := time.Now().UTC()

		token, _ := signInToPassword(t, gw, fx)
		var redeemed struct {
			SessionToken string `json:"sessionToken"`
		}
		gw.login(t, verifyPath, fmt.Sprintf(`{"code":%q}`, codes[len(codes)-1]), token, &redeemed)

		// No set is issued. The answer names no code, and the table holds none.
		if held := recoveryCodesHeld(t, gw, fx); held != 0 {
			t.Errorf("%d recovery codes remain, want none issued", held)
		}
		if countAudit(t, gw, "mfa.recovery_codes_regenerated", before) != 0 {
			t.Error("a set of recovery codes was issued automatically")
		}
		// Re-enrolment is not forced either. The factor still stands, so the next
		// sign-in is challenged the same way.
		_, methods := signInToPassword(t, gw, fx)
		if len(methods) != 1 || methods[0] != session.FactorOTP {
			t.Errorf("methods is %v, want %v", methods, []string{session.FactorOTP})
		}
	})

	t.Run("the finalize step refuses a person who skipped the challenge", func(t *testing.T) {
		// The account has spent time steps above, so the code below is computed
		// for a step this factor has not proved yet.
		forgetSpentStep(t, gw, fx)

		auth := gw.startAuthorization(t, fx.confidential)
		token, methods := signInToPassword(t, gw, fx)
		if len(methods) != 1 || methods[0] != session.FactorOTP {
			t.Fatalf("methods is %v, want %v", methods, []string{session.FactorOTP})
		}

		// The step signal is the route forward, and this is the enforcement. The
		// finalize step is reachable on its own, so a person who never visits the
		// challenge arrives here holding one factor.
		refused := gw.refuse(t, completePath,
			fmt.Sprintf(`{"authRequest":%q}`, auth.request), token, fiber.StatusUnauthorized)
		if refused != "insufficient_factors" {
			t.Fatalf("slug is %q, want %q", refused, "insufficient_factors")
		}

		// The refusal is not a dead end. The login UI reads that slug and routes
		// the person back to the step they skipped, and the sign-in finishes on
		// the same authorization request.
		atFreshStep(t)
		var challenged struct {
			SessionToken string `json:"sessionToken"`
		}
		gw.login(t, verifyPath, fmt.Sprintf(`{"code":%q}`, code(t, secret)), token, &challenged)
		if challenged.SessionToken == "" {
			t.Fatal("the challenge answered no session token")
		}

		issued := gw.finish(t, fx.confidential, auth, challenged.SessionToken)
		if issued.AccessToken == "" || issued.IDToken == "" {
			t.Fatalf("the token endpoint answered %+v", issued)
		}
	})
}

// enrolFactor signs the person in once and enrols a Second Factor, over HTTP.
// It answers the shared secret and the Recovery Codes the activation disclosed.
//
// The password answer names no step here, which is what proves the MFA
// Requirement is off for this run.
func enrolFactor(t *testing.T, gw *gateway, fx fixture) (secret string, codes []string) {
	t.Helper()

	token, methods := signInToPassword(t, gw, fx)
	if len(methods) != 0 {
		t.Fatalf("methods is %v before any factor is enrolled, want none", methods)
	}

	started := gw.enrolStart(t, token)

	var activated struct {
		SessionToken  string   `json:"sessionToken"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	gw.login(t, enrolActivatePath,
		fmt.Sprintf(`{"code":%q}`, code(t, started.Secret)), token, &activated)
	if len(activated.RecoveryCodes) == 0 {
		t.Fatal("the activation issued no recovery codes")
	}
	return started.Secret, activated.RecoveryCodes
}

// signInToPassword opens a login session and proves the password on it. It
// answers the rotated token and the steps the person still owes.
func signInToPassword(t *testing.T, gw *gateway, fx fixture) (token string, methods []string) {
	t.Helper()

	var opened struct {
		SessionToken string `json:"sessionToken"`
	}
	gw.login(t, "/identifier", fmt.Sprintf(`{"identifier":%q}`, fx.email), "", &opened)

	var verified struct {
		SessionToken string   `json:"sessionToken"`
		Methods      []string `json:"methods"`
	}
	gw.login(t, "/password", fmt.Sprintf(`{"password":%q}`, fx.password),
		opened.SessionToken, &verified)
	if verified.SessionToken == "" {
		t.Fatal("the password step answered no session token")
	}
	return verified.SessionToken, verified.Methods
}

// forgetSpentStep puts the account back to a factor that has spent no time step.
//
// The activation spends the step it was proved with, and a test that signed in
// again inside the same 30 seconds would be refused for the right reason at the
// wrong moment. A person signing in later is steps ahead of the one they spent,
// and this is that state.
func forgetSpentStep(t *testing.T, gw *gateway, fx fixture) {
	t.Helper()

	_, err := gw.bdb.ExecContext(t.Context(),
		"UPDATE user_totp SET last_step = 0 WHERE tenant_id = ? AND user_id = ?",
		gw.tenantID, fx.userID)
	if err != nil {
		t.Fatalf("clear the spent time step: %v", err)
	}
}

// keepOneRecoveryCode leaves the account holding the one code named, so the next
// redemption spends its last one.
func keepOneRecoveryCode(t *testing.T, gw *gateway, fx fixture, keep string) {
	t.Helper()

	_, err := gw.bdb.ExecContext(t.Context(),
		"DELETE FROM user_totp_recovery_codes WHERE tenant_id = ? AND user_id = ? AND code_hash <> ?",
		gw.tenantID, fx.userID, recoveryDigest(keep))
	if err != nil {
		t.Fatalf("spend every recovery code but one: %v", err)
	}
	if held := recoveryCodesHeld(t, gw, fx); held != 1 {
		t.Fatalf("%d recovery codes remain, want the last one", held)
	}
}

// recoveryCodesHeld answers how many Recovery Codes the account still holds. A
// spent code leaves no row, so the count is the answer.
func recoveryCodesHeld(t *testing.T, gw *gateway, fx fixture) int {
	t.Helper()

	return countRows(t, gw, "user_totp_recovery_codes",
		"tenant_id = ? AND user_id = ?", gw.tenantID, fx.userID)
}

// recoveryDigest is what the table stores for one Recovery Code as it was shown.
//
// The printed form carries a hyphen and nothing else the canonical spelling
// drops, because the alphabet holds no character a person mistypes for another.
func recoveryDigest(shown string) string {
	return crypto.Digest(strings.ReplaceAll(shown, "-", ""))
}

// atFreshStep waits until enough of the current time step is left for one
// request to run inside it.
func atFreshStep(t *testing.T) {
	t.Helper()

	if left := stepSeconds - time.Now().Unix()%stepSeconds; left < stepHeadroom {
		time.Sleep(time.Duration(left) * time.Second)
	}
}

// codeAt is what an Authenticator shows for one secret at one moment.
func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()

	shown, err := rfc6238.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("generate a totp code: %v", err)
	}
	return shown
}
