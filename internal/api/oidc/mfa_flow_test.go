package oidc_test

// This file drives forced enrolment end to end, over HTTP, against the same
// routes the server mounts.
//
// A person governed by the MFA Requirement, holding no Second Factor, is walked
// through enrolment during the sign-in and finishes signed in. The requirement
// is set as an organization override, so the run also proves that both policy
// levels resolve: the tenant default says nothing, and the override decides.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	rfc6238 "github.com/pquerna/otp/totp"

	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/session"
)

// The three login addresses this slice adds, inside the login group.
const (
	enrolStartPath    = "/mfa/totp/enroll/start"
	enrolActivatePath = "/mfa/totp/enroll/activate"
)

// recoveryCodesIssued is how many Recovery Codes one activation answers.
const recoveryCodesIssued = 10

// TestForcedEnrolmentFlow walks one person from an authorization request to
// tokens, enrolling a Second Factor in the middle because the policy demands
// one.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestForcedEnrolmentFlow(t *testing.T) {
	skipUnlessIntegration(t)

	gw := newGateway(t)
	fx := seedFixture(t, gw)
	requireMFA(t, gw, fx.orgID)

	// Where the person arrives. The browser is at the sign-in page with this
	// authorization request named on the query, and the sign-in must finish it.
	auth := gw.startAuthorization(t, fx.confidential)

	var opened struct {
		SessionID    string `json:"sessionId"`
		SessionToken string `json:"sessionToken"`
	}
	gw.login(t, "/identifier", fmt.Sprintf(`{"identifier":%q}`, fx.email), "", &opened)
	if opened.SessionID == "" || opened.SessionToken == "" {
		t.Fatalf("identifier answered %+v", opened)
	}

	t.Run("a session that proved no password cannot enrol a factor", func(t *testing.T) {
		// This is the guard the whole module rests on. The session names the
		// person from the identifier step onward, so without it anybody who
		// knows an identifier could enrol a factor on that account.
		for _, step := range []string{enrolStartPath, enrolActivatePath} {
			t.Run(step, func(t *testing.T) {
				refused := gw.refuse(t, step, `{"code":"000000"}`, opened.SessionToken,
					fiber.StatusUnauthorized)
				if refused != "unauthenticated" {
					t.Errorf("slug is %q, want %q", refused, "unauthenticated")
				}
			})
		}
	})

	// The password step. Its answer names the factor the person still owes.
	var verified struct {
		SessionToken string   `json:"sessionToken"`
		Methods      []string `json:"methods"`
	}
	gw.login(t, "/password", fmt.Sprintf(`{"password":%q}`, fx.password), opened.SessionToken, &verified)
	token := verified.SessionToken

	t.Run("the password answer names forced enrolment", func(t *testing.T) {
		if token == "" || token == opened.SessionToken {
			t.Fatal("the password step did not rotate the session token")
		}
		if len(verified.Methods) != 1 || verified.Methods[0] != session.StepEnrolOTP {
			t.Fatalf("methods is %v, want %v", verified.Methods, []string{session.StepEnrolOTP})
		}
		// No passkey value is ever named. No passkey backend exists, so a person
		// routed to one would reach a screen that never moves.
		for _, method := range verified.Methods {
			if strings.Contains(method, "webauthn") || strings.Contains(method, "passkey") {
				t.Errorf("methods names a passkey: %v", verified.Methods)
			}
		}
	})

	// The first start. Its secret is abandoned below, which proves that a second
	// start replaces a pending enrolment instead of being blocked by it.
	abandoned := gw.enrolStart(t, token)

	t.Run("a start answers the secret and the provisioning uri", func(t *testing.T) {
		if abandoned.Secret == "" {
			t.Fatal("start answered no secret")
		}
		if !strings.HasPrefix(abandoned.OtpauthURI, "otpauth://totp/") {
			t.Fatalf("the provisioning uri is %q, want an otpauth uri", abandoned.OtpauthURI)
		}
		// The tenant is named by the host of its issuer, and the person by their
		// email address. A blank label is what must never happen.
		if !strings.Contains(abandoned.OtpauthURI, fx.email) {
			t.Errorf("the provisioning uri %q does not name the person", abandoned.OtpauthURI)
		}
		if !strings.Contains(abandoned.OtpauthURI, gw.domain) {
			t.Errorf("the provisioning uri %q does not name the tenant %q",
				abandoned.OtpauthURI, gw.domain)
		}
		if !strings.Contains(abandoned.OtpauthURI, "secret="+abandoned.Secret) {
			t.Error("the provisioning uri does not carry the secret the answer named")
		}
		// A start records no factor and rotates no token, so the person is still
		// where the password step left them.
		if gw.enrolStart(t, token).Secret == "" {
			t.Fatal("the session token was rotated by a start")
		}
	})

	started := gw.enrolStart(t, token)

	t.Run("a second start replaces the pending enrolment", func(t *testing.T) {
		if started.Secret == abandoned.Secret {
			t.Error("the second start answered the secret of the first")
		}
		// The abandoned secret no longer proves anything, so a person who left a
		// setup half done is not held to it.
		refused := gw.refuse(t, enrolActivatePath,
			fmt.Sprintf(`{"code":%q}`, code(t, abandoned.Secret)), token, fiber.StatusUnauthorized)
		if refused != "invalid_credentials" {
			t.Errorf("slug is %q, want %q", refused, "invalid_credentials")
		}
	})

	t.Run("a wrong code is refused", func(t *testing.T) {
		refused := gw.refuse(t, enrolActivatePath, `{"code":"000000"}`, token, fiber.StatusUnauthorized)
		if refused != "invalid_credentials" {
			t.Errorf("slug is %q, want %q", refused, "invalid_credentials")
		}
	})

	before := time.Now().UTC()

	var activated struct {
		SessionToken  string   `json:"sessionToken"`
		RecoveryCodes []string `json:"recoveryCodes"`
	}
	gw.login(t, enrolActivatePath,
		fmt.Sprintf(`{"code":%q}`, code(t, started.Secret)), token, &activated)

	t.Run("an activation records the factor and rotates the token", func(t *testing.T) {
		if activated.SessionToken == "" {
			t.Fatal("activate answered no session token")
		}
		if activated.SessionToken == token {
			t.Fatal("activate answered the token it was called with")
		}
		// The token the browser held is dead. A rotation that left the old value
		// usable would leave a credential behind on every enrolment.
		if gw.refuse(t, enrolStartPath, "{}", token, fiber.StatusUnauthorized) != "unauthenticated" {
			t.Error("the token the activation replaced still credentials a request")
		}
	})

	t.Run("ten recovery codes are issued", func(t *testing.T) {
		if len(activated.RecoveryCodes) != recoveryCodesIssued {
			t.Fatalf("%d recovery codes, want %d", len(activated.RecoveryCodes), recoveryCodesIssued)
		}

		seen := make(map[string]bool, recoveryCodesIssued)
		for _, shown := range activated.RecoveryCodes {
			groups := strings.Split(shown, "-")
			if len(groups) != 2 || len(groups[0]) != 5 || len(groups[1]) != 5 {
				t.Errorf("the code %q is not two groups of five", shown)
			}
			if seen[shown] {
				t.Errorf("the code %q was issued twice", shown)
			}
			seen[shown] = true
		}

		// The plaintext is never stored. Every row holds the digest of the code,
		// so no code the person was shown can be read back out of the table.
		for _, shown := range activated.RecoveryCodes {
			plain := strings.ReplaceAll(shown, "-", "")
			if countRows(t, gw, "user_totp_recovery_codes",
				"user_id = ? AND code_hash = ?", fx.userID, plain) != 0 {
				t.Fatalf("the code %q is stored in the clear", shown)
			}
			if countRows(t, gw, "user_totp_recovery_codes",
				"user_id = ? AND code_hash = ?", fx.userID, crypto.Digest(plain)) != 1 {
				t.Errorf("the code %q is not stored as its digest", shown)
			}
		}
		if held := countRows(t, gw, "user_totp_recovery_codes",
			"user_id = ?", fx.userID); held != recoveryCodesIssued {
			t.Errorf("%d recovery code rows, want %d", held, recoveryCodesIssued)
		}
	})

	t.Run("the secret is encrypted at rest", func(t *testing.T) {
		var stored []byte
		err := gw.bdb.NewSelect().Table("user_totp").Column("secret_encrypted").
			Where("tenant_id = ? AND user_id = ?", gw.tenantID, fx.userID).Scan(t.Context(), &stored)
		if err != nil {
			t.Fatalf("read the stored secret: %v", err)
		}
		// A deployment with no encryption key stores the secret in the clear, the
		// way the login session and the OIDC storage already do. This run
		// configures a key, so the plaintext must not be there.
		if gw.cfg.Database.EncryptionKey != "" && strings.Contains(string(stored), started.Secret) {
			t.Error("the stored secret carries the plaintext")
		}
	})

	t.Run("a start against an active factor is refused", func(t *testing.T) {
		refused := gw.refuse(t, enrolStartPath, "{}", activated.SessionToken, fiber.StatusConflict)
		if refused != "mfa_already_enrolled" {
			t.Errorf("slug is %q, want %q", refused, "mfa_already_enrolled")
		}
	})

	t.Run("a factor-added event is recorded", func(t *testing.T) {
		if countAudit(t, gw, "mfa.enrolled", before) == 0 {
			t.Error("no mfa.enrolled event was recorded")
		}
	})

	t.Run("the authorization request the person arrived on completes", func(t *testing.T) {
		issued := gw.finish(t, fx.confidential, auth, activated.SessionToken)
		if issued.AccessToken == "" || issued.IDToken == "" {
			t.Fatalf("the token endpoint answered %+v", issued)
		}
		if sid, _ := jwtClaims(t, issued.IDToken)["sid"].(string); sid != opened.SessionID {
			t.Errorf("sid is %q, want the login session %q", sid, opened.SessionID)
		}
		if sub, _ := jwtClaims(t, issued.IDToken)["sub"].(string); sub != fx.userID {
			t.Errorf("sub is %q, want the person %q", sub, fx.userID)
		}
	})
}

// enrolStart runs one enrolment start and reads the answer.
func (g *gateway) enrolStart(t *testing.T, token string) struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauthUri"`
} {
	t.Helper()

	var started struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauthUri"`
	}
	g.login(t, enrolStartPath, "{}", token, &started)
	return started
}

// refuse runs one login step that is expected to fail, and returns the slug the
// answer carried. A client branches on the slug, never on the message.
func (g *gateway) refuse(t *testing.T, step, body, token string, want int) string {
	t.Helper()

	var refused struct {
		Error string `json:"error"`
	}
	answer := g.do(t, fiber.MethodPost, loginPath(step), strings.NewReader(body),
		g.loginHeader(token, fiber.MIMEApplicationJSON)...)
	decode(t, answer, want, &refused)
	return refused.Error
}

// code is what an Authenticator shows for one secret right now.
func code(t *testing.T, secret string) string {
	t.Helper()

	shown, err := rfc6238.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate a totp code: %v", err)
	}
	return shown
}

// requireMFA turns the MFA Requirement on for one organization, and restores the
// level as it found it when the test ends.
//
// The override is written and the tenant default is left alone, so the run also
// proves that both levels resolve. A read of the tenant row alone would leave
// this test signing the person in with no factor.
func requireMFA(t *testing.T, gw *gateway, orgID string) {
	t.Helper()

	ctx := t.Context()

	var required, deleted sql.NullString
	err := gw.bdb.QueryRowContext(ctx,
		"SELECT mfa_required, deleted_at FROM auth_policy_settings WHERE tenant_id = ? AND org_id = ?",
		gw.tenantID, orgID).Scan(&required, &deleted)
	held := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("read the auth policy override: %v", err)
	}

	_, err = gw.bdb.ExecContext(ctx,
		`INSERT INTO auth_policy_settings (tenant_id, org_id, mfa_required) VALUES (?, ?, 1)
		 ON DUPLICATE KEY UPDATE mfa_required = 1, deleted_at = NULL`, gw.tenantID, orgID)
	if err != nil {
		t.Fatalf("write the auth policy override: %v", err)
	}

	t.Cleanup(func() {
		// t.Context is already cancelled when a cleanup runs, so the restore
		// takes a context of its own.
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		query := "DELETE FROM auth_policy_settings WHERE tenant_id = ? AND org_id = ?"
		args := []any{gw.tenantID, orgID}
		if held {
			query = `UPDATE auth_policy_settings SET mfa_required = ?, deleted_at = ?
			         WHERE tenant_id = ? AND org_id = ?`
			args = []any{required, deleted, gw.tenantID, orgID}
		}
		if _, err := gw.bdb.ExecContext(ctx, query, args...); err != nil {
			t.Errorf("restore the auth policy override: %v", err)
		}
	})
}
