package oidc_test

// This file drives the portal's second-factor enrolment end to end, over HTTP,
// against the same routes the server mounts.
//
// Three things are only testable here. The access token is the whole proof: no
// login session is in flight, and the bearer guard names the person. The
// provisioning URI the portal answers is the one the sign-in answers, label for
// label. The enrolment reaches the person's own activity feed, because the audit
// row the shared body writes is the row that feed already renders.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/oidc"
)

// The three account addresses this slice adds, inside the account group.
const (
	accountMFAPath         = "/mfa"
	accountEnrolStartPath  = "/mfa/totp/enroll/start"
	accountEnrolActivePath = "/mfa/totp/enroll/activate"
)

// mfaStatus is the answer the portal reads to decide what the security page
// shows. It names no secret and no code, and this test proves that by decoding
// the whole answer into a shape that would carry one.
type mfaStatus struct {
	Active                 bool   `json:"active"`
	ActivatedAt            string `json:"activatedAt"`
	RecoveryCodesRemaining int    `json:"recoveryCodesRemaining"`

	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauthUri"`
	Code       string `json:"code"`
}

// TestAccountMFAFlow enrols a Second Factor from the portal, under an access
// token and nothing else.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestAccountMFAFlow(t *testing.T) {
	gw := newGateway(t)
	fx := seedFixture(t, gw)

	forAccount := fx.confidential
	forAccount.resource = oidc.ResourceAccountAPI

	// The device the person reads the portal on. Every account call below is
	// made with the token this sign-in minted.
	portal := gw.signIn(t, fx, fx.password)
	held := gw.grant(t, forAccount, portal.token)

	t.Run("an account holding no factor reads as none", func(t *testing.T) {
		state := gw.mfaStatus(t, held.AccessToken)
		if state.Active {
			t.Error("the account holds no factor and the status says it does")
		}
		if state.RecoveryCodesRemaining != 0 {
			t.Errorf("recovery codes remaining is %d, want 0", state.RecoveryCodesRemaining)
		}
		if state.ActivatedAt != "" {
			t.Errorf("activatedAt is %q, want no key at all", state.ActivatedAt)
		}
	})

	// The sign-in path's answer for the same person, read from a second sign-in
	// of their own. It is the value the portal's answer is measured against.
	signIn := gw.enrolStart(t, gw.signIn(t, fx, fx.password).token)

	started := gw.accountEnrolStart(t, held.AccessToken)

	t.Run("the provisioning uri is the one the sign-in produces", func(t *testing.T) {
		if started.OtpauthURI == "" || started.Secret == "" {
			t.Fatalf("start answered %+v", started)
		}

		// Everything but the secret. The two starts mint one secret each, and
		// the labels around it are what must be identical: the tenant on the
		// issuer, and the person on the account name.
		want := labelsOf(t, signIn.OtpauthURI)
		got := labelsOf(t, started.OtpauthURI)
		if got != want {
			t.Errorf("the portal provisions %q and the sign-in provisions %q", got, want)
		}
		if !strings.Contains(got, fx.email) {
			t.Errorf("the provisioning uri %q does not name the person", got)
		}
	})

	t.Run("the status still reads as no factor", func(t *testing.T) {
		// A start records nothing. A page that called a pending secret a factor
		// would tell the person they are protected when nobody has proved a code.
		if gw.mfaStatus(t, held.AccessToken).Active {
			t.Error("a pending enrolment reads as an active factor")
		}
	})

	t.Run("a wrong code activates nothing", func(t *testing.T) {
		var refused struct {
			Error string `json:"error"`
		}
		answer := gw.account(t, fiber.MethodPost, accountEnrolActivePath,
			strings.NewReader(`{"code":"000000"}`), held.AccessToken,
			fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		decode(t, answer, fiber.StatusUnauthorized, &refused)

		if refused.Error != "invalid_credentials" {
			t.Errorf("slug is %q, want %q", refused.Error, "invalid_credentials")
		}
		if gw.mfaStatus(t, held.AccessToken).Active {
			t.Error("a refused code left an active factor behind")
		}
	})

	var codes []string
	t.Run("a code from the authenticator activates the factor", func(t *testing.T) {
		var activated struct {
			RecoveryCodes []string `json:"recoveryCodes"`
		}
		answer := gw.account(t, fiber.MethodPost, accountEnrolActivePath,
			strings.NewReader(fmt.Sprintf(`{"code":%q}`, code(t, started.Secret))),
			held.AccessToken, fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		decode(t, answer, fiber.StatusOK, &envelope{Data: &activated})

		codes = activated.RecoveryCodes
		if len(codes) != recoveryCodesIssued {
			t.Fatalf("activation answered %d recovery codes, want %d", len(codes), recoveryCodesIssued)
		}
	})

	t.Run("the status reads the live factor", func(t *testing.T) {
		state := gw.mfaStatus(t, held.AccessToken)
		if !state.Active {
			t.Fatal("the factor is activated and the status says it is not")
		}
		if state.ActivatedAt == "" {
			t.Error("the status names no activation time")
		}
		if state.RecoveryCodesRemaining != recoveryCodesIssued {
			t.Errorf("recovery codes remaining is %d, want %d",
				state.RecoveryCodesRemaining, recoveryCodesIssued)
		}
		// The status is what a page renders. Neither credential may reach it.
		if state.Secret != "" || state.OtpauthURI != "" || state.Code != "" {
			t.Errorf("the status carries a credential: %+v", state)
		}
	})

	t.Run("a second enrolment is refused", func(t *testing.T) {
		var refused struct {
			Error string `json:"error"`
		}
		answer := gw.account(t, fiber.MethodPost, accountEnrolStartPath, nil, held.AccessToken)
		decode(t, answer, fiber.StatusConflict, &refused)

		if refused.Error != "mfa_already_enrolled" {
			t.Errorf("slug is %q, want %q", refused.Error, "mfa_already_enrolled")
		}
	})

	t.Run("the enrolment reaches the activity feed", func(t *testing.T) {
		var events []audit.ActivityView
		decode(t, gw.account(t, fiber.MethodGet, "/activity", nil, held.AccessToken),
			fiber.StatusOK, &envelope{Data: &events})

		for _, event := range events {
			if event.Action == string(audit.ActionMFAEnrolled) {
				return
			}
		}
		t.Errorf("no %s event in the activity feed", audit.ActionMFAEnrolled)
	})

	t.Run("an unauthenticated caller reads nothing", func(t *testing.T) {
		var refused struct {
			Error string `json:"error"`
		}
		decode(t, gw.do(t, fiber.MethodGet, accountPrefix+accountMFAPath, nil),
			fiber.StatusUnauthorized, &refused)

		if refused.Error != "unauthenticated" {
			t.Errorf("slug is %q, want %q", refused.Error, "unauthenticated")
		}
	})
}

// mfaStatus reads the second-factor state of the caller.
func (g *gateway) mfaStatus(t *testing.T, accessToken string) mfaStatus {
	t.Helper()

	var state mfaStatus
	decode(t, g.account(t, fiber.MethodGet, accountMFAPath, nil, accessToken),
		fiber.StatusOK, &envelope{Data: &state})
	return state
}

// accountEnrolStart runs one portal enrolment start and reads the answer.
func (g *gateway) accountEnrolStart(t *testing.T, accessToken string) struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauthUri"`
} {
	t.Helper()

	var started struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauthUri"`
	}
	decode(t, g.account(t, fiber.MethodPost, accountEnrolStartPath, nil, accessToken),
		fiber.StatusOK, &envelope{Data: &started})
	return started
}

// labelsOf is one provisioning URI with the secret taken out: the scheme, the
// path an Authenticator prints, and the issuer beside it.
//
// The secret differs between two starts by design, and every other part of the
// URI is what tells a person which account the code belongs to.
func labelsOf(t *testing.T, uri string) string {
	t.Helper()

	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse the provisioning uri %q: %v", uri, err)
	}

	query := parsed.Query()
	query.Del("secret")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
