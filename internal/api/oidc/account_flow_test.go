package oidc_test

// This file drives the self-service account API end to end, over HTTP, against
// the same routes the server mounts.
//
// Four things are only testable here. The audience gate refuses a token minted
// for the admin API. The tenant is resolved from the host of the request. Every
// answer carries the one response envelope. A revoke reaches the grants of the
// login session it ends. A service test sees none of them.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/session"
)

// accountPrefix is where the portal reaches the account API.
const accountPrefix = "/api/v1/account"

// loginSession is one sign-in of the test person: the id the account API names
// it by, and the token the login steps carry.
type loginSession struct {
	id    string
	token string
}

// TestAccountAPIFlow signs one person in on three devices, reads their login
// sessions, ends one of them, and changes the password.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestAccountAPIFlow(t *testing.T) {
	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// One registration, two audiences. The resource parameter is per request,
	// so the same client mints a token for either API.
	forAccount := fx.confidential
	forAccount.resource = oidc.ResourceAccountAPI
	forAdmin := fx.confidential
	forAdmin.resource = oidc.ResourceAdminAPI

	// The device the person keeps. Every call below is made from this one.
	mine := gw.signIn(t, fx, fx.password)
	held := gw.grant(t, forAccount, mine.token)

	t.Run("the token names the account API", func(t *testing.T) {
		claims := jwtClaims(t, held.AccessToken)
		if got := audienceOf(claims["aud"]); got != oidc.ResourceAccountAPI {
			t.Errorf("aud is %v, want %q", claims["aud"], oidc.ResourceAccountAPI)
		}

		// The sid claim names the login session the token was minted in. The
		// portal reads it there and sends it as the session to keep.
		if sid, _ := jwtClaims(t, held.IDToken)["sid"].(string); sid != mine.id {
			t.Errorf("sid is %q, want the login session %q", sid, mine.id)
		}
	})

	t.Run("a token of the admin API is refused", func(t *testing.T) {
		other := gw.grant(t, forAdmin, mine.token)

		var refused struct {
			Error string `json:"error"`
		}
		answer := gw.account(t, fiber.MethodGet, "/sessions", nil, other.AccessToken)
		decode(t, answer, fiber.StatusUnauthorized, &refused)
		if refused.Error != "unauthenticated" {
			t.Errorf("slug is %q, want %q", refused.Error, "unauthenticated")
		}
	})

	// The second device. It holds a grant of its own, which the revoke below
	// must take with it.
	second := gw.signIn(t, fx, fx.password)
	theirs := gw.grant(t, forAccount, second.token)

	t.Run("list own login sessions", func(t *testing.T) {
		live := gw.sessions(t, held.AccessToken)
		if !live[mine.id] || !live[second.id] {
			t.Fatalf("the list holds %v, want both %q and %q", keysOf(live), mine.id, second.id)
		}
	})

	t.Run("revoke the second device", func(t *testing.T) {
		var ended session.RevokedView
		answer := gw.account(t, fiber.MethodDelete, "/sessions/"+second.id, nil, held.AccessToken)
		decode(t, answer, fiber.StatusOK, &envelope{Data: &ended})

		if ended.Sessions != 1 {
			t.Errorf("the answer ended %d sessions, want 1", ended.Sessions)
		}
		if ended.Grants < 1 {
			t.Errorf("the answer ended %d grants, want at least 1", ended.Grants)
		}

		// The grant died with the session, so the refresh token of that device
		// buys nothing any more. That is the fact read from outside.
		gw.expectDeadRefreshToken(t, fx.confidential, theirs.RefreshToken)

		live := gw.sessions(t, held.AccessToken)
		if live[second.id] {
			t.Errorf("the revoked session %q is still listed", second.id)
		}
		if !live[mine.id] {
			t.Errorf("the caller's session %q is gone", mine.id)
		}
	})

	// A third device, so the password change has another session to end.
	third := gw.signIn(t, fx, fx.password)

	t.Run("change the password", func(t *testing.T) {
		next := randomString(t) + "aA1!"

		body := fmt.Sprintf(`{"currentPassword":%q,"newPassword":%q}`, fx.password, next)
		answer := gw.account(t, fiber.MethodPost, "/password?except="+url.QueryEscape(mine.id),
			strings.NewReader(body), held.AccessToken,
			fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		if answer.StatusCode != fiber.StatusOK {
			t.Fatalf("status %d, want %d: %s", answer.StatusCode, fiber.StatusOK, readAll(t, answer))
		}

		// Every other device signed out, and the device that asked stayed
		// signed in.
		live := gw.sessions(t, held.AccessToken)
		if live[third.id] {
			t.Errorf("the third device %q outlived the password change", third.id)
		}
		if !live[mine.id] {
			t.Errorf("the caller's session %q ended with the others", mine.id)
		}

		// The new password is what signs the person in now.
		fx.password = next
		gw.signIn(t, fx, next)
	})
}

// signIn walks the two login steps and returns the login session they opened.
// The token is the one the password step rotated to.
func (g *gateway) signIn(t *testing.T, fx fixture, password string) loginSession {
	t.Helper()

	var opened struct {
		SessionID    string `json:"sessionId"`
		SessionToken string `json:"sessionToken"`
	}
	g.login(t, "/identifier", fmt.Sprintf(`{"identifier":%q}`, fx.email), "", &opened)
	if opened.SessionID == "" || opened.SessionToken == "" {
		t.Fatalf("identifier answered %+v", opened)
	}

	var verified struct {
		SessionToken string `json:"sessionToken"`
	}
	g.login(t, "/password", fmt.Sprintf(`{"password":%q}`, password), opened.SessionToken, &verified)
	if verified.SessionToken == "" {
		t.Fatal("password answered no session token")
	}

	return loginSession{id: opened.SessionID, token: verified.SessionToken}
}

// account calls one route of the account API with one access token.
func (g *gateway) account(
	t *testing.T, method, path string, body io.Reader, accessToken string, header ...string,
) *http.Response {
	t.Helper()

	header = append(header, fiber.HeaderAuthorization, "Bearer "+accessToken)
	return g.do(t, method, accountPrefix+path, body, header...)
}

// sessions reads the live login sessions of the caller, as a set of ids.
func (g *gateway) sessions(t *testing.T, accessToken string) map[string]bool {
	t.Helper()

	var rows []session.AccountSession
	decode(t, g.account(t, fiber.MethodGet, "/sessions", nil, accessToken),
		fiber.StatusOK, &envelope{Data: &rows})

	live := make(map[string]bool, len(rows))
	for _, row := range rows {
		live[row.ID] = true
	}
	return live
}

// expectDeadRefreshToken presents one refresh token and expects the refusal a
// revoked grant answers with.
func (g *gateway) expectDeadRefreshToken(t *testing.T, cl clientFixture, refreshToken string) {
	t.Helper()

	var refused struct {
		Error string `json:"error"`
	}
	answer := g.oidc(t, fiber.MethodPost, "/token",
		strings.NewReader(url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
		}.Encode()),
		fiber.HeaderContentType, formType,
		fiber.HeaderAuthorization, basicAuth(cl))
	decode(t, answer, fiber.StatusBadRequest, &refused)

	if refused.Error != "invalid_grant" {
		t.Errorf("error is %q, want %q", refused.Error, "invalid_grant")
	}
}

// audienceOf reads the aud claim, which is one string or a list of them.
func audienceOf(claim any) string {
	switch value := claim.(type) {
	case string:
		return value
	case []any:
		if len(value) > 0 {
			first, _ := value[0].(string)
			return first
		}
	}
	return ""
}

// keysOf names what a set holds, for a failure message.
func keysOf(set map[string]bool) []string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	return names
}
