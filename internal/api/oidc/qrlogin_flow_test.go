package oidc_test

// This file drives QR Login end to end, over HTTP, against the same routes the
// server mounts.
//
// The flow crosses three parties. The browser starts the transaction and polls
// it. The Scan Verifier pushes the result to a callback that sits outside the
// tenant lookup and behind a credential of its own. The person arrives on an
// authorization request, and the sign-in must finish it.
//
// A stand-in Scan Verifier serves the one outbound call, so the test needs no
// vendor and no network. It answers a code object with a field the gateway does
// not model, which proves that the object reaches the browser unchanged.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/qrlogin"
	"alphaomega/identitygateway/internal/utils"
)

// qrStartPath and qrPollPath are the two browser steps, inside the login group.
const (
	qrStartPath = "/qr/start"
	qrPollPath  = "/qr/poll"
)

// qrCallbackPath is where the Scan Verifier pushes its result. It is spelled out
// because it is the address a third party is configured with: a change here is a
// change the vendor must be told about.
const qrCallbackPath = "/api/v1/di/callback"

// The credential the stand-in Scan Verifier presents on the callback. It lives
// only inside the test process.
const (
	testCallbackID     = "qr-flow-test-callback"
	testCallbackSecret = "qr-flow-test-callback-secret"
)

// initializePath is the one operation the gateway calls out with.
const initializePath = "/initializeVPTransaction"

// qrExtraField is a field of the code object that the gateway does not model. It
// must still reach the browser, because the sign-in page renders the fallback
// link out of fields like it.
const qrExtraField = "https://wallet.example/fallback"

// scanVerifier stands in for the Scan Verifier. It answers the start call and it
// keeps the nonce it was given, so the test can push that nonce back the way the
// real verifier does.
type scanVerifier struct {
	url string

	sessionID      string
	presentationID string

	mu    sync.Mutex
	nonce string
}

// newScanVerifier starts the stand-in and stops it when the test ends.
func newScanVerifier(t *testing.T) *scanVerifier {
	t.Helper()

	v := &scanVerifier{
		sessionID:      utils.NewUUIDv7(),
		presentationID: utils.NewUUIDv7(),
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != initializePath {
			http.NotFound(w, r)
			return
		}

		var asked struct {
			Nonce string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&asked); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		v.mu.Lock()
		v.nonce = asked.Nonce
		v.mu.Unlock()

		w.Header().Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		fmt.Fprintf(w, `{"data":{"presentation_id":%q,"qr_code":{"session_id":%q,"fallback_link":%q}}}`,
			v.presentationID, v.sessionID, qrExtraField)
	}))
	t.Cleanup(server.Close)

	v.url = server.URL
	return v
}

// mintedNonce is the nonce the gateway bound this transaction to.
func (v *scanVerifier) mintedNonce(t *testing.T) string {
	t.Helper()

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.nonce == "" {
		t.Fatal("the stand-in verifier was never asked for a transaction")
	}
	return v.nonce
}

// push is the body of one result push, in the shape the vendor sends.
func (v *scanVerifier) push(nonce, username string) string {
	return fmt.Sprintf(
		`{"stateWord":"0","presentationId":%q,"session_id":%q,"message":"success",
		  "DecodedVpToken":{"Username":%q,"Nonce":%q}}`,
		v.presentationID, v.sessionID, username, nonce)
}

// TestQRLoginFlow walks one person from an authorization request to tokens,
// with a scan in place of a password.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestQRLoginFlow(t *testing.T) {
	skipUnlessIntegration(t)

	verifier := newScanVerifier(t)

	// The integration is turned on for this test alone, and it is pointed at the
	// stand-in. An environment variable already set wins over the .env file, so
	// these values reach the configuration newGateway loads.
	t.Setenv("AO_DI_ENABLED", "true")
	t.Setenv("AO_DI_BASE_URL", verifier.url)
	t.Setenv("AO_DI_CALLBACK_CLIENT_ID", testCallbackID)
	t.Setenv("AO_DI_CALLBACK_CLIENT_SECRET", testCallbackSecret)

	gw := newGateway(t)
	fx := seedFixture(t, gw)

	// A QR Login is exempt from the MFA Requirement, so the whole run happens
	// with the requirement on. A Wallet presentation is a possession factor
	// already, and the poll answers pending, authenticated, or expired, with no
	// room to name a step still owed. See ADR 0011.
	setMFARequired(t, gw, fx.orgID, true)

	// Where the person arrives. The browser is at the sign-in page with this
	// authorization request named on the query, and the scan must finish it.
	auth := gw.startAuthorization(t, fx.confidential)

	var started struct {
		SessionID    string          `json:"sessionId"`
		SessionToken string          `json:"sessionToken"`
		QRCode       json.RawMessage `json:"qrCode"`
		ExpiresIn    int             `json:"expiresIn"`
	}
	gw.login(t, qrStartPath, "{}", "", &started)
	if started.SessionID == "" || started.SessionToken == "" {
		t.Fatalf("start answered %+v", started)
	}
	deleteTransactions(t, gw, started.SessionID)

	t.Run("start hands the browser the code object of the verifier", func(t *testing.T) {
		var code map[string]any
		if err := json.Unmarshal(started.QRCode, &code); err != nil {
			t.Fatalf("decode the code object: %v: %s", err, started.QRCode)
		}
		if code["session_id"] != verifier.sessionID {
			t.Errorf("session_id is %v, want %q", code["session_id"], verifier.sessionID)
		}
		// The field the gateway does not model survived. A re-encode would drop
		// it, and the sign-in page would lose its fallback link.
		if code["fallback_link"] != qrExtraField {
			t.Errorf("fallback_link is %v, want %q", code["fallback_link"], qrExtraField)
		}
		// The gateway adds no identifier of its own to the code object. The
		// stand-in decides what the object holds, so this pins the gateway and
		// not the vendor: the presentation identifier addresses the transaction
		// on the callback, and a browser that held it could assert a scan.
		if strings.Contains(string(started.QRCode), verifier.presentationID) {
			t.Error("the code object carries the presentation identifier of the verifier")
		}
		if started.ExpiresIn <= 0 {
			t.Errorf("expiresIn is %d, want a positive number of seconds", started.ExpiresIn)
		}
	})

	body := verifier.push(verifier.mintedNonce(t), fx.username)

	t.Run("the callback is refused without the credential", func(t *testing.T) {
		for _, header := range []struct {
			name  string
			value string
		}{
			{name: "no credential"},
			{name: "the wrong secret", value: basicHeader(testCallbackID, "not-the-secret")},
			{name: "the login credential", value: basicHeader(testLoginPAT, testLoginPAT)},
		} {
			t.Run(header.name, func(t *testing.T) {
				var refused struct {
					Error string `json:"error"`
				}
				answer := gw.callback(t, body, header.value)
				decode(t, answer, fiber.StatusUnauthorized, &refused)
				if refused.Error != "unauthenticated" {
					t.Errorf("slug is %q, want %q", refused.Error, "unauthenticated")
				}
			})
		}

		// The refusals changed nothing, so the transaction is still pending.
		if status := gw.poll(t, started.SessionToken).Status; status != qrlogin.StatusPending {
			t.Errorf("status is %q, want %q", status, qrlogin.StatusPending)
		}
	})

	t.Run("the pushed result signs the person in", func(t *testing.T) {
		answer := gw.callback(t, body, basicHeader(testCallbackID, testCallbackSecret))
		if answer.StatusCode != fiber.StatusOK {
			t.Fatalf("status %d, want %d: %s", answer.StatusCode, fiber.StatusOK, readAll(t, answer))
		}
	})

	// The poll that steps the login session to authenticated. It is the only one
	// that hands out a token, so the value is kept for every step below.
	polled := gw.poll(t, started.SessionToken)

	t.Run("the poll rotates the session token", func(t *testing.T) {
		if polled.Status != qrlogin.StatusAuthenticated {
			t.Fatalf("status is %q, want %q", polled.Status, qrlogin.StatusAuthenticated)
		}
		if polled.SessionToken == "" {
			t.Fatal("the poll answered no rotated session token")
		}
		if polled.SessionToken == started.SessionToken {
			t.Fatal("the poll answered the token it was called with")
		}

		// The token the browser started with is dead. A rotation that left the
		// old value usable would leave a credential behind on every sign-in.
		var refused struct {
			Error string `json:"error"`
		}
		answer := gw.do(t, fiber.MethodPost, loginPath(qrPollPath), strings.NewReader("{}"),
			gw.loginHeader(started.SessionToken, fiber.MIMEApplicationJSON)...)
		decode(t, answer, fiber.StatusUnauthorized, &refused)
		if refused.Error != "unauthenticated" {
			t.Errorf("slug is %q, want %q", refused.Error, "unauthenticated")
		}

		// A later poll on the live token reports the same state and rotates
		// nothing. The browser already holds the token it needs.
		again := gw.poll(t, polled.SessionToken)
		if again.Status != qrlogin.StatusAuthenticated {
			t.Errorf("status is %q, want %q", again.Status, qrlogin.StatusAuthenticated)
		}
		if again.SessionToken != "" {
			t.Error("a later poll rotated the token a second time")
		}
	})

	t.Run("the authorization request the person arrived on completes", func(t *testing.T) {
		issued := gw.finish(t, fx.confidential, auth, polled.SessionToken)
		if issued.AccessToken == "" || issued.IDToken == "" {
			t.Fatalf("the token endpoint answered %+v", issued)
		}

		// The sid claim names the login session the scan authenticated, so the
		// tokens belong to that sign-in and not to another one.
		if sid, _ := jwtClaims(t, issued.IDToken)["sid"].(string); sid != started.SessionID {
			t.Errorf("sid is %q, want the login session %q", sid, started.SessionID)
		}
		// The person the scan named is the subject the tokens carry.
		if sub, _ := jwtClaims(t, issued.IDToken)["sub"].(string); sub != fx.userID {
			t.Errorf("sub is %q, want the person %q", sub, fx.userID)
		}
	})
}

// poll runs one browser poll and reads the answer.
func (g *gateway) poll(t *testing.T, token string) qrlogin.PollResponse {
	t.Helper()

	var polled qrlogin.PollResponse
	g.login(t, qrPollPath, "{}", token, &polled)
	return polled
}

// callback pushes one result the way the Scan Verifier does. The address carries
// no tenant, and credential is the whole Authorization header, empty for a push
// that presents none.
func (g *gateway) callback(t *testing.T, body, credential string) *http.Response {
	t.Helper()

	header := []string{fiber.HeaderContentType, fiber.MIMEApplicationJSON}
	if credential != "" {
		header = append(header, fiber.HeaderAuthorization, credential)
	}
	return g.do(t, fiber.MethodPost, qrCallbackPath, strings.NewReader(body), header...)
}

// loginPath is the full address of one login step.
func loginPath(step string) string { return "/api/v1/login" + step }

// basicHeader renders one HTTP Basic credential.
func basicHeader(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

// deleteTransactions removes the QR Login transactions of one login session when
// the test ends. The rows are consumed, not entities, so they are hard deleted.
func deleteTransactions(t *testing.T, gw *gateway, loginSessionID string) {
	t.Helper()

	t.Cleanup(func() {
		// t.Context is already cancelled when a cleanup runs, so the delete takes
		// a context of its own.
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		_, err := gw.bdb.NewRaw(
			"DELETE FROM qr_login_transactions WHERE login_session_id = ?", loginSessionID).Exec(ctx)
		if err != nil {
			t.Errorf("clean up qr_login_transactions: %v", err)
		}
	})
}
