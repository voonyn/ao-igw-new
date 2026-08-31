package oidc_test

// This file drives the portal's Passkey registration end to end, over HTTP,
// against the same routes the server mounts.
//
// It is the first ceremony that runs, so it proves the parts every later ticket
// stands on: the RP ID derived from the verified host, the origin the RP ID must
// cover, the challenge that lives in Redis and is consumed once, and the audit
// row the person reads in their own activity feed.
//
// The device is the software authenticator of authenticator_test.go. The
// production code gains no seam for it: the answer it builds is the answer a
// browser builds, and the real library verifies it.
//
// It shares the gateway, the fixture and the helpers of flow_integration_test.go,
// so it skips on the same environment variable and it creates its own person and
// its own client.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/passkey"
	"alphaomega/identitygateway/internal/utils"
)

// The three account addresses this slice adds, inside the account group.
const (
	accountPasskeysPath      = "/mfa/passkeys"
	accountPasskeyStartPath  = "/mfa/passkeys/register/start"
	accountPasskeyFinishPath = "/mfa/passkeys/register/finish"
)

// budgetProbes bounds the loop that proves the guessing budget refuses a start.
// The budget allows fifteen attempts in a trailing window, so a loop that never
// meets it inside this many is a budget that is not counting.
const budgetProbes = 25

// TestAccountPasskeyFlow registers a Passkey from the portal, under an access
// token and nothing else, and reads it back.
//
// The steps depend on each other, so they run in order and share what the
// earlier steps produced.
func TestAccountPasskeyFlow(t *testing.T) {
	gw := newGateway(t)
	fx := seedFixture(t, gw)

	forAccount := fx.confidential
	forAccount.resource = oidc.ResourceAccountAPI

	// The device the person reads the portal on. Every account call below is
	// made with the token this sign-in minted.
	portal := gw.signIn(t, fx, fx.password)
	held := gw.grant(t, forAccount, portal.token)

	// What the deployment derives from the verified host, and the origin the
	// browser calls from. The tenant domain is a real registrable name, so the
	// RP ID is derived and no override is configured.
	origin := "https://" + gw.domain
	rpID := utils.RegistrableDomain(gw.domain)
	if rpID == "" {
		t.Fatalf("the tenant host %q has no registrable domain", gw.domain)
	}

	t.Run("an account holding no passkey reads an empty list", func(t *testing.T) {
		if rows := gw.passkeys(t, held.AccessToken); len(rows) != 0 {
			t.Errorf("the list answered %d rows, want 0", len(rows))
		}
	})

	t.Run("an origin the rp id does not cover is refused", func(t *testing.T) {
		// A Passkey binds to one domain. A credential created here would be a
		// Factor no sign-in of this tenant could ever answer, so it is refused
		// before a key pair exists.
		//
		// This is the same refusal a misconfigured deployment reads. The portal
		// BFF names its own origin on the start, so a deployment that lists no
		// portal origin in AO_WEBAUTHN_ORIGINS is refused here, with the slug
		// that names the deployment, and no device prompt opens.
		var refused struct {
			Error string `json:"error"`
		}
		answer := gw.account(t, fiber.MethodPost, accountPasskeyStartPath, nil, held.AccessToken,
			fiber.HeaderOrigin, "https://not-this-tenant.example.com")
		decode(t, answer, fiber.StatusBadRequest, &refused)

		if refused.Error != "passkey_origin_refused" {
			t.Errorf("slug is %q, want %q", refused.Error, "passkey_origin_refused")
		}
	})

	t.Run("a request with no origin still runs the ceremony", func(t *testing.T) {
		// A caller that names no origin is not refused. The login BFF is one:
		// it runs at the verified host that resolved the request, which the
		// covered list already holds. The finish still compares the origin the
		// device signed against the origins the RP ID covers, which is where the
		// rule is enforced for every caller.
		var options registrationOptions
		answer := gw.account(t, fiber.MethodPost, accountPasskeyStartPath, nil, held.AccessToken)
		decode(t, answer, fiber.StatusOK, &envelope{Data: &options})

		if options.PublicKey.Challenge == "" {
			t.Error("the start answered no challenge")
		}
	})

	device := newAuthenticator(t)
	options := gw.passkeyStart(t, held.AccessToken, origin)

	t.Run("the options name the derived rp id and the person", func(t *testing.T) {
		if options.PublicKey.RelyingParty.ID != rpID {
			t.Errorf("the options name rp id %q, want %q",
				options.PublicKey.RelyingParty.ID, rpID)
		}
		if options.PublicKey.Challenge == "" {
			t.Error("the options carry no challenge")
		}
		// The user handle is the user id, and no column stores it.
		if want := base64url(fx.userID); options.PublicKey.User.ID != want {
			t.Errorf("the user handle is %q, want %q", options.PublicKey.User.ID, want)
		}
		if len(options.PublicKey.ExcludeCredentials) != 0 {
			t.Errorf("the person holds no passkey and %s", options)
		}
	})

	answer := device.register(t, rpID, origin, options.PublicKey.Challenge)

	t.Run("a wrong answer registers nothing", func(t *testing.T) {
		// The challenge inside the client data is not the one the gateway
		// stored, so the library refuses the answer. Nothing else about the
		// body changes.
		var refused struct {
			Error string `json:"error"`
		}
		decode(t, gw.passkeyFinish(t, held.AccessToken, origin, "Laptop", tamper(t, answer)),
			fiber.StatusUnauthorized, &refused)

		if refused.Error != "passkey_rejected" {
			t.Errorf("slug is %q, want %q", refused.Error, "passkey_rejected")
		}
		if rows := gw.passkeys(t, held.AccessToken); len(rows) != 0 {
			t.Errorf("a refused answer left %d rows behind", len(rows))
		}
	})

	t.Run("the challenge is consumed by the refused answer", func(t *testing.T) {
		// The finish deletes the challenge before it verifies, so one challenge
		// answers one ceremony however that ceremony ends. A captured answer
		// replayed against it finds nothing.
		var refused struct {
			Error string `json:"error"`
		}
		decode(t, gw.passkeyFinish(t, held.AccessToken, origin, "Laptop", answer),
			fiber.StatusConflict, &refused)

		if refused.Error != "passkey_challenge_expired" {
			t.Errorf("slug is %q, want %q", refused.Error, "passkey_challenge_expired")
		}
	})

	var registered passkey.View
	t.Run("a device registers a passkey", func(t *testing.T) {
		// A start replaces the challenge, so a person who lost the first prompt
		// begins again at once.
		options = gw.passkeyStart(t, held.AccessToken, origin)
		fresh := device.register(t, rpID, origin, options.PublicKey.Challenge)

		decode(t, gw.passkeyFinish(t, held.AccessToken, origin, "Work laptop", fresh),
			fiber.StatusCreated, &envelope{Data: &registered})

		if registered.ID != device.credentialID() {
			t.Errorf("the answer names credential %q, want %q",
				registered.ID, device.credentialID())
		}
		if registered.Name != "Work laptop" {
			t.Errorf("the passkey is named %q, want %q", registered.Name, "Work laptop")
		}
		if registered.CreatedAt.IsZero() {
			t.Error("the answer names no added date")
		}
		if registered.LastUsedAt != nil {
			t.Errorf("a passkey that signed nobody in reports a last use of %v", registered.LastUsedAt)
		}
	})

	t.Run("the list answers the live passkey and no key material", func(t *testing.T) {
		rows := gw.passkeys(t, held.AccessToken)
		if len(rows) != 1 {
			t.Fatalf("the list answered %d rows, want 1", len(rows))
		}
		if rows[0].ID != registered.ID || rows[0].Name != "Work laptop" {
			t.Errorf("the list answered %+v, want the registered passkey", rows[0])
		}

		// A list renders the four mapped columns. No public key and no stored
		// blob may reach the person's screen, and this decodes the whole answer
		// into a shape that would carry one.
		var carrying []struct {
			Credential json.RawMessage `json:"credential"`
			PublicKey  json.RawMessage `json:"publicKey"`
		}
		decode(t, gw.account(t, fiber.MethodGet, accountPasskeysPath, nil, held.AccessToken),
			fiber.StatusOK, &envelope{Data: &carrying})
		for _, row := range carrying {
			if len(row.Credential) != 0 || len(row.PublicKey) != 0 {
				t.Errorf("the list carries stored key material: %+v", row)
			}
		}
	})

	t.Run("the exclude list names the device the person already holds", func(t *testing.T) {
		// A device that already registered tells the person so, instead of
		// creating a second key pair for the same account.
		again := gw.passkeyStart(t, held.AccessToken, origin)
		if len(again.PublicKey.ExcludeCredentials) != 1 {
			t.Fatalf("the person holds one passkey and %s", again)
		}
		if got := again.PublicKey.ExcludeCredentials[0].ID; got != device.credentialID() {
			t.Errorf("the exclude list names %q, want %q", got, device.credentialID())
		}
	})

	t.Run("the registration reaches the activity feed", func(t *testing.T) {
		// The Passkey actions never reuse the TOTP names. The trail is the only
		// record that a Factor existed.
		var events []audit.ActivityView
		decode(t, gw.account(t, fiber.MethodGet, "/activity", nil, held.AccessToken),
			fiber.StatusOK, &envelope{Data: &events})

		for _, event := range events {
			if event.Action == string(audit.ActionMFAPasskeyRegistered) {
				return
			}
		}
		t.Errorf("no %s event in the activity feed", audit.ActionMFAPasskeyRegistered)
	})

	t.Run("a ceremony start spends the shared guessing budget", func(t *testing.T) {
		// One budget covers both Second Factors, and a start is the request that
		// costs the gateway work. Without it, a valid token asks for challenges
		// without end.
		//
		// It runs last, because it spends what every step above left. The bound
		// is well over the limit, so a budget that never refuses fails here
		// instead of looping.
		var refused struct {
			Error string `json:"error"`
		}
		for range budgetProbes {
			answer := gw.account(t, fiber.MethodPost, accountPasskeyStartPath, nil,
				held.AccessToken, fiber.HeaderOrigin, origin)
			if answer.StatusCode != fiber.StatusTooManyRequests {
				continue
			}

			decode(t, answer, fiber.StatusTooManyRequests, &refused)
			if refused.Error != "rate_limited" {
				t.Errorf("slug is %q, want %q", refused.Error, "rate_limited")
			}
			return
		}
		t.Errorf("%d ceremony starts never met the guessing budget", budgetProbes)
	})

	t.Run("an unauthenticated caller reads nothing", func(t *testing.T) {
		var refused struct {
			Error string `json:"error"`
		}
		decode(t, gw.do(t, fiber.MethodGet, accountPrefix+accountPasskeysPath, nil),
			fiber.StatusUnauthorized, &refused)

		if refused.Error != "unauthenticated" {
			t.Errorf("slug is %q, want %q", refused.Error, "unauthenticated")
		}
	})
}

// passkeys reads the live Passkeys of the caller.
func (g *gateway) passkeys(t *testing.T, accessToken string) []passkey.View {
	t.Helper()

	var rows []passkey.View
	decode(t, g.account(t, fiber.MethodGet, accountPasskeysPath, nil, accessToken),
		fiber.StatusOK, &envelope{Data: &rows})
	return rows
}

// passkeyStart runs one registration start and reads the ceremony options.
func (g *gateway) passkeyStart(t *testing.T, accessToken, origin string) registrationOptions {
	t.Helper()

	var options registrationOptions
	decode(t, g.account(t, fiber.MethodPost, accountPasskeyStartPath, nil, accessToken,
		fiber.HeaderOrigin, origin), fiber.StatusOK, &envelope{Data: &options})
	return options
}

// passkeyFinish sends one registration answer. The caller decodes the response,
// because half the calls below expect a refusal.
func (g *gateway) passkeyFinish(
	t *testing.T, accessToken, origin, name string, answer json.RawMessage,
) *http.Response {
	t.Helper()

	body, err := json.Marshal(map[string]any{"name": name, "credential": answer})
	if err != nil {
		t.Fatalf("encode the finish body: %v", err)
	}

	return g.account(t, fiber.MethodPost, accountPasskeyFinishPath,
		bytes.NewReader(body), accessToken,
		fiber.HeaderContentType, fiber.MIMEApplicationJSON, fiber.HeaderOrigin, origin)
}

// base64url spells one user handle the way the ceremony options carry it. The
// handle is the user id, and the library encodes it for the browser.
func base64url(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
