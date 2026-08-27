// Package di is the outbound HTTP client for the Scan Verifier, the external
// service behind QR Login and DI Enrolment.
//
// The package is not a domain package, although it sits beside them. It holds no
// model, no repository, and no tenant. It holds an HTTP client and two round
// trips. It sits under internal/ because the tenant isolation gate of CI reads
// ./internal/... only.
//
// The client has two operations: start a verifiable-presentation transaction, and
// enrol a person. It never reads a result back. The Scan Verifier pushes the
// result of a scan to a callback instead. See
// docs/adr/0008-scan-verifier-push-callback.md.
//
// The paths and the field names below are the one place to change if the contract
// of the vendor differs.
package di

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The operation paths, joined onto the configured base address.
const (
	initializePath = "/initializeVPTransaction"
	enrolUserPath  = "/api/v2/account/enrolUser"
)

// defaultTimeout bounds one round trip when the configuration names none.
const defaultTimeout = 10 * time.Second

// defaultInputDescriptorID is the presentation-definition descriptor id used when
// the configuration names none. The Scan Verifier matches the credential by this
// id, so a vendor that renames it makes every start fail until it is overridden.
const defaultInputDescriptorID = "identity"

// requestAudience is the audience the Scan Verifier binds the presentation to.
// The only consumer is QR Login for a person.
// ponytail: make it configuration the day a different audience exists.
const requestAudience = "user"

// The identity-document fields an enrolment requires and this gateway does not
// model. This gateway knows a username, not a document type and not an issuing
// country. They are constants and not configuration, because there is one Scan
// Verifier and a value that never varies is not configuration.
// ponytail: promote to AO_DI_ID_TYPE and AO_DI_COUNTRY_ID the day a second
// deployment enrols against a different document type or country.
const (
	enrolIDType    = "NEW_MYKAD"
	enrolCountryID = "9574"
)

// enrolVerifiedBy is the attester recorded against a verified email address. The
// vocabulary belongs to the Scan Verifier. This gateway is the SPASS side.
const enrolVerifiedBy = "SPASS"

// enrolTimeLayout is the timestamp format of the verifiedAt field.
const enrolTimeLayout = "2006-01-02 15:04:05"

// maxResponseBytes caps how much of an answer is read. The Scan Verifier is a
// third party. An unbounded read makes the memory of this deployment its
// decision.
const maxResponseBytes = 1 << 20

// Client talks to the Scan Verifier. Build it with New. The zero value does not
// work.
type Client struct {
	http         *http.Client
	baseURL      string
	clientID     string
	clientSecret string
	descriptorID string
	log          logger.Logger
}

// New builds a Client from the deployment settings. A timeout that is not
// positive falls back to defaultTimeout, and an empty descriptor id falls back to
// defaultInputDescriptorID. A trailing slash on the address is trimmed, so the
// path constants join cleanly. The logger can be nil, and the round-trip line is
// then not written.
func New(cfg config.DIConfig, log logger.Logger) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	descriptorID := cfg.InputDescriptorID
	if descriptorID == "" {
		descriptorID = defaultInputDescriptorID
	}
	return &Client{
		http:         &http.Client{Timeout: timeout},
		baseURL:      strings.TrimRight(cfg.BaseURL, "/"),
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		descriptorID: descriptorID,
		log:          log,
	}
}

// requestCredentials returns the caller credentials in the shape the Scan
// Verifier expects: in the JSON body, in camel case. An empty half is left out
// rather than sent blank, so a deployment that configured nothing reads the
// answer "client id is required" instead of a refusal of an empty string.
func (c *Client) requestCredentials() map[string]any {
	out := map[string]any{}
	if c.clientID != "" {
		out["clientId"] = c.clientID
	}
	if c.clientSecret != "" {
		out["clientSecret"] = c.clientSecret
	}
	return out
}

// loginPresentationDefinition is what the wallet is asked to present: the one
// claim QR Login resolves against the username of a person. limit_disclosure
// tells the wallet to release nothing else.
//
// ponytail: one credential type stands behind QR Login, so the claim path and the
// ES256 algorithm are fixed. Make them configuration the day a tenant needs
// something else. Note the two spellings: the envelope around the definition is
// camel case, and the definition itself is DIF Presentation Exchange and stays
// snake case. The Scan Verifier refuses either half spelled the other way.
func (c *Client) loginPresentationDefinition() map[string]any {
	return map[string]any{
		"id": uuid.NewString(),
		"input_descriptors": []map[string]any{{
			"id": c.descriptorID,
			"format": map[string]any{"vc+sd-jwt": map[string]any{
				"sd-jwt_alg_values": []string{"ES256"},
			}},
			"constraints": map[string]any{
				"limit_disclosure": "required",
				"fields": []map[string]any{
					{
						"path":   []string{"$.vct"},
						"filter": map[string]any{"type": "string", "const": c.descriptorID},
					},
					{"path": []string{"$.username.value"}, "optional": false},
				},
			},
		}},
	}
}

// Transaction is a started verifiable-presentation transaction. The Scan Verifier
// mints both identifiers, and this gateway only stores them.
type Transaction struct {
	// PresentationID is the handle of the Scan Verifier. It stays on the server
	// and never reaches the browser.
	PresentationID string
	// SessionID is the per-transaction identifier the wallet echoes, and the one
	// the push callback names the transaction by. It is a fourth meaning of the
	// word "session" in this system. It is neither a Login Session nor an Authn
	// Session.
	SessionID string
	// QRCode is the qr_code object of the answer, unchanged. The browser receives
	// it as it arrived. A re-encode drops every field the Scan Verifier adds,
	// including the fallback link the sign-in page offers as "no app?".
	QRCode json.RawMessage
}

// InitializeVPTransaction starts a transaction, binds it to nonce, and returns the
// two identifiers of the Scan Verifier with the wallet-facing qr_code object.
func (c *Client) InitializeVPTransaction(ctx context.Context, nonce string) (Transaction, error) {
	req := map[string]any{
		"aud":                    requestAudience,
		"nonce":                  nonce,
		"presentationDefinition": c.loginPresentationDefinition(),
	}
	for k, v := range c.requestCredentials() {
		req[k] = v
	}
	body, err := json.Marshal(req)
	if err != nil {
		return Transaction{}, fmt.Errorf("di: encode initialize request: %w", err)
	}

	var out struct {
		Data struct {
			PresentationID string          `json:"presentation_id"`
			QRCode         json.RawMessage `json:"qr_code"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, initializePath, body, &out); err != nil {
		return Transaction{}, err
	}

	var qr struct {
		SessionID string `json:"session_id"`
	}
	if len(out.Data.QRCode) > 0 {
		if err := json.Unmarshal(out.Data.QRCode, &qr); err != nil {
			return Transaction{}, fmt.Errorf("di: decode qr_code: %w", err)
		}
	}
	// Both identifiers carry load. One addresses the transaction on the callback,
	// and the other addresses it on the verifier API. A half-filled answer is a
	// failure, and not a transaction with an empty column.
	if out.Data.PresentationID == "" || qr.SessionID == "" {
		return Transaction{}, errors.New("di: initialize response is missing presentation_id or qr_code.session_id")
	}
	return Transaction{
		PresentationID: out.Data.PresentationID,
		SessionID:      qr.SessionID,
		QRCode:         out.Data.QRCode,
	}, nil
}

// EnrolUser is a person this gateway provisioned, in the shape the account API of
// the Scan Verifier takes. IDNumber is the document number the account is keyed
// by, and it is the username of the person. The username is also the one claim QR
// Login resolves a scan against. An enrolment under anything else mints a wallet
// credential that does not match the account it was minted for.
type EnrolUser struct {
	FullName      string
	IDNumber      string
	Email         string // left out of the request when empty
	EmailVerified bool
	VerifiedAt    time.Time // read only when EmailVerified. Zero means now.
}

// EnrolUser registers a person with the Scan Verifier and returns the identifier
// the Scan Verifier keeps for them.
//
// Only the fields this gateway knows are sent. The address, phone, directory, and
// demographic blocks are optional, and this gateway has nothing to put in them.
func (c *Client) EnrolUser(ctx context.Context, u EnrolUser) (string, error) {
	if u.IDNumber == "" {
		return "", errors.New("di: enrol: id number is required")
	}
	fullName := u.FullName
	if fullName == "" {
		fullName = u.IDNumber
	}
	req := map[string]any{
		"userInfo": map[string]any{"fullName": fullName},
		"identityDocumentInfo": map[string]any{
			"idType":    enrolIDType,
			"idNumber":  u.IDNumber,
			"countryId": enrolCountryID,
		},
	}
	if u.Email != "" {
		email := map[string]any{
			"emailAddress": u.Email,
			"isPrimary":    1,
			"isVerified":   0,
		}
		// verifiedBy and verifiedAt are attestations. They go out only when this
		// gateway holds the verification. A claim it does not hold writes a false
		// attestation into the record of the Scan Verifier.
		if u.EmailVerified {
			at := u.VerifiedAt
			if at.IsZero() {
				at = time.Now()
			}
			email["isVerified"] = 1
			email["verifiedBy"] = enrolVerifiedBy
			email["verifiedAt"] = at.UTC().Format(enrolTimeLayout)
		}
		req["emailInfo"] = []map[string]any{email}
	}
	// The documented body carries no credentials. The Scan Verifier authenticates
	// the caller in the body everywhere else, and an unknown field is ignored
	// where it is not wanted.
	for k, v := range c.requestCredentials() {
		req[k] = v
	}
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("di: encode enrol request: %w", err)
	}

	var out struct {
		Msg       string `json:"msg"`
		StateWord int    `json:"stateWord"`
		Data      struct {
			UserUUID string `json:"userUuid"`
		} `json:"data"`
	}
	if err := c.do(ctx, http.MethodPost, enrolUserPath, body, &out); err != nil {
		return "", err
	}
	// The Scan Verifier answers 200 with a status word of its own, so the HTTP
	// status alone does not mean that the account exists. Anything but 0 is a
	// refusal.
	if out.StateWord != 0 {
		return "", fmt.Errorf("di: enrol: refused (stateWord %d): %s", out.StateWord, out.Msg)
	}
	if out.Data.UserUUID == "" {
		return "", errors.New("di: enrol response is missing data.userUuid")
	}
	return out.Data.UserUUID, nil
}

// do performs one authenticated round trip and decodes the JSON answer into out.
// A status outside 2xx is an error. The body is capped, so a third party does not
// choose how much memory this deployment spends.
func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return fmt.Errorf("di: build request %s: %w", path, err)
	}
	// No Authorization header. The Scan Verifier authenticates the caller in the
	// request body, and it answers a bare refusal to a Basic header. See
	// requestCredentials.
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	started := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		c.logCall(method, path, 0, time.Since(started), err)
		return fmt.Errorf("di: request %s: %w", path, err)
	}
	defer resp.Body.Close() //nolint:errcheck
	c.logCall(method, path, resp.StatusCode, time.Since(started), nil)

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("di: read %s: %w", path, err)
	}
	// The status is read before the body is decoded. An error payload that happens
	// to parse must never pass for a result. The refusal of the Scan Verifier is
	// carried into the error, trimmed, because the status alone does not say why.
	// The body of an answer carries no credential of this deployment.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("di: %s: unexpected status %d: %s", path, resp.StatusCode, trim(raw))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("di: decode %s: %w", path, err)
	}
	return nil
}

// maxReasonBytes caps how much of a refusal is carried into an error, so a third
// party does not choose how long a log line is.
const maxReasonBytes = 256

// trim renders the answer of a failed round trip for an error message.
func trim(raw []byte) string {
	if len(raw) > maxReasonBytes {
		return string(raw[:maxReasonBytes]) + "..."
	}
	return string(raw)
}

// logCall writes the one line every round trip leaves behind. It carries the
// method, the path, the status, and the duration, and it carries no credential. A
// call that never left and a call the Scan Verifier refused look the same from
// outside without it.
//
// A transport failure is reported at info too, and not at error. The caller wraps
// that error and handles it. This line says that the call happened.
//
// A Client built with no logger stays usable.
func (c *Client) logCall(method, path string, status int, took time.Duration, err error) {
	if c.log == nil {
		return
	}
	fields := []logger.Field{
		logger.String("method", method),
		logger.String("path", path),
		logger.Int("status", status),
		logger.Duration("took", took),
	}
	if err != nil {
		fields = append(fields, logger.Err(err))
	}
	c.log.Info("di: call", fields...)
}
