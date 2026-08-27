package qrlogin

import (
	"encoding/json"
	"strings"
)

// StartResponse is the answer to POST /qr/start.
//
// SessionToken is disclosed exactly once, here. QRCode is the code object of the
// Scan Verifier, byte for byte, so no field the verifier adds is dropped. The
// presentation identifier of the verifier is deliberately absent: it stays on the
// server.
type StartResponse struct {
	SessionID    string          `json:"sessionId"`
	SessionToken string          `json:"sessionToken"`
	QRCode       json.RawMessage `json:"qrCode"`
	ExpiresIn    int             `json:"expiresIn"`
}

// PollResponse is the answer to POST /qr/poll. Status is pending, authenticated,
// or expired.
//
// SessionToken carries the rotated token on the one poll that turns the login
// session authenticated, and it is absent on every other answer.
type PollResponse struct {
	Status       string `json:"status"`
	SessionToken string `json:"sessionToken,omitempty"`
}

// CallbackResponse is the answer to the push of the Scan Verifier. It carries
// nothing: an unknown, expired, claimed, or refused transaction all answer alike,
// so the endpoint never says which transactions exist.
type CallbackResponse struct {
	Status string `json:"status"`
}

// CallbackRequest is the push body of the Scan Verifier. The verifier writes it,
// so it is validated here like every other body this gateway takes.
//
// The fields arrive at the top level or inside a data envelope, the way the other
// answers of the Scan Verifier are. Both halves are read, and parseCallback picks
// which spelling wins.
type CallbackRequest struct {
	CallbackFields
	Data *CallbackFields `json:"data"`

	// Raw is the body as it arrived, and it is never decoded from JSON. The
	// handler sets it after the bind, so an unusable body still names its own
	// shape in the log and a change of contract is fixed from evidence.
	Raw []byte `json:"-"`
}

// CallbackFields is the field set one push carries.
//
// The confirmed body is:
//
//	{"stateWord":"0","presentationId":"6c7b...","message":"success",
//	 "DecodedVpToken":{"Username":"person@example.com"}}
//
// Snake case and session_id are taken beside it. The start operation answers in
// snake case, so the vendor spells both, and taking a wobble here costs less than
// an outage. stateWord is a result code and not the echo of the wallet: mapping it
// to a reference would look up a transaction named "0".
//
// The two identifiers of the Scan Verifier are bounded at the width of the column
// that holds them. A longer value names no row that can exist, so it is refused
// before it reaches the database or the log.
type CallbackFields struct {
	SessionID      string `json:"session_id" validate:"omitempty,max=64"`
	State          string `json:"state" validate:"omitempty,max=64"` // the wallet echoes the verifier session id here
	PresentationID string `json:"presentation_id" validate:"omitempty,max=64"`
	Nonce          string `json:"nonce" validate:"omitempty,max=255"`

	// StateWord is the result code of the Scan Verifier. It arrives as "0" in a
	// push and as 0 in an answer, so it is read raw and normalised below.
	StateWord json.RawMessage `json:"stateWord"`

	SessionIDCamel      string `json:"sessionId" validate:"omitempty,max=64"`
	PresentationIDCamel string `json:"presentationId" validate:"omitempty,max=64"`

	// DecodedVpToken is what the Scan Verifier decoded out of the presentation.
	// The capitals are the vendor's. The decoder of Go matches a field name
	// without case, so the lower-case spellings arrive here too.
	DecodedVpToken *struct {
		Username string `json:"Username" validate:"omitempty,max=255"`
		Nonce    string `json:"Nonce" validate:"omitempty,max=255"`
	} `json:"DecodedVpToken"`
}

func (f *CallbackFields) username() string {
	if f == nil || f.DecodedVpToken == nil {
		return ""
	}
	return f.DecodedVpToken.Username
}

// stateWord renders the result code as text. A JSON string and a JSON number
// both read as the same value, so 0 and "0" mean one thing.
func (f *CallbackFields) stateWord() string {
	if f == nil || len(f.StateWord) == 0 {
		return ""
	}
	var text string
	if err := json.Unmarshal(f.StateWord, &text); err == nil {
		return text
	}
	return strings.Trim(string(f.StateWord), `"`)
}

func (f *CallbackFields) nonce() string {
	if f == nil {
		return ""
	}
	if f.Nonce != "" {
		return f.Nonce
	}
	if f.DecodedVpToken == nil {
		return ""
	}
	return f.DecodedVpToken.Nonce
}
