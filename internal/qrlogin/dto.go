package qrlogin

import "encoding/json"

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
