// Package qrlogin owns QR Login: the flow where a person proves who they are by
// presenting a Wallet credential to the Scan Verifier, instead of typing a
// password.
//
// The slice is its own domain package so the Scan Verifier dependency stays out
// of the package every sign-in path imports. It imports the session domain one
// way, and no cycle exists.
//
// A note on the word "session", which this flow overloads a fourth time. The
// session identifier of the Scan Verifier is its own per-transaction identifier,
// and the wallet echoes it. It is not a Login Session and it is not an Authn
// Session.
package qrlogin

import (
	"errors"
	"time"

	"github.com/uptrace/bun"
)

// The three states qr_login_transactions.state holds. The values are persisted,
// so they are never renumbered.
const (
	// StatePending is a started transaction. The code is on screen and nothing
	// has been presented yet.
	StatePending = 1
	// StateVerified means the Scan Verifier accepted a presentation and it
	// resolved to a person of this tenant. The poll can now complete the sign-in.
	StateVerified = 2
	// StateFailed is terminal. The nonce did not match, or the presented name
	// resolved to no person. The person scans again.
	StateFailed = 3
)

// The three answers the poll gives. Expired, consumed, and unknown all read as
// expired: telling them apart is free reconnaissance on an endpoint whose
// success means "sign somebody in".
const (
	StatusPending       = "pending"
	StatusAuthenticated = "authenticated"
	StatusExpired       = "expired"
)

// TransactionTTL is how long a started transaction can be presented against.
//
// It is sized above the window of the Scan Verifier, and not chosen freely. The
// Scan Verifier drops its own transaction about 60 seconds after the start, so a
// scan that is going to succeed is pushed inside that window. The row must still
// be claimable when the push lands, and expiring first would refuse a scan the
// verifier accepted.
//
// ponytail: a constant. Make it configuration the day a second Scan Verifier
// runs a different window.
const TransactionTTL = 90 * time.Second

// stateWordAccepted is the result code the Scan Verifier answers an accepted
// presentation with. Every other value is a refusal, and the HTTP status alone
// does not say which happened: the verifier reports a refusal inside a
// successful push.
const stateWordAccepted = "0"

// ErrUnusableCallback reports a push body that names no transaction. It is the
// only callback failure a caller can observe. Every outcome past the parse
// answers success, because the endpoint must never say which transactions exist.
var ErrUnusableCallback = errors.New("qr login: the callback body names no transaction")

// ErrNotFound reports that no row matches. Consume answers it too, and unknown,
// expired, and already consumed collapse into it on purpose.
var ErrNotFound = errors.New("qr login transaction not found")

// Transaction is one row of qr_login_transactions: one QR Login in flight.
//
// NonceHash holds a SHA-256 digest, never the nonce. The plaintext nonce only
// ever leaves this deployment towards the Scan Verifier.
//
// The row is consumed, not an entity. It is never soft deleted. See the
// ao-db-migration skill.
type Transaction struct {
	bun.BaseModel `bun:"table:qr_login_transactions,alias:q"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`

	LoginSessionID string `bun:"login_session_id"`

	// The two identifiers of the Scan Verifier. VerifierSessionID is the one the
	// wallet echoes, and VerifierPresentationID stays on the server and never
	// reaches the browser. Either one addresses the row, and both are globally
	// unique.
	VerifierSessionID      string `bun:"verifier_session_id"`
	VerifierPresentationID string `bun:"verifier_presentation_id"`

	NonceHash string `bun:"nonce_hash"`
	State     int    `bun:"state"`
	UserID    string `bun:"user_id,nullzero"`

	ExpiresAt  time.Time `bun:"expires_at"`
	ConsumedAt time.Time `bun:"consumed_at,nullzero"`
}
