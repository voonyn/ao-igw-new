// Package session holds the login session: proof that a person authenticated
// with one tenant, held across every application of that tenant.
//
// The session lives as an encrypted blob plus the columns an operator needs to
// find it. It is credentialed by an opaque token that rotates on every factor
// upgrade, and only the digest of that token is ever stored.
package session

import (
	"errors"
	"time"
)

// The two states login_sessions.state holds. An expired session stays active
// until pruning removes it, because expiry is derived from expires_at.
const (
	StateActive     = 1
	StateTerminated = 2
)

// FactorPassword names the password factor in the factor map. The names are the
// AMR values of RFC 8176, so the ID token can carry them unchanged.
const FactorPassword = "pwd"

// partialLifetime bounds the identifier step. The person has proved nothing
// yet, so the session lives only long enough to type a password.
//
// ponytail: a constant. Move it into a tenant policy row when a tenant asks for
// its own number.
const partialLifetime = 10 * time.Minute

// fullLifetime bounds a session the person proved a factor on. It outlives any
// single authorization request, because one sign-in serves every application of
// the tenant.
//
// ponytail: a constant. Move it into a tenant policy row when a tenant asks for
// its own number.
const fullLifetime = 12 * time.Hour

// ErrNotAuthenticated reports a session that exists but carries no factor. The
// identifier step opens such a session, and the password step upgrades it.
var ErrNotAuthenticated = errors.New("login session is not authenticated")

// ErrBadCredentials reports a refused password. A wrong password, a session
// that names nobody, and a broken stored hash all give it, so the answer never
// says which of them happened.
var ErrBadCredentials = errors.New("identifier or password is wrong")

// LoginSession is the authority on one person's login. It is what the sealed
// blob holds, so every field here survives a restart.
//
// UserID is empty until an identifier names a person. Factors maps an AMR name
// to the moment that factor was verified, so a later step can honour max_age.
type LoginSession struct {
	ID        string               `json:"id"`
	TenantID  string               `json:"tenant_id"`
	UserID    string               `json:"user_id,omitempty"`
	Email     string               `json:"email,omitempty"`
	IP        string               `json:"ip,omitempty"`
	UserAgent string               `json:"user_agent,omitempty"`
	Factors   map[string]time.Time `json:"factors,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	ExpiresAt time.Time            `json:"expires_at"`
}

// Authenticated reports whether the person verified at least one factor. A
// partial session answers false, and only a full session names a signed-in
// person.
func (s LoginSession) Authenticated() bool {
	return len(s.Factors) > 0
}

// AuthTime is the moment the person last verified a factor. An authorization
// request measures prompt=login and max_age against it. A partial session
// answers the zero time.
func (s LoginSession) AuthTime() time.Time {
	var latest time.Time
	for _, at := range s.Factors {
		if at.After(latest) {
			latest = at
		}
	}
	return latest
}

// Identity is what the identifier step learns about a person.
type Identity struct {
	UserID string
	Email  string
}

// Opened is what the caller of Identify gets back: the public session id, and
// the token that credentials it. The token is disclosed exactly once, here.
type Opened struct {
	ID    string
	Token string
}
