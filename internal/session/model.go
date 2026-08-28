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

	"github.com/uptrace/bun"
)

// The two states login_sessions.state holds. An expired session stays active
// until pruning removes it, because expiry is derived from expires_at.
const (
	StateActive     = 1
	StateTerminated = 2
)

// FactorPassword names the password factor in the factor map. A factor name is a
// registry value of RFC 8176 where one fits, so the ID token carries it
// unchanged.
const FactorPassword = "pwd"

// FactorScan names the factor a person proves by presenting a Wallet credential
// to the Scan Verifier. The AMR registry lists no value for it, and the registry
// permits values outside its own list.
const FactorScan = "vc"

// FactorOTP names the factor a person proves with a code from an Authenticator.
// It is the RFC 8176 registry value, so the ID token carries it unchanged.
//
// A redeemed Recovery Code records the same name. It is the break-glass of that
// factor, and the audit metadata tells the two apart.
const FactorOTP = "otp"

// StepEnrolOTP is what the password answer names when the MFA Requirement
// applies and the person holds no active TOTP Enrolment. The sign-in front end
// reads it and walks the person through enrolment.
//
// It is a step signal and not an AMR name, so it never reaches a token. No
// passkey value is ever named here, because no passkey backend exists and a
// person routed to one would reach a screen that never moves.
const StepEnrolOTP = "otp_enroll"

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

// maxWrongCodes is how many wrong second-factor codes one login session takes
// before it ends. Six digits is a million values, so a sign-in that never ends
// is a sign-in an attacker can guess through.
//
// ponytail: a constant. Move it into a tenant policy row when a tenant asks for
// its own number.
const maxWrongCodes = 5

// ErrNotAuthenticated reports a session that exists but carries no factor. The
// identifier step opens such a session, and the password step upgrades it.
var ErrNotAuthenticated = errors.New("login session is not authenticated")

// ErrInsufficientFactors reports a login session that proved a factor but still
// owes one. The finalize step answers it, and the login UI routes the person
// back to the step they skipped.
//
// It is not ErrNotAuthenticated. That one reports a session that proved nothing,
// and the two need different answers: one restarts the sign-in, and this one
// resumes it. See docs/adr/0011-the-mfa-gate-is-at-the-finalize-step.md.
var ErrInsufficientFactors = errors.New("login session owes a factor")

// ErrSubjectBound reports a login session that already names a different person.
// A step that binds a person refuses one, because that is the shape of an
// attempt to point a live session at somebody else.
var ErrSubjectBound = errors.New("login session already names another person")

// ErrBadCredentials reports a refused password. A wrong password, a session
// that names nobody, and a broken stored hash all give it, so the answer never
// says which of them happened.
var ErrBadCredentials = errors.New("identifier or password is wrong")

// LoginSession is the authority on one person's login. It is what the sealed
// blob holds, so every field here survives a restart.
//
// UserID is empty until an identifier names a person. Factors maps an AMR name
// to the moment that factor was verified, so a later step can honour max_age.
//
// WrongCodes counts the wrong second-factor codes this sign-in submitted. It
// lives in the sealed blob, so it needs no column and every instance reads the
// same number.
type LoginSession struct {
	ID         string               `json:"id"`
	TenantID   string               `json:"tenant_id"`
	UserID     string               `json:"user_id,omitempty"`
	Email      string               `json:"email,omitempty"`
	IP         string               `json:"ip,omitempty"`
	UserAgent  string               `json:"user_agent,omitempty"`
	WrongCodes int                  `json:"wrong_codes,omitempty"`
	Factors    map[string]time.Time `json:"factors,omitempty"`
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

// Row is one row of login_sessions. Data holds the sealed LoginSession, which
// is the authority. The other columns are extracted copies, so the database can
// find the row and an operator can read it.
//
// TokenHash holds a SHA-256 digest, never the token. A leaked row cannot
// credential a request.
//
// The table records the fact of a login, so a row is terminated, never soft
// deleted. See the ao-db-migration skill.
type Row struct {
	bun.BaseModel `bun:"table:login_sessions"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	UserID   string `bun:"user_id,nullzero"`
	State    int    `bun:"state"`

	TokenHash string `bun:"token_hash"`
	Data      []byte `bun:"data"`

	ExpiresAt    time.Time `bun:"expires_at"`
	TerminatedAt time.Time `bun:"terminated_at,nullzero"`
}

// Record is one row of login_sessions as an administrative read projects it.
//
// The flat columns answer the list, and the sealed blob answers the context: the
// address, the agent, and the verified factors. A row whose seal cannot be
// opened keeps its columns and carries no context, because an operator
// investigating an account must still see that the session exists.
//
// TokenHash is not projected. An administrative read never needs it, and a
// column that is never selected cannot leak into an answer.
type Record struct {
	bun.BaseModel `bun:"table:login_sessions,alias:s"`

	ID        string    `bun:"id"`
	TenantID  string    `bun:"tenant_id"`
	UserID    string    `bun:"user_id,nullzero"`
	State     int       `bun:"state"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
	ExpiresAt time.Time `bun:"expires_at,nullzero"`
	Data      []byte    `bun:"data"`

	UserName string `bun:"user_name,scanonly"`
	OrgID    string `bun:"org_id,scanonly"`

	// What the sealed session holds. They are read after the scan, so no column
	// carries them.
	IP        string               `bun:"-"`
	UserAgent string               `bun:"-"`
	Factors   map[string]time.Time `bun:"-"`
	Links     []Link               `bun:"-"`
}

// Link is one row of login_session_links: one protocol flow the login session
// satisfied. AppID is the relying party, and Ref is the request identifier the
// protocol minted.
type Link struct {
	bun.BaseModel `bun:"table:login_session_links,alias:l"`

	LoginSessionID string `bun:"login_session_id"`
	Protocol       int    `bun:"protocol"`
	Ref            string `bun:"protocol_ref"`
	AppID          string `bun:"client_id,nullzero"`
}
