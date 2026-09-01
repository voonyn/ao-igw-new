// Package session holds the login session: proof that a person authenticated
// with one tenant, held across every application of that tenant.
//
// The session lives as an encrypted blob plus the columns an operator needs to
// find it. It is credentialed by an opaque token that rotates on every factor
// upgrade, and only the digest of that token is ever stored.
package session

import (
	"errors"
	"maps"
	"slices"
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

// FactorPasskey names the factor a person proves with a Passkey. The AMR
// registry lists no value that this gateway can state truthfully, so the name is
// its own. See docs/adr/0012-passkey-amr-value.md.
const FactorPasskey = "webauthn"

// The four Pending Steps this deployment names. The password answer carries the
// ones the person can run, and the sign-in front end reads them to pick the next
// route.
//
// A Pending Step is not a Factor. A Factor is what the person already proved, and
// the ID token carries its name. A Pending Step is what the person still owes, and
// it never reaches a token. StepChallengeOTP therefore holds the same text as
// FactorOTP and means the other thing: the person owes the challenge, and did not
// answer it. Read FactorOTP where a proved factor is recorded.
//
// A challenge step must hold the text of the Factor it asks for. The finalize
// gate reads a challenge step as a Factor name, so a step named for one thing and
// a Factor named for another would be owed for ever.
//
// StepChallengePasskey is answered by the passkey challenge of the sign-in, and
// StepEnrolPasskey by its forced enrolment. ADR 0012 fixes the text of both.
const (
	// StepChallengeOTP is owed by a person who holds an active TOTP Enrolment.
	StepChallengeOTP = "otp"

	// StepEnrolOTP is owed when the MFA Requirement applies and the person holds
	// no Second Factor at all. It is owed beside StepEnrolPasskey, and the person
	// answers one of the two.
	StepEnrolOTP = "otp_enroll"

	// StepChallengePasskey is owed by a person who holds an active Passkey.
	StepChallengePasskey = FactorPasskey

	// StepEnrolPasskey is owed when the MFA Requirement applies and the person
	// holds no Second Factor at all. It is owed beside StepEnrolOTP, and it is
	// named first: the Passkey is the Factor the enrolment screen offers first.
	StepEnrolPasskey = "webauthn_enroll"
)

// challengeSteps names every challenge step. Anything else a step list carries
// is an enrolment step, or a step this build does not know, and the finalize gate
// refuses both.
//
// It also names every Second Factor, because a challenge step holds the text of
// the Factor it asks for. One list therefore answers both halves of the gate, and
// the two halves cannot drift apart.
var challengeSteps = []string{StepChallengeOTP, StepChallengePasskey}

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

// ErrDirectoryDisabled reports a sign-in against a directory that is inactive or
// soft deleted. It is not a credential failure, and it spends no budget.
//
// It answers the slug ErrBadCredentials answers, so the response never says that
// a directory is what refused. A slug of its own would name every
// directory-owned person of the tenant for as long as the provider stays off.
// The audit trail tells the two apart, because it is read by an operator.
var ErrDirectoryDisabled = errors.New("the identity provider is disabled")

// ErrDirectoryUnavailable reports a directory that did not answer: a dial
// failure, a timeout, a TLS failure, or a failed bind of the service credential.
// A bind budget nobody could read answers it too.
//
// None of those is a credential failure, so the answer says so. It discloses
// that the identifier is served by a directory, and that is paid for on purpose:
// the state is transient, and the person needs to call the right helpdesk. See
// docs/specs/0002-directory-sign-in.md.
var ErrDirectoryUnavailable = errors.New("the directory did not answer")

// ErrTooManyBinds reports an identifier that spent its whole bind budget. The
// person waits out the window, and the directory is not dialled.
var ErrTooManyBinds = errors.New("too many directory binds")

// LoginSession is the authority on one person's login. It is what the sealed
// blob holds, so every field here survives a restart.
//
// UserID is empty until an identifier names a person. Factors maps an AMR name
// to the moment that factor was verified. Two readers need it: a later step
// honours max_age against the moment, and the ID token publishes the names as
// the amr claim. See docs/adr/0010.
//
// WrongCodes counts the wrong second-factor codes this sign-in submitted. It
// lives in the sealed blob, so it needs no column and every instance reads the
// same number.
//
// IdpID names the Identity Provider the identifier step resolved, and it is
// empty when the local password compare proves this sign-in. It needs no column
// either, and no SQL read names a field inside the blob, so a session already in
// flight decodes it to the empty string, which is what that session was.
//
// Identifier is what the person typed at the identifier step. The bind searches
// the directory with it, because a person the gateway does not hold yet names no
// email and no user id. It is personal data, and the blob is sealed, which is
// where Email already lives.
type LoginSession struct {
	ID         string               `json:"id"`
	TenantID   string               `json:"tenant_id"`
	UserID     string               `json:"user_id,omitempty"`
	Email      string               `json:"email,omitempty"`
	IdpID      string               `json:"idp_id,omitempty"`
	Identifier string               `json:"identifier,omitempty"`
	IP         string               `json:"ip,omitempty"`
	UserAgent  string               `json:"user_agent,omitempty"`
	WrongCodes int                  `json:"wrong_codes,omitempty"`
	Factors    map[string]time.Time `json:"factors,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
	ExpiresAt  time.Time            `json:"expires_at"`
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

// IsChallengeStep reports whether one Pending Step is a challenge step.
//
// It reads the one list, so a caller outside this package never respells the
// step names. The sign-in enrolment guard of both Second Factor modules asks
// this of the steps a person owes: a person the steps name a challenge for is a
// person who already holds a Factor, and a sign-in never enrols beside one.
func IsChallengeStep(step string) bool {
	return slices.Contains(challengeSteps, step)
}

// meets reports whether this session answered one Pending Step.
//
// A challenge step is met by any proved Second Factor. A person who is offered
// two Second Factors proves one of them, so a gate that demanded the exact name
// of each step would refuse a sign-in that is complete.
//
// Every other step is refused. An enrolment step is met by its own exact name
// alone, and no Factor carries an enrolment name, so nothing on the session
// answers one. A person who enrolled is let through by Steps and not by this
// function: the enrolment landed, so the step the account owes is now the
// challenge of the Factor they hold, and the Factor they just proved meets it.
// A step this build cannot classify is refused for the same reason a wrong code
// is: a gate that guesses is a gate that opens.
//
// The names are compared whole. webauthn_enroll is not the webauthn challenge,
// so a person who owes the enrolment is never let through by a Passkey the
// account does not hold yet.
//
// The password answers no challenge step, and neither does a Wallet presentation.
// Only a name this list carries counts. See docs/adr/0012-passkey-amr-value.md.
func (s LoginSession) meets(step string) bool {
	if !IsChallengeStep(step) {
		return false
	}
	for _, factor := range challengeSteps {
		if _, proved := s.Factors[factor]; proved {
			return true
		}
	}
	return false
}

// FactorNames names every factor the person proved, sorted. The ID token
// carries them as the amr claim, and the sorted order keeps that claim the same
// on every token minted from one sign-in.
func (s LoginSession) FactorNames() []string {
	names := slices.Collect(maps.Keys(s.Factors))
	slices.Sort(names)
	return names
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
