package session

import "time"

// AccountSession is one login session as the person who owns it reads it.
//
// It is not SessionView. The console reads the tenant, the account, and the
// organization behind a session, because an operator investigates other people.
// A person reads only what tells one of their own devices from another: where it
// signed in from, what it signed in with, and when.
//
// Nothing here marks the caller's own session. The access token carries no
// session identifier and does not gain one, so the gateway cannot name it. The
// portal holds a validated ID token, which carries sid, and it marks the row
// itself.
//
// The session token never appears here, at any level and in any environment.
// Only its digest is stored, and the digest never leaves the gateway.
type AccountSession struct {
	ID    string `json:"id"`
	State int    `json:"state"`

	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`

	IP        string `json:"ip"`
	UserAgent string `json:"userAgent"`
}
