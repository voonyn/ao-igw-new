package session

import "time"

// Query is the window and the narrowing of one administrative session read.
//
// UserID and OrgID narrow the list to one person and to one organization. The
// console reads the same list three times: whole for the sessions page, by
// person on the user drawer, and by organization on the organization drawer.
//
// State is 1 for a live session and 2 for a terminated one. Zero reads both: a
// session state is a lifecycle and not a soft delete, so an operator who
// investigates an account must see that a session ended.
type Query struct {
	UserID string
	OrgID  string
	State  int

	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// FactorView is one verified factor of a login session, as the console renders
// it. AMR is the name of RFC 8176 that the ID token carries.
type FactorView struct {
	AMR  string    `json:"amr"`
	Time time.Time `json:"time"`
}

// LinkView is one protocol flow the login session satisfied. AppID is the
// relying party the flow named, and Ref is the request identifier of the
// protocol.
type LinkView struct {
	Protocol int    `json:"protocol"`
	AppID    string `json:"appId"`
	Ref      string `json:"ref"`
}

// SessionView is one login session as the console reads it.
//
// UserName and OrgID are joined from the account. The organization is what the
// console gates its force-logout control on, so it is authorization input and
// not decoration.
//
// IP, UserAgent, and Factors are read from the sealed session, and they record
// the moment the session began rather than the last time it was seen. A row
// whose seal cannot be opened answers with empty values, and the console then
// renders an explicit unknown marker.
//
// The session token never appears here, at any level and in any environment.
// Only its digest is stored, and the digest never leaves the gateway.
type SessionView struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	UserID   string `json:"userId"`
	UserName string `json:"userName"`
	OrgID    string `json:"orgId"`
	State    int    `json:"state"`

	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`

	IP        string       `json:"ip"`
	UserAgent string       `json:"ua"`
	Factors   []FactorView `json:"factors"`
	Links     []LinkView   `json:"links"`
}

// RevokedView is what a force-logout answers with: how much it ended. The
// console reports the counts, because an operator who signs somebody out of
// everything needs to read what "everything" was.
type RevokedView struct {
	Sessions int `json:"sessions"`
	Grants   int `json:"grants"`
}
