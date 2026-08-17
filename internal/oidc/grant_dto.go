package oidc

import "time"

// The three kinds of grant the console names. The kind is derived from the row,
// because the authoritative grant is sealed and a list must not open one per
// page.
const (
	KindClientCredentials = "client_credentials"
	KindRefreshToken      = "refresh_token"
	KindAuthorizationCode = "authorization_code"
)

// GrantQuery is the window and the narrowing of one administrative grant read.
// UserID narrows the list to one subject, which is how the console reads the
// grants of one person.
type GrantQuery struct {
	UserID string

	Sort   string
	Desc   bool
	Limit  int
	Offset int
}

// GrantView is one grant as the console reads it.
//
// AppID carries the OIDC client identifier the grant holds, and AppName carries
// the name of the application that identifier belongs to. A client that is gone
// keeps its identifier and loses its name, so the row still says which client
// received the grant.
//
// Subject is empty for a client-credentials grant, which no person authorized.
//
// Neither the refresh token nor the authorization code appears here, at any
// level and in any environment. Only their digests are stored, and a digest
// never leaves the gateway.
type GrantView struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`

	AppID   string `json:"appId"`
	AppName string `json:"appName"`

	Subject     string `json:"subject"`
	SubjectName string `json:"subjectName"`

	LoginSessionID string `json:"loginSessionId"`
	Kind           string `json:"kind"`

	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}
