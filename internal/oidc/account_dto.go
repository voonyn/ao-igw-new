package oidc

import "time"

// ConnectionView is one connected application as the person reads it.
//
// ClientID is always answered. AppName is empty when the client or the
// application behind it is gone, so a connection whose record was removed is
// still listed and can still be taken back.
//
// HasLiveGrant reports an unexpired grant of this person and this client right
// now. It separates an application that is still calling the gateway from one
// that only holds a remembered consent.
type ConnectionView struct {
	ClientID string   `json:"clientId"`
	AppName  string   `json:"appName"`
	Scopes   []string `json:"scopes"`

	HasLiveGrant bool `json:"hasLiveGrant"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// DisconnectedView is what one disconnect ended: the consent, and the grants
// that went with it. The count lets the portal say what was taken back.
type DisconnectedView struct {
	ClientID string `json:"clientId"`
	Grants   int    `json:"grants"`
}
