package session

// IdentifierRequest is the body of POST /identifier. The identifier is a
// username or an email address.
type IdentifierRequest struct {
	Identifier string `json:"identifier" validate:"required,max=500"`
}

// IdentifierResponse is the answer to POST /identifier. SessionToken is
// disclosed exactly once, here. The caller stores it and never shows it.
//
// The answer is the same whether or not the identifier names a person, so it
// never says which people a tenant holds.
type IdentifierResponse struct {
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
}

// PasswordRequest is the body of POST /password. The authorization request in
// flight is not named here, because the password step never touches it.
type PasswordRequest struct {
	Password string `json:"password" validate:"required,max=72"`
}

// PasswordResponse is the answer to POST /password. SessionToken is the rotated
// token, disclosed exactly once, here. The token the caller presented is dead
// from this moment.
//
// Methods names the Pending Steps the person still owes. It is empty when the
// sign-in owes nothing, and the login UI then goes straight to the finalize
// step.
//
// The field is named for the wire, and the wire name predates the term. It never
// carries a Factor. A Factor is what the person already proved, and the ID token
// carries that. Every value here is a step the person must still run.
//
// It carries otp when the person holds an active TOTP Enrolment, and otp_enroll
// when the MFA Requirement applies and the person holds none. It never carries a
// passkey value, because no passkey backend exists and a person routed to one
// would reach a screen that never moves.
type PasswordResponse struct {
	SessionToken string   `json:"sessionToken"`
	Methods      []string `json:"methods"`
}

// CompleteRequest is the body of POST /complete. AuthRequest is the authn
// session id, a UUID the protocol engine wrote, so 36 characters is the cap.
type CompleteRequest struct {
	AuthRequest string `json:"authRequest" validate:"required,max=36"`
}

// ConsentRequest is the body of POST /consent. Approved is the answer the
// person gave on the consent screen.
type ConsentRequest struct {
	AuthRequest string `json:"authRequest" validate:"required,max=36"`
	Approved    bool   `json:"approved"`
}

// CompleteResponse is the answer to POST /complete and to POST /consent.
//
// RedirectTo carries the browser back to the protocol engine, which answers the
// client. ConsentRequired replaces it when the person must answer the consent
// screen first, and Client and Scopes are what the screen renders.
type CompleteResponse struct {
	RedirectTo      string         `json:"redirectTo,omitempty"`
	ConsentRequired bool           `json:"consentRequired,omitempty"`
	Client          *ConsentClient `json:"client,omitempty"`
	Scopes          []ConsentScope `json:"scopes,omitempty"`
}

// ConsentClient names the client the consent screen asks about.
type ConsentClient struct {
	ClientID string `json:"clientId"`
}

// ConsentScope is one scope on the consent screen.
//
// DisplayName and Description are the words the tenant wrote. A scope the
// tenant does not describe falls back to the bare scope name. Claims stays
// empty: the screen names the scopes, not the claims each one releases.
type ConsentScope struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Claims      []string `json:"claims"`
}

// StatusResponse is the answer to GET /session. Active is true only for a
// session that carries a verified factor, and Email is empty otherwise.
type StatusResponse struct {
	Active bool   `json:"active"`
	Email  string `json:"email,omitempty"`
}

// LogoutResponse is the answer to POST /logout. It carries nothing: the answer
// is the same whether or not the token named a live session.
type LogoutResponse struct{}
