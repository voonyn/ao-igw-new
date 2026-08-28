package totp

// StartResponse is the answer to POST /mfa/totp/enroll/start.
//
// Secret is the base32 shared secret, and OtpauthURI carries the same secret in
// the form an Authenticator reads off a QR code. Both are answered, so a person
// on a device that cannot scan types the secret instead.
//
// No factor is recorded by a start, and the session token is not rotated, so no
// token field belongs here.
type StartResponse struct {
	Secret     string `json:"secret"`
	OtpauthURI string `json:"otpauthUri"`
}

// ActivateRequest is the body of POST /mfa/totp/enroll/activate. The code is
// what the Authenticator shows for the pending secret.
type ActivateRequest struct {
	Code string `json:"code" validate:"required,len=6,number"`
}

// ActivateResponse is the answer to POST /mfa/totp/enroll/activate.
//
// SessionToken is the rotated token, disclosed exactly once, here. The token the
// caller presented is dead from this moment.
//
// RecoveryCodes is the whole set, disclosed exactly once, here. The database
// holds digests, so no later answer can name them again.
type ActivateResponse struct {
	SessionToken  string   `json:"sessionToken"`
	RecoveryCodes []string `json:"recoveryCodes"`
}
