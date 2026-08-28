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

// VerifyRequest is the body of POST /mfa/verify.
//
// One field carries both kinds of value. Six digits is a code from the
// Authenticator, and anything else is a Recovery Code. A length rule of six
// would refuse every Recovery Code, so the cap is the only rule here and the
// service decides what the value is.
type VerifyRequest struct {
	Code string `json:"code" validate:"required,max=64"`
}

// VerifyResponse is the answer to POST /mfa/verify.
//
// SessionToken is the rotated token, disclosed exactly once, here. The token the
// caller presented is dead from this moment.
//
// Nothing else is answered. How many Recovery Codes remain is a question the
// portal asks under an access token, and a sign-in that names it would tell an
// observer how close the account is to its last code.
type VerifyResponse struct {
	SessionToken string `json:"sessionToken"`
}
