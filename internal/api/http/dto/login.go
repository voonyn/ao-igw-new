package dto

type LoginCheckRequest struct {
	Identifier string `json:"identifier" validate:"required"`
}

type LoginPasswordRequest struct {
	Password    string `json:"password" validate:"required"`
	AuthRequest string `json:"authRequest" validate:"required"`
}

// LoginCompleteRequest is the body of POST /complete.
type LoginCompleteRequest struct {
	AuthRequest string `json:"authRequest" validate:"required"`
}

// LoginConsentRequest is the body of POST /consent.
type LoginConsentRequest struct {
	AuthRequest string `json:"authRequest" validate:"required"`
	Approved    bool   `json:"approved"`
}

// PasswordResetRequest is the body of POST /password/reset/request.
type PasswordResetRequest struct {
	Identifier string `json:"identifier" validate:"required"`
}

// PasswordResetConfirmRequest is the body of POST /password/reset/confirm.
type PasswordResetConfirmRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// InvitationAcceptRequest is the body of POST /invitation/accept
type InvitationAcceptRequest struct {
	Token    string `json:"token" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// PasswordChangeRequest is the body of POST /password/change.
type PasswordChangeRequest struct {
	CurrentPassword string `json:"currentPassword" validate:"required"`
	NewPassword     string `json:"newPassword" validate:"required"`
}

// ProfileUpdateRequest is the body of POST /api/v1/account/profile
type ProfileUpdateRequest struct {
	FirstName   string `json:"firstName" validate:"required"`
	LastName    string `json:"lastName" validate:"required"`
	DisplayName string `json:"displayName" validate:"required"`
	Locale      string `json:"locale" validate:"required"`
}

// EmailVerifyRequest is the body of POST /email/verify/request.
type EmailVerifyRequest struct {
	Identifier string `json:"identifier" validate:"required"`
}

// EmailVerifyConfirmRequest is the body of POST /email/verify/confirm.
type EmailVerifyConfirmRequest struct {
	Token string `json:"token" validate:"required"`
}

// MfaVerifyRequest is the body of POST /mfa/verify
type MfaVerifyRequest struct {
	Code string `json:"code" validate:"required"`
}

// MfaEnrollActivateRequest is the body of POST /mfa/totp/enroll/activate
type MfaEnrollActivateRequest struct {
	Code string `json:"code" validate:"required"`
}
