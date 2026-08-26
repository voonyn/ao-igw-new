package user

import (
	"time"

	"github.com/uptrace/bun"
)

// User is one row of users joined to its user_humans row: the account and the
// person behind it.
//
// PasswordHash holds a bcrypt hash, never the password. It never reaches a log
// line and never leaves this package in a response.
type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	OrgID    string `bun:"org_id"`
	Username string `bun:"username,nullzero"`
	UserType int    `bun:"user_type"`
	State    int    `bun:"state"`

	CreatedAt  time.Time `bun:"created_at,nullzero"`
	LastAuthAt time.Time `bun:"last_auth_at,nullzero"`

	// The columns of the joined user_humans row, and the second factor derived
	// beside it. A machine account holds no such row, so every one of them is
	// empty for one.
	DisplayName     string `bun:"display_name,scanonly"`
	Email           string `bun:"email,scanonly"`
	IsEmailVerified bool   `bun:"is_email_verified,scanonly"`
	PasswordHash    string `bun:"password_hash,scanonly"`

	FirstName         string    `bun:"first_name,scanonly"`
	LastName          string    `bun:"last_name,scanonly"`
	Lang              string    `bun:"preferred_language,scanonly"`
	Phone             string    `bun:"phone,scanonly"`
	IsPhoneVerified   bool      `bun:"is_phone_verified,scanonly"`
	PasswordChangeReq bool      `bun:"password_change_required,scanonly"`
	PasswordChangedAt time.Time `bun:"password_changed_at,scanonly,nullzero"`
	MFAEnabled        bool      `bun:"mfa_enabled,scanonly"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// Human is one row of user_humans: the person behind one account. A machine
// account holds no such row.
//
// PasswordHash holds a bcrypt hash, never the password. It never reaches a log
// line and never leaves this package in a response.
type Human struct {
	bun.BaseModel `bun:"table:user_humans,alias:h"`

	UserID   string `bun:"user_id,pk"`
	TenantID string `bun:"tenant_id,pk"`

	FirstName   string `bun:"first_name,nullzero"`
	LastName    string `bun:"last_name,nullzero"`
	DisplayName string `bun:"display_name,nullzero"`
	Lang        string `bun:"preferred_language,nullzero"`

	Email           string `bun:"email,nullzero"`
	IsEmailVerified bool   `bun:"is_email_verified"`
	Phone           string `bun:"phone,nullzero"`

	PasswordHash string `bun:"password_hash,nullzero"`

	CreatedAt time.Time `bun:"created_at,nullzero"`
}

// AccountToken is one row of account_tokens: a single-use, time-limited value a
// person redeems once.
//
// TokenHash holds a SHA-256 digest, never the token itself. The token is
// disclosed exactly once, in the answer of the request that minted it.
type AccountToken struct {
	bun.BaseModel `bun:"table:account_tokens"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	UserID   string `bun:"user_id"`
	Purpose  int    `bun:"purpose"`

	TokenHash string    `bun:"token_hash"`
	ExpiresAt time.Time `bun:"expires_at"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
}

// The three tables a second-factor reset clears. Only the keys are modelled,
// because the reset writes no other column of them.
type (
	totp struct {
		bun.BaseModel `bun:"table:user_totp"`

		TenantID  string    `bun:"tenant_id,pk"`
		UserID    string    `bun:"user_id,pk"`
		DeletedAt time.Time `bun:",soft_delete,nullzero"`
	}

	totpRecoveryCode struct {
		bun.BaseModel `bun:"table:user_totp_recovery_codes"`

		TenantID string `bun:"tenant_id,pk"`
		UserID   string `bun:"user_id,pk"`
		CodeHash string `bun:"code_hash,pk"`
	}

	passkey struct {
		bun.BaseModel `bun:"table:user_webauthn_credentials"`

		TenantID     string    `bun:"tenant_id,pk"`
		CredentialID []byte    `bun:"credential_id,pk"`
		UserID       string    `bun:"user_id"`
		DeletedAt    time.Time `bun:",soft_delete,nullzero"`
	}
)
