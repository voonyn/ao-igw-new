// Package totp owns the TOTP Second Factor: the shared secret of an
// Authenticator, the Recovery Codes behind it, and the two tables that hold
// them.
//
// The package imports neither the user domain nor the login session domain.
// The login session domain already imports the user domain, so an import either
// way from here would close a cycle. The router wires this module to the other
// two, which is the router's stated job.
//
// A note on the word "enrolment", which this system now overloads three times.
// A TOTP Enrolment is the row below. It is not the Scan Verifier enrolment of a
// person, and it is not the invitation that enrols a new account.
package totp

import "github.com/uptrace/bun"

// Enrolment is one row of user_totp: the TOTP Second Factor of one person.
//
// The row is hard deleted. It holds a credential the client cannot recover, so
// it carries no deleted_at. See docs/adr/0009-hard-delete-the-totp-factor.md.
//
// Only the keys are modelled, because clearing the factor writes no other
// column. A slice that reads the secret adds the columns it reads.
type Enrolment struct {
	bun.BaseModel `bun:"table:user_totp,alias:t"`

	TenantID string `bun:"tenant_id,pk"`
	UserID   string `bun:"user_id,pk"`
}

// RecoveryCode is one row of user_totp_recovery_codes: one single-use code.
//
// The stored value is a SHA-256 digest of the plaintext, never the code. The
// row is consumed once and hard deleted, and it carries no deleted_at.
type RecoveryCode struct {
	bun.BaseModel `bun:"table:user_totp_recovery_codes,alias:rc"`

	TenantID string `bun:"tenant_id,pk"`
	UserID   string `bun:"user_id,pk"`
	CodeHash string `bun:"code_hash,pk"`
}
