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

import (
	"time"

	"github.com/uptrace/bun"
)

// Enrolment is one row of user_totp: the TOTP Second Factor of one person.
//
// The row is hard deleted. It holds a credential the client cannot recover, so
// it carries no deleted_at. See docs/adr/0009-hard-delete-the-totp-factor.md.
//
// SecretEncrypted holds the base32 shared secret sealed at rest. A nil cipher
// matches the development bootstrap, which stores it in the clear, the way the
// login session and the OIDC storage already do.
//
// ActivatedAt is the state of the row. The zero time is a pending enrolment: the
// secret is minted and nobody has proved a code with it yet. A set time is an
// active Second Factor.
//
// LastStep is the newest time step this account has spent. It stops a code an
// observer read off the screen from being replayed.
type Enrolment struct {
	bun.BaseModel `bun:"table:user_totp,alias:t"`

	TenantID string `bun:"tenant_id,pk"`
	UserID   string `bun:"user_id,pk"`

	SecretEncrypted []byte    `bun:"secret_encrypted"`
	ActivatedAt     time.Time `bun:"activated_at,nullzero"`
	LastStep        int64     `bun:"last_step"`
}

// Active reports whether the row is an active Second Factor. A pending enrolment
// answers false: the secret exists, and nobody has proved a code with it.
func (e Enrolment) Active() bool { return !e.ActivatedAt.IsZero() }

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
