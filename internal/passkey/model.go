// Package passkey owns the Passkey Second Factor: the WebAuthn ceremonies, and
// the table of public keys behind them.
//
// The package imports neither the user domain nor the login session domain. The
// login session domain already imports the user domain, so an import either way
// from here would close a cycle. The router wires this module to the other two,
// which is the router's stated job.
//
// Nothing here is a credential of the gateway. A Passkey stores a public key, so
// a database leak exposes no secret and no cipher is involved.
package passkey

import (
	"time"

	"github.com/uptrace/bun"
)

// Credential is one row of user_webauthn_credentials: one Passkey of one person.
//
// The row carries deleted_at. A Passkey is an entity a person creates, names,
// and expects to find again, so a removal marks it. See
// docs/adr/0009-hard-delete-the-totp-factor.md, which states the rule for both
// Second Factors.
//
// Record is the JSON of the library's webauthn.Credential, stored verbatim. No
// Go type in this package parses it, so a new field of the library lands without
// a migration. CredentialID is that blob's id, copied out as the queryable key.
//
// Record is a string and not a byte slice. The column is JSON, and MySQL refuses
// a JSON value built from a binary string, which is what a byte slice parameter
// is.
//
// RPID is the domain the Passkey was registered under. A device answers a
// challenge under that domain alone, so a row that names another domain can
// never sign the person in.
//
// Name is what the person calls the device. The column is nullable and names are
// not unique: two devices called "Phone" are that person's business.
type Credential struct {
	bun.BaseModel `bun:"table:user_webauthn_credentials,alias:wc"`

	TenantID     string `bun:"tenant_id,pk"`
	CredentialID []byte `bun:"credential_id,pk"`

	UserID     string    `bun:"user_id"`
	RPID       string    `bun:"rp_id"`
	Record     string    `bun:"credential"`
	Name       string    `bun:"name,nullzero"`
	CreatedAt  time.Time `bun:"created_at,nullzero"`
	LastUsedAt time.Time `bun:"last_used_at,nullzero"`
	DeletedAt  time.Time `bun:",soft_delete,nullzero"`
}
