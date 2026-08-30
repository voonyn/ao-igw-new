package passkey

import (
	"encoding/json"
	"time"
)

// RegisterFinishRequest is the body of POST /mfa/passkeys/register/finish.
//
// Credential is the object navigator.credentials.create() produced, passed
// through whole. Every field of it is covered by what the device signed, so
// nothing between the browser and the library picks a field out of it. The
// gateway is the first thing that reads inside it.
//
// Name is what the person calls the device. It is optional: the service supplies
// a default, the column is nullable, and two devices may share a name.
type RegisterFinishRequest struct {
	Credential json.RawMessage `json:"credential" validate:"required"`
	Name       string          `json:"name" validate:"omitempty,max=255"`
}

// View is one Passkey as the person who owns it reads it.
//
// ID is the credential id in the base64url spelling the browser uses, so a later
// rename or removal names the same value the browser named. It is a public
// handle and never a credential: every assertion sends it in the clear.
//
// No public key and no stored blob reaches this shape. A list renders the four
// mapped columns, and no Go type parses the blob behind them.
//
// LastUsedAt is absent until the Passkey signs the person in once.
type View struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

// view projects one row onto what the portal renders.
func view(row Credential) View {
	answer := View{
		ID:        credentialID(row.CredentialID),
		Name:      row.Name,
		CreatedAt: row.CreatedAt,
	}
	if !row.LastUsedAt.IsZero() {
		used := row.LastUsedAt
		answer.LastUsedAt = &used
	}
	return answer
}

// views projects a whole list. It answers an empty list and never nil, so the
// portal renders "no passkeys yet" and never a missing key.
func views(rows []Credential) []View {
	answer := make([]View, 0, len(rows))
	for _, row := range rows {
		answer = append(answer, view(row))
	}
	return answer
}
