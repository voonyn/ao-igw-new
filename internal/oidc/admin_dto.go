package oidc

import "time"

// The names the console prints for oidc_provider_configs.access_token_type. The
// column stores a number, and the console renders the name.
const (
	AccessTokenNameJWT    = "JWT"
	AccessTokenNameOpaque = "Opaque"
)

// ProviderConfigBody is the body of one provider write. It carries the seven
// writable settings and no others.
//
// Every field is a pointer, so an omitted field is left alone and a false is an
// explicit value. A lifetime of zero is refused: nothing downstream reads it as
// "off", and the engine falls back to its own default instead. The maximum is
// one year.
//
// The issuer, the state, the advertised signing algorithms, and the resource
// identifiers are not here. Each of them is read only, and the reasons are on
// ProviderView.
type ProviderConfigBody struct {
	AuthCodeLifetime     *int `json:"authCodeLifetime" validate:"omitempty,min=1,max=31536000"`
	AccessTokenLifetime  *int `json:"accessTokenLifetime" validate:"omitempty,min=1,max=31536000"`
	IDTokenLifetime      *int `json:"idTokenLifetime" validate:"omitempty,min=1,max=31536000"`
	RefreshTokenLifetime *int `json:"refreshTokenLifetime" validate:"omitempty,min=1,max=31536000"`

	RequirePKCE     *bool `json:"requirePkce"`
	RefreshRotation *bool `json:"refreshRotation"`

	// AccessTokenType is the format of a new access token, by name. Only the JWT
	// format is served, and the service refuses the other one.
	AccessTokenType *string `json:"accessTokenType" validate:"omitempty,oneof=JWT Opaque"`
}

// ProviderView is the provider config as the console reads it.
//
// Issuer, State, and ResourceIndicators are read only, and each describes live
// behaviour the operator needs to see:
//
//   - The issuer names the host every token of the tenant is verified against.
//     Changing it refuses every token already issued, the operator's own
//     included.
//   - The resource identifiers decide which audiences a client may ask for. The
//     admin guard admits one of them alone, so an operator who removed it could
//     not mint another admin token and no console route could put it back.
//
// The advertised signing algorithms are not here at all. No Go code reads that
// column, and a field for a setting the engine ignores is a false statement to
// the operator.
type ProviderView struct {
	Issuer string `json:"issuer"`
	State  int    `json:"state"`

	RequirePKCE     bool `json:"requirePkce"`
	RefreshRotation bool `json:"refreshRotation"`

	AuthCodeLifetime     int    `json:"authCodeLifetime"`
	AccessTokenType      string `json:"accessTokenType"`
	AccessTokenLifetime  int    `json:"accessTokenLifetime"`
	IDTokenLifetime      int    `json:"idTokenLifetime"`
	RefreshTokenLifetime *int   `json:"refreshTokenLifetime"`

	ResourceIndicators []string `json:"resourceIndicators"`
}

// KeyView is one signing key as the console reads it. The row id doubles as the
// JWKS kid, so the console prints it as the kid.
//
// No key material appears here. The public half is served by the JWKS endpoint,
// and the private half never leaves the gateway, at any level and in any
// environment.
//
// ActiveAt and ExpiresAt are null when the key carries no rotation window.
// Updated is the last write to the row, which is when a rotation moved the key:
// ExpiresAt is a future grace deadline and does not answer that question.
type KeyView struct {
	ID       string `json:"id"`
	TenantID string `json:"tenantId"`
	Use      int    `json:"use"`
	Alg      string `json:"alg"`
	State    int    `json:"state"`

	ActiveAt  *time.Time `json:"activeAt"`
	ExpiresAt *time.Time `json:"expiresAt"`
	Created   time.Time  `json:"created"`
	Updated   time.Time  `json:"updated"`
}
