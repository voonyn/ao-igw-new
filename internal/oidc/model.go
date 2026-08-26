package oidc

import (
	"time"

	"github.com/uptrace/bun"
)

// Client is one row of application_oidc_configs joined to its application: the
// protocol identity of one application. Name comes from the application, because
// the application is the thing an administrator names.
//
// This package owns the model, and internal/application imports it. The table
// belongs to the application domain, but the import cannot run that way:
// internal/api/http/middlewares imports this package for the provider config of
// a tenant, and internal/application imports those middlewares, so a model here
// is the only direction that closes no cycle.
//
// The engine reads the protocol columns. ParRequired and DefaultMaxAge are read
// by the console alone, and the protocol read leaves them at their zero value
// because clientColumns does not name them.
//
// Secret holds a bcrypt hash, not the secret itself. VerifyClientSecret is the
// only reader of it.
type Client struct {
	bun.BaseModel `bun:"table:application_oidc_configs,alias:c"`

	AppID    string `bun:"app_id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	ClientID string `bun:"client_id"`
	Name     string `bun:"name,scanonly"`

	CreatedAt       time.Time `bun:"created_at,nullzero"`
	ExpiresAt       time.Time `bun:"expires_at,nullzero"`
	Secret          string    `bun:"secret,nullzero"`
	SecretExpiresAt time.Time `bun:"secret_expires_at,nullzero"`

	// TokenAuthnMethod names how the client authenticates at the token endpoint.
	// AuthnMethodNone is the public client, and IsPublic below reads it.
	TokenAuthnMethod string `bun:"token_authn_method"`
	SubjectType      string `bun:"subject_type,nullzero"`
	Scopes           string `bun:"scopes,nullzero"`
	ParRequired      bool   `bun:"par_is_required"`
	IsFirstParty     bool   `bun:"is_first_party"`

	// DefaultMaxAge is read and answered, and it is not writable. No Go code
	// reads the column, so the console labels the field read only.
	DefaultMaxAge int `bun:"default_max_age_secs,nullzero"`

	RedirectURIs           []string `bun:"redirect_uris"`
	GrantTypes             []string `bun:"grant_types"`
	ResponseTypes          []string `bun:"response_types"`
	PostLogoutRedirectURIs []string `bun:"post_logout_redirect_uris,nullzero"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// AuthnMethodNone is the token_authn_method of a public client. The column is
// kept flat, so a caller reads it without deserializing any JSON.
const AuthnMethodNone = "none"

// IsPublic reports a client that authenticates with PKCE alone. It presents no
// secret, so it stores none, and a secret minted for it is unusable.
func (c *Client) IsPublic() bool { return c.TokenAuthnMethod == AuthnMethodNone }

// UserConsent is one row of oidc_user_consents: the cumulative set of scopes one
// person allows one client. Scopes is space-delimited, as the protocol writes
// it.
type UserConsent struct {
	bun.BaseModel `bun:"table:oidc_user_consents,alias:uc"`

	ID        string    `bun:"id,pk"`
	TenantID  string    `bun:"tenant_id"`
	UserID    string    `bun:"user_id"`
	ClientID  string    `bun:"client_id"`
	Scopes    string    `bun:"scopes"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
	UpdatedAt time.Time `bun:"updated_at,nullzero"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// GrantRecord is one row of oidc_grants as an administrative read projects it.
//
// The sealed grant is not projected. The list answers from the extracted columns
// alone, so a page of 100 rows costs no decryption, and the secrets the blob
// carries never reach the read.
//
// HasRefreshToken reports that the digest column is set. It says that a refresh
// token exists, never what it is.
type GrantRecord struct {
	bun.BaseModel `bun:"table:oidc_grants,alias:g"`

	ID             string    `bun:"id"`
	TenantID       string    `bun:"tenant_id"`
	ClientID       string    `bun:"client_id"`
	Subject        string    `bun:"subject,nullzero"`
	LoginSessionID string    `bun:"login_session_id,nullzero"`
	CreatedAt      time.Time `bun:"created_at,nullzero"`
	ExpiresAt      time.Time `bun:"expires_at,nullzero"`

	HasRefreshToken bool   `bun:"has_refresh_token,scanonly"`
	AppName         string `bun:"app_name,scanonly"`
	SubjectName     string `bun:"subject_name,scanonly"`
}

// Key is one row of oidc_keys. PublicKey holds the public JWK JSON as it is
// served. PrivateKey holds the private JWK JSON sealed by the cipher. The row
// id doubles as the JWKS kid.
//
// The row carries no DeletedAt. A key stays readable after it stops working, so
// State marks it instead: KeyStateRetired takes it out of the JWKS and out of
// signer selection, and the console still renders it.
type Key struct {
	bun.BaseModel `bun:"table:oidc_keys"`

	ID         string    `bun:"id,pk"`
	TenantID   string    `bun:"tenant_id,pk"`
	KeyUse     int       `bun:"key_use"`
	Algorithm  string    `bun:"algorithm"`
	State      int       `bun:"state"`
	PublicKey  []byte    `bun:"public_key"`
	PrivateKey []byte    `bun:"private_key"`
	ActiveAt   time.Time `bun:"active_at,nullzero"`
	ExpiresAt  time.Time `bun:"expires_at,nullzero"`

	// UpdatedAt is the last write to the row, which is when a rotation demoted
	// or promoted the key. The administrative read renders it, because
	// ExpiresAt is a future grace deadline and answers a different question.
	CreatedAt time.Time `bun:"created_at,nullzero"`
	UpdatedAt time.Time `bun:"updated_at,nullzero"`
}

// ProviderConfig is one row of oidc_provider_configs: the protocol settings of
// one tenant. Every OIDC knob comes from here, never from the environment.
// RefreshTokenLifetimeSecs is nil when the tenant disables the refresh grant.
type ProviderConfig struct {
	bun.BaseModel `bun:"table:oidc_provider_configs"`

	TenantID string `bun:"tenant_id,pk"`
	Issuer   string `bun:"issuer"`
	State    int    `bun:"state"`

	RequirePKCE          bool `bun:"require_pkce"`
	RefreshTokenRotation bool `bun:"refresh_token_rotation"`

	AuthorizationCodeLifetimeSecs int  `bun:"authorization_code_lifetime_secs"`
	AccessTokenType               int  `bun:"access_token_type"`
	AccessTokenLifetimeSecs       int  `bun:"access_token_lifetime_secs"`
	IDTokenLifetimeSecs           int  `bun:"id_token_lifetime_secs"`
	RefreshTokenLifetimeSecs      *int `bun:"refresh_token_lifetime_secs"`

	// ResourceIndicators lists the RFC 8707 resource identifiers a client of this
	// tenant can ask for. Empty means the tenant runs without the indicator.
	ResourceIndicators []string `bun:"resource_indicators,nullzero"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// ScopeRow is one row of oidc_scopes.
//
// The protocol read has its own Scope struct, which carries the three words the
// consent screen renders and nothing else. This one is the whole row, because
// the console writes it.
//
// MapperCount is not a column. It is counted by the list read, so the scopes
// page names how many claims each scope releases without a request per row.
type ScopeRow struct {
	bun.BaseModel `bun:"table:oidc_scopes,alias:s"`

	ID          string `bun:"id,pk"`
	TenantID    string `bun:"tenant_id"`
	Name        string `bun:"name"`
	DisplayName string `bun:"display_name,nullzero"`
	Description string `bun:"description,nullzero"`

	IsEnabled bool `bun:"is_enabled"`
	IsDefault bool `bun:"is_default"`
	IsBuiltin bool `bun:"is_builtin"`

	CreatedAt time.Time `bun:"created_at,nullzero"`
	UpdatedAt time.Time `bun:"updated_at,nullzero"`
	DeletedAt time.Time `bun:"deleted_at,soft_delete,nullzero"`

	MapperCount int `bun:"mapper_count,scanonly"`
}

// ClaimMapperRow is one row of oidc_claim_mappers. The claims service has its
// own ClaimMapper, which carries what a token build reads; this one is the whole
// row, because the console writes it.
//
// SourceValue is the JSON column of a static mapper. It is bound as a string and
// not as bytes: the column is MySQL JSON, and the driver sends a []byte as a
// binary string, which MySQL refuses to read as JSON.
type ClaimMapperRow struct {
	bun.BaseModel `bun:"table:oidc_claim_mappers,alias:m"`

	ID          string `bun:"id,pk"`
	TenantID    string `bun:"tenant_id"`
	ScopeID     string `bun:"scope_id"`
	ClaimName   string `bun:"claim_name"`
	SourceType  int    `bun:"source_type"`
	SourceKey   string `bun:"source_key,nullzero"`
	SourceValue string `bun:"source_value,nullzero"`

	InIDToken     bool `bun:"in_id_token"`
	InUserInfo    bool `bun:"in_userinfo"`
	InAccessToken bool `bun:"in_access_token"`

	CreatedAt time.Time `bun:"created_at,nullzero"`
	UpdatedAt time.Time `bun:"updated_at,nullzero"`
	DeletedAt time.Time `bun:"deleted_at,soft_delete,nullzero"`
}

// Grant is one row of oidc_grants: what a client received from one successful
// authorization. Data holds the sealed goidc.Grant, which is the authority. The
// other columns are extracted copies, so the database can find the row.
//
// AuthCodeHash and RefreshTokenHash hold a SHA-256 digest, never the value. A
// leaked row cannot be replayed.
type Grant struct {
	bun.BaseModel `bun:"table:oidc_grants"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	ClientID string `bun:"client_id"`
	Subject  string `bun:"subject,nullzero"`

	// LoginSessionID names the sign-in the grant came from. A logout of that
	// session revokes the grant. It is empty for a grant that no browser
	// sign-in produced.
	LoginSessionID string `bun:"login_session_id,nullzero"`

	AuthCodeHash     string `bun:"auth_code_hash,nullzero"`
	RefreshTokenHash string `bun:"refresh_token_hash,nullzero"`

	Data      []byte    `bun:"data"`
	ExpiresAt time.Time `bun:"expires_at,nullzero"`
}

// SupersededRefreshToken is one row of oidc_superseded_refresh_tokens: a
// refresh token that a rotation replaced. The row holds the SHA-256 digest,
// never the token, so a leaked row cannot be replayed. A later request that
// presents the same token is a replay, and the grant dies.
//
// The row is a fact, not an entity, so it is hard deleted when it expires.
type SupersededRefreshToken struct {
	bun.BaseModel `bun:"table:oidc_superseded_refresh_tokens"`

	TenantID  string    `bun:"tenant_id,pk"`
	TokenHash string    `bun:"token_hash,pk"`
	GrantID   string    `bun:"grant_id"`
	ExpiresAt time.Time `bun:"expires_at"`
}

// Session is one row of oidc_sessions: one authorization request in flight.
// Data holds the sealed goidc.AuthnSession, which is the authority.
type Session struct {
	bun.BaseModel `bun:"table:oidc_sessions"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	ClientID string `bun:"client_id,nullzero"`
	Subject  string `bun:"subject,nullzero"`

	Data      []byte    `bun:"data"`
	ExpiresAt time.Time `bun:"expires_at,nullzero"`
}
