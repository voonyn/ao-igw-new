package application

import (
	"time"

	"github.com/uptrace/bun"
)

// The values applications.app_type holds. Only an OIDC application and an API
// application carry a client. A SAML application carries none, because no SAML
// table exists.
const (
	TypeOIDC = 1
	TypeSAML = 2
	TypeAPI  = 3
)

// The values applications.state holds. StateActive is an application that
// serves requests.
const (
	StateActive   = 1
	StateInactive = 2
	StateRemoved  = 3
)

// Application is one row of applications, with the project it sits in.
//
// ProjectName and OrgID are read from projects. The console renders the name,
// and the write gate reads the organization, so both travel with the row.
type Application struct {
	bun.BaseModel `bun:"table:applications,alias:a"`

	ID        string    `bun:"id,pk"`
	TenantID  string    `bun:"tenant_id,pk"`
	ProjectID string    `bun:"project_id"`
	Name      string    `bun:"name"`
	AppType   int       `bun:"app_type"`
	State     int       `bun:"state"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
	DeletedAt time.Time `bun:",soft_delete,nullzero"`

	ProjectName string `bun:"project_name,scanonly"`
	OrgID       string `bun:"org_id,scanonly"`
}

// OIDCConfig is one row of application_oidc_configs, limited to the columns
// this API reads or writes.
//
// The table holds six JSON blobs — crypto_config, authn_config,
// token_binding_config, ciba_config, federation_config, and custom_attributes —
// that no Go code reads. They stay out of this model and out of the API. A form
// field for a setting the engine ignores is a false statement to the operator.
//
// Secret holds a bcrypt hash, never the secret itself. The rotation answers the
// secret once and stores the hash. internal/oidc/client_service.go verifies a
// presented secret against it.
type OIDCConfig struct {
	bun.BaseModel `bun:"table:application_oidc_configs,alias:c"`

	AppID    string `bun:"app_id,pk"`
	TenantID string `bun:"tenant_id,pk"`
	ClientID string `bun:"client_id"`

	CreatedAt       time.Time `bun:"created_at,nullzero"`
	Secret          string    `bun:"secret,nullzero"`
	SecretExpiresAt time.Time `bun:"secret_expires_at,nullzero"`

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

// isPublic reports a client that authenticates with PKCE alone. It presents no
// secret, so it stores none.
func (c OIDCConfig) isPublic() bool { return c.TokenAuthnMethod == authnMethodNone }

// authnMethodNone is the token_authn_method of a public client.
const authnMethodNone = "none"
