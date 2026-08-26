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
