package organization

import (
	"time"

	"github.com/uptrace/bun"
)

// The organization roles. A person who holds one of them administers one
// organization, so the console admits them and shows that organization. The
// organization owns organization membership, so the names are declared here and
// no roles table exists.
const (
	RoleOrgOwner       = "ORG_OWNER"
	RoleOrgUserManager = "ORG_USER_MANAGER"
)

// The values organizations.state holds. StateActive is an organization in use.
const (
	StateActive   = 1
	StateInactive = 2
	StateRemoved  = 3
)

// Organization is one row of organizations.
type Organization struct {
	bun.BaseModel `bun:"table:organizations"`

	ID        string    `bun:"id,pk"`
	TenantID  string    `bun:"tenant_id,pk"`
	Name      string    `bun:"name"`
	State     int       `bun:"state"`
	CreatedAt time.Time `bun:"created_at"`
	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// Membership is one row of organization_members: the roles one person holds in
// one organization.
type Membership struct {
	bun.BaseModel `bun:"table:organization_members,alias:m"`

	TenantID  string    `bun:"tenant_id,pk"`
	OrgID     string    `bun:"org_id,pk"`
	UserID    string    `bun:"user_id,pk"`
	Roles     []string  `bun:"roles"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
	DeletedAt time.Time `bun:",soft_delete,nullzero"`

	// UserName is the person behind the membership, joined by the roster read.
	// It is empty everywhere else, because no column of this table holds it.
	UserName string `bun:"user_name,scanonly"`
}
