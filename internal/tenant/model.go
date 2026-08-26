package tenant

import (
	"time"

	"github.com/uptrace/bun"
)

// Tenant is one row of tenants. DefaultOrgID is empty until bootstrap points the
// tenant at its default organization.
type Tenant struct {
	bun.BaseModel `bun:"table:tenants"`

	ID           string    `bun:"id,pk"`
	Name         string    `bun:"name"`
	State        int       `bun:"state"`
	DefaultOrgID string    `bun:"default_org_id,nullzero"`
	CreatedAt    time.Time `bun:"created_at"`
	DeletedAt    time.Time `bun:",soft_delete,nullzero"`
}

// Member is one row of tenant_members: the tenant roles of one person.
type Member struct {
	bun.BaseModel `bun:"table:tenant_members,alias:m"`

	TenantID  string    `bun:"tenant_id,pk"`
	UserID    string    `bun:"user_id,pk"`
	Roles     []string  `bun:"roles"`
	CreatedAt time.Time `bun:"created_at,nullzero"`
	DeletedAt time.Time `bun:",soft_delete,nullzero"`

	// UserName is the person behind the membership, joined by the roster read.
	// It is empty everywhere else, because no column of this table holds it.
	UserName string `bun:"user_name,scanonly"`
}

// Domain is one row of tenant_domains. The domain is the bare host, lowercased,
// with a port only for a non-standard listener.
type Domain struct {
	bun.BaseModel `bun:"table:tenant_domains"`

	Domain     string    `bun:"domain,pk"`
	TenantID   string    `bun:"tenant_id"`
	IsPrimary  bool      `bun:"is_primary"`
	IsVerified bool      `bun:"is_verified"`
	State      int       `bun:"state"`
	DeletedAt  time.Time `bun:",soft_delete,nullzero"`
}

// Bootstrap is the singleton row of system_bootstrap: the marker the bootstrap
// command wrote when it created the first tenant. The table holds one row of the
// deployment, so the read takes no tenant id.
type Bootstrap struct {
	bun.BaseModel `bun:"table:system_bootstrap"`

	ID        int       `bun:"id,pk"`
	TenantID  string    `bun:"tenant_id"`
	Version   string    `bun:"version"`
	AppliedAt time.Time `bun:"applied_at,nullzero"`
}
