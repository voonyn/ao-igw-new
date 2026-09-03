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

// LocalOwner is one IAM_OWNER of a tenant whom the local password compare still
// signs in. It is the row LocalOwners answers with, and it is not a table.
//
// Email is the address the person carries, lowercased. The guard that refuses a
// domain claim matches the claimed domains against it, so the read carries it
// and no caller reads the person again.
type LocalOwner struct {
	UserID string `bun:"user_id"`
	Email  string `bun:"email"`
}

// DomainPerson is one person of a tenant whose email address carries a claimed
// domain. It is the row PeopleAtDomains answers with, and it is not a table.
//
// It is the population one domain claim moves onto a directory. LocalOwner is
// the subset of it the guard rail reads, and this row is the whole of it: the
// preview names everybody the claim moves, and the refusal names nobody.
type DomainPerson struct {
	UserID   string `bun:"user_id"`
	Username string `bun:"username"`
	Email    string `bun:"email"`
}

// LastLocalOwner reports whether one write empties the local owners of a tenant.
//
// owners is what LocalOwners answered before the write. takes reports whether
// the write takes that owner out of the local compare: a revoked role, or a
// domain claim that routes their email address to a directory.
//
// A tenant that already holds no local owner is not made worse by the write, so
// it answers false. There is nothing left to protect, and a refusal there would
// trap an administrator whose directory is gone for good.
func LastLocalOwner(owners []LocalOwner, takes func(LocalOwner) bool) bool {
	if len(owners) == 0 {
		return false
	}
	for _, owner := range owners {
		if !takes(owner) {
			return false
		}
	}
	return true
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
