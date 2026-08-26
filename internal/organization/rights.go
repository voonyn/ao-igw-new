package organization

import (
	"slices"

	"alphaomega/identitygateway/internal/tenant"
)

// Rights is what one person may do across the organizations of a tenant.
//
// This package owns the type because it declares the organization roles the
// rules read, and because it imports neither internal/project nor
// internal/application. Those two, and this package, apply the same rule and
// share it from here.
//
// internal/user does NOT share it. An ORG_USER_MANAGER administers the people of
// an organization, so the account rules admit a role these do not. Widening this
// type to cover that would let an ORG_USER_MANAGER write projects and
// applications, which it must never do. That package keeps its own rule, and
// says so where it declares it.
type Rights struct {
	// TenantManager reports an IAM_OWNER or an IAM_ADMIN of the tenant. Either
	// one writes anything the tenant holds.
	TenantManager bool

	// OrgRoles is the roles the person holds, by organization id.
	OrgRoles map[string][]string
}

// NewRights reads what the person may do from the two answers a service already
// holds: the tenant roles, and the organization memberships.
func NewRights(tenantRoles []string, memberships []Membership) Rights {
	held := Rights{
		TenantManager: slices.Contains(tenantRoles, tenant.RoleIAMOwner) ||
			slices.Contains(tenantRoles, tenant.RoleIAMAdmin),
		OrgRoles: make(map[string][]string, len(memberships)),
	}
	for _, m := range memberships {
		held.OrgRoles[m.OrgID] = m.Roles
	}
	return held
}

// CanWrite reports whether the person may write what one organization holds. A
// tenant manager writes any of them, and an ORG_OWNER writes its own.
func (r Rights) CanWrite(orgID string) bool {
	return r.TenantManager || slices.Contains(r.OrgRoles[orgID], RoleOrgOwner)
}

// Admits reports whether the person administers anything at all. A person who
// administers nothing belongs in the portal, not in the console.
func (r Rights) Admits() bool {
	if r.TenantManager {
		return true
	}
	for _, roles := range r.OrgRoles {
		if slices.Contains(roles, RoleOrgOwner) || slices.Contains(roles, RoleOrgUserManager) {
			return true
		}
	}
	return false
}
