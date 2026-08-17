package organization

import "time"

// MemberBody is what a grant carries. An empty OrgID names the tenant roster,
// and a non-empty one names an organization, which is the same rule the console
// writes its request with.
//
// Four roles exist in the whole gateway, so a body carrying more than four
// names is refused before the service reads it.
type MemberBody struct {
	UserID string   `json:"userId" validate:"required"`
	OrgID  string   `json:"orgId"`
	Roles  []string `json:"roles" validate:"required,min=1,max=4,dive,required,max=50"`
}

// RolesBody is what a role change carries. The path names the person, so the
// body does not.
type RolesBody struct {
	OrgID string   `json:"orgId"`
	Roles []string `json:"roles" validate:"required,min=1,max=4,dive,required,max=50"`
}

// TenantMemberView is one row of the tenant roster, as the console reads it.
type TenantMemberView struct {
	TenantID string    `json:"tenantId"`
	UserID   string    `json:"userId"`
	UserName string    `json:"userName"`
	Roles    []string  `json:"roles"`
	Created  time.Time `json:"created"`
}

// OrgMemberView is one row of the roster of one organization.
type OrgMemberView struct {
	TenantID string    `json:"tenantId"`
	OrgID    string    `json:"orgId"`
	UserID   string    `json:"userId"`
	UserName string    `json:"userName"`
	Roles    []string  `json:"roles"`
	Created  time.Time `json:"created"`
}
