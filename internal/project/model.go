package project

import (
	"time"

	"github.com/uptrace/bun"
)

// The values projects.state holds. StateActive is a project in use.
const (
	StateActive   = 1
	StateInactive = 2
	StateRemoved  = 3
)

// Project is one row of projects.
//
// RoleAssertion, RoleCheck, HasProjectCheck, and PrivateLabeling are stored and
// read back, and no part of the gateway acts on them. Project roles, project
// grants, and branding do not exist here, so the console labels the four
// settings "not enforced yet".
type Project struct {
	bun.BaseModel `bun:"table:projects"`

	ID              string    `bun:"id,pk"`
	TenantID        string    `bun:"tenant_id,pk"`
	OrgID           string    `bun:"org_id"`
	Name            string    `bun:"name"`
	State           int       `bun:"state"`
	RoleAssertion   bool      `bun:"project_role_assertion"`
	RoleCheck       bool      `bun:"project_role_check"`
	HasProjectCheck bool      `bun:"has_project_check"`
	PrivateLabeling int       `bun:"private_labeling_setting"`
	CreatedAt       time.Time `bun:"created_at"`
	DeletedAt       time.Time `bun:",soft_delete,nullzero"`
}
