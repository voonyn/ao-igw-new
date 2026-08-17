package project

import "time"

// Settings is the four stored project settings. Nothing in the gateway reads
// them, so the console labels them "not enforced yet". PrivateLabeling holds
// the three values the console offers: 0 unspecified, 1 project branding, 2
// user-organization branding.
type Settings struct {
	RoleAssertion   bool `json:"roleAssertion"`
	RoleCheck       bool `json:"roleCheck"`
	HasProjectCheck bool `json:"hasProjectCheck"`
	PrivateLabeling int  `json:"privateLabeling" validate:"min=0,max=2"`
}

// CreateBody is what a create carries. A project belongs to one organization,
// so the body names it, and the gate reads that organization. The column holds
// 255 characters, and a name of only spaces names nothing.
type CreateBody struct {
	OrgID string `json:"orgId" validate:"required"`
	Name  string `json:"name" validate:"required,min=1,max=255"`
	Settings
}

// UpdateBody is what an update carries. A project does not move between
// organizations, so the body carries no organization.
type UpdateBody struct {
	Name string `json:"name" validate:"required,min=1,max=255"`
	Settings
}

// View is one project as the console reads it.
type View struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenantId"`
	OrgID    string    `json:"orgId"`
	Name     string    `json:"name"`
	State    int       `json:"state"`
	Created  time.Time `json:"created"`
	Settings
}

func newView(row Project) View {
	return View{
		ID:       row.ID,
		TenantID: row.TenantID,
		OrgID:    row.OrgID,
		Name:     row.Name,
		State:    row.State,
		Created:  row.CreatedAt,
		Settings: Settings{
			RoleAssertion:   row.RoleAssertion,
			RoleCheck:       row.RoleCheck,
			HasProjectCheck: row.HasProjectCheck,
			PrivateLabeling: row.PrivateLabeling,
		},
	}
}
