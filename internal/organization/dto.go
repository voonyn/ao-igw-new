package organization

import "time"

// Body is what a create and a rename carry. The column holds 500 characters,
// and a name of only spaces names nothing, so the tag refuses both.
type Body struct {
	Name string `json:"name" validate:"required,min=1,max=500"`
}

// View is one organization as the console reads it. IsDefault marks the
// organization self-registration points at, which the console badges and which
// no operator can delete.
type View struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenantId"`
	Name      string    `json:"name"`
	State     int       `json:"state"`
	Created   time.Time `json:"created"`
	IsDefault bool      `json:"isDefault"`
}

func newView(row Organization, defaultOrgID string) View {
	return View{
		ID:        row.ID,
		TenantID:  row.TenantID,
		Name:      row.Name,
		State:     row.State,
		Created:   row.CreatedAt,
		IsDefault: row.ID == defaultOrgID && defaultOrgID != "",
	}
}
