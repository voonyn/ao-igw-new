package tenant

import "time"

// AddDomainBody is the body of one domain add. The host is bare: no scheme, no
// path, and a port only for a non-standard listener.
//
// A host with a port and a host without one are both valid, so the rule is one
// of the two. The backend is the enforcement point, and the console field is a
// convenience.
type AddDomainBody struct {
	Domain string `json:"domain" validate:"required,max=255,hostname_rfc1123|hostname_port"`
}

// View is the tenant as the console reads it: the record, and every hostname
// the tenant holds.
type View struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	State        int          `json:"state"`
	DefaultOrgID string       `json:"defaultOrgId"`
	Created      time.Time    `json:"created"`
	Domains      []DomainView `json:"domains"`
}

// DomainView is one hostname of the tenant. A removed host reads state 2 and
// stays in the list, because the row still holds the globally unique host.
type DomainView struct {
	Domain     string `json:"domain"`
	IsPrimary  bool   `json:"isPrimary"`
	IsVerified bool   `json:"isVerified"`
	State      int    `json:"state"`
}

// BootstrapView is the singleton bootstrap record as the console reads it.
//
// Artifacts is always a list and never null, because the console iterates it
// without a guard. The routine records no per-artifact provenance, so the list
// is empty and the console says so.
type BootstrapView struct {
	ID        int            `json:"id"`
	TenantID  string         `json:"tenantId"`
	Version   string         `json:"version"`
	AppliedAt time.Time      `json:"appliedAt"`
	Artifacts []ArtifactView `json:"artifacts"`
}

// ArtifactView is one thing the bootstrap routine created.
type ArtifactView struct {
	Label  string `json:"label"`
	Detail string `json:"detail"`
}
