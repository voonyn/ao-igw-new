// Package identityprovider holds the directories a tenant registers: the
// connection, the search, the attribute names, the domains a provider claims,
// and the Identity Link that ties one directory account to one person.
//
// The package imports neither the user domain nor the login session domain. It
// takes what it needs as function values in Deps, so the composition root wires
// every crossing.
package identityprovider

import (
	"time"

	"github.com/uptrace/bun"
)

// The values identity_providers.type holds. LDAP is the only type this gateway
// serves. A redirect provider adds a value here and columns beside the LDAP
// ones. See docs/adr/0013.
const TypeLDAP = 1

// The values identity_providers.state holds. An inactive provider and a
// soft-deleted provider behave alike at sign-in: both refuse every person tied
// to them.
const (
	StateActive   = 1
	StateInactive = 2
)

// The values identity_providers.mode holds. It is the transport of one LDAP
// connection, and it defaults to LDAPS. A boolean cannot tell StartTLS from
// LDAPS, because those two differ in port and in handshake.
const (
	ModePlain    = 1
	ModeStartTLS = 2
	ModeLDAPS    = 3
)

// Provider is one row of identity_providers.
//
// OrgID carries the level: an empty string is the tenant-wide row, and a UUID is
// that organization's own. DefaultOrgID names the organization a bind creates
// people in when OrgID is empty, because users.org_id is mandatory.
//
// Sealed holds the encrypted bind password the column stores. BindPassword holds
// the same credential in the clear, and it is not a column: the repository seals
// it on the way in and opens it on the way out, so no other layer handles the
// ciphertext. No view and no log line ever carries either one.
//
// Domains is not a column. It is the claim list of identity_provider_domains,
// which the service reads beside the row.
type Provider struct {
	bun.BaseModel `bun:"table:identity_providers,alias:ip"`

	ID           string `bun:"id,pk"`
	TenantID     string `bun:"tenant_id,pk"`
	OrgID        string `bun:"org_id"`
	Name         string `bun:"name"`
	Type         int    `bun:"type"`
	State        int    `bun:"state"`
	DefaultOrgID string `bun:"default_org_id,nullzero"`

	Mode      int      `bun:"mode"`
	Servers   []string `bun:"servers"`
	RootCA    string   `bun:"root_ca,nullzero"`
	TimeoutMS int      `bun:"timeout_ms"`

	BindDN            string   `bun:"bind_dn,nullzero"`
	Sealed            []byte   `bun:"bind_password,nullzero"`
	BaseDN            string   `bun:"base_dn,nullzero"`
	UserObjectClasses []string `bun:"user_object_classes"`
	UserFilters       []string `bun:"user_filters"`
	UserBase          string   `bun:"user_base,nullzero"`

	AttrID          string `bun:"attr_id,nullzero"`
	AttrUsername    string `bun:"attr_username,nullzero"`
	AttrEmail       string `bun:"attr_email,nullzero"`
	AttrFirstName   string `bun:"attr_first_name,nullzero"`
	AttrLastName    string `bun:"attr_last_name,nullzero"`
	AttrDisplayName string `bun:"attr_display_name,nullzero"`

	CreatedAt time.Time `bun:"created_at,nullzero"`
	DeletedAt time.Time `bun:",soft_delete,nullzero"`

	BindPassword string   `bun:"-"`
	Domains      []string `bun:"-"`
}

// Domain is one row of identity_provider_domains: one email domain a provider
// claims. The claim is an entity, so it carries deleted_at, and a re-claim
// revives the deleted row.
//
// (tenant_id, domain) is the primary key, so one domain belongs to at most one
// provider of a tenant and the database refuses the second claim.
type Domain struct {
	bun.BaseModel `bun:"table:identity_provider_domains,alias:ipd"`

	TenantID string `bun:"tenant_id,pk"`
	Domain   string `bun:"domain,pk"`
	IdpID    string `bun:"idp_id"`

	DeletedAt time.Time `bun:",soft_delete,nullzero"`
}

// Link is one row of identity_provider_user_links: the Identity Link that ties
// one directory account to one person.
//
// It is not an entity. It carries no deleted_at and it is hard deleted, because
// nobody re-reads an unlinked account: the idp.unlinked audit row is the record.
//
// ExternalID is the stable id of the directory, objectGUID in Active Directory,
// and never the username. ProviderName is read from identity_providers, because
// the console renders the directory a person is tied to.
type Link struct {
	bun.BaseModel `bun:"table:identity_provider_user_links,alias:ipl"`

	TenantID   string `bun:"tenant_id,pk"`
	IdpID      string `bun:"idp_id,pk"`
	ExternalID string `bun:"external_id,pk"`
	UserID     string `bun:"user_id"`

	CreatedAt time.Time `bun:"created_at,nullzero"`

	ProviderName string `bun:"provider_name,scanonly"`
}
