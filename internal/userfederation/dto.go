package userfederation

import (
	"fmt"
	"strings"
	"time"
)

// The scheme each transport accepts. A plain bind and a StartTLS bind both dial
// the plaintext port and differ only in the handshake that follows, so both
// carry ldap://. LDAPS dials its own port, so it carries ldaps://.
var modeSchemes = map[int]string{
	ModePlain:    "ldap://",
	ModeStartTLS: "ldap://",
	ModeLDAPS:    "ldaps://",
}

// Body is the body of one federation write. The console submits the whole form,
// so every field except the bind password replaces what is stored.
//
// BindPassword is the one write-only field, and it is a pointer because three
// answers are possible: absent keeps the stored credential, an empty string
// clears it, and a value replaces it. No read path answers it in any shape.
//
// OrgID carries the level. An empty string is the tenant-wide federation, and a
// UUID is that organization's own. DefaultOrgID is required at tenant level,
// because users.org_id is mandatory and a tenant-wide federation that names no
// organization would create nobody.
//
// ConfirmPlaintext is the explicit confirmation a plain bind needs. A plain bind
// puts the password of every person on the wire in clear, so mode 1 is refused
// without it.
//
// AttrID and AttrUsername are the two attributes the gateway cannot work
// without: the id keys the Federation Link, and the username keys the person.
// Every other mapped attribute is optional, AttrEmail included. A directory
// that publishes no mail attribute is a real directory, and the read of one
// entry already answers the empty case.
//
// The bounds match the ones the console renders. The backend is the enforcement
// point, and the console form is a convenience for the operator.
type Body struct {
	OrgID        string `json:"orgId" validate:"omitempty,max=36"`
	Name         string `json:"name" validate:"required,min=1,max=255"`
	State        int    `json:"state" validate:"required,oneof=1 2"`
	DefaultOrgID string `json:"defaultOrgId" validate:"required_without=OrgID,omitempty,max=36"`

	Mode             int      `json:"mode" validate:"required,oneof=1 2 3"`
	ConfirmPlaintext bool     `json:"confirmPlaintext" validate:"required_if=Mode 1"`
	Servers          []string `json:"servers" validate:"required,min=1,max=10,dive,required,url,max=512"`
	RootCA           string   `json:"rootCa" validate:"omitempty,max=16384"`
	TimeoutSeconds   int      `json:"timeoutSeconds" validate:"required,min=1,max=60"`

	BindDN            string   `json:"bindDn" validate:"required,max=512"`
	BindPassword      *string  `json:"bindPassword" validate:"omitnil,max=255"`
	BaseDN            string   `json:"baseDn" validate:"required,max=512"`
	UserObjectClasses []string `json:"userObjectClasses" validate:"required,min=1,max=10,dive,required,max=255"`
	UserFilters       []string `json:"userFilters" validate:"required,min=1,max=10,dive,required,max=255"`
	UserBase          string   `json:"userBase" validate:"omitempty,max=512"`

	AttrID          string `json:"attrId" validate:"required,max=255"`
	AttrUsername    string `json:"attrUsername" validate:"required,max=255"`
	AttrEmail       string `json:"attrEmail" validate:"omitempty,max=255"`
	AttrFirstName   string `json:"attrFirstName" validate:"omitempty,max=255"`
	AttrLastName    string `json:"attrLastName" validate:"omitempty,max=255"`
	AttrDisplayName string `json:"attrDisplayName" validate:"omitempty,max=255"`

	Domains []string `json:"domains" validate:"omitempty,max=50,dive,required,fqdn,max=255"`
}

// View is one federation as the console reads it.
//
// BindPasswordSet reports that a credential is stored. The value is never
// carried: the console renders a badge and a change button from this one flag.
type View struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenantId"`
	OrgID        string `json:"orgId"`
	Name         string `json:"name"`
	Type         int    `json:"type"`
	State        int    `json:"state"`
	DefaultOrgID string `json:"defaultOrgId"`

	Mode           int      `json:"mode"`
	Servers        []string `json:"servers"`
	RootCA         string   `json:"rootCa"`
	TimeoutSeconds int      `json:"timeoutSeconds"`

	BindDN            string   `json:"bindDn"`
	BindPasswordSet   bool     `json:"bindPasswordSet"`
	BaseDN            string   `json:"baseDn"`
	UserObjectClasses []string `json:"userObjectClasses"`
	UserFilters       []string `json:"userFilters"`
	UserBase          string   `json:"userBase"`

	AttrID          string `json:"attrId"`
	AttrUsername    string `json:"attrUsername"`
	AttrEmail       string `json:"attrEmail"`
	AttrFirstName   string `json:"attrFirstName"`
	AttrLastName    string `json:"attrLastName"`
	AttrDisplayName string `json:"attrDisplayName"`

	Domains []string  `json:"domains"`
	Created time.Time `json:"created"`
}

// ClaimPreviewBody is the candidate domain list one preview reads. The console
// sends the box on screen, so the preview answers values nobody saved yet.
//
// OrgID carries the level, the same way Body.OrgID does. The preview names the
// people of the tenant, so the level decides nothing about the answer and
// everything about who may read it: a caller who cannot write a federation at that
// level cannot list the people a claim there would move.
//
// The bounds match Body.Domains. A preview of a list the save would refuse as
// malformed answers the same 422 the save does.
type ClaimPreviewBody struct {
	OrgID   string   `json:"orgId" validate:"omitempty,max=36"`
	Domains []string `json:"domains" validate:"omitempty,max=50,dive,required,fqdn,max=255"`
}

// ClaimPreview is what one claim preview answers.
//
// Total counts every person the claim moves. People is one capped page of them,
// so a tenant that holds a whole company at one domain reads the number without
// reading the company.
//
// The total sits in the answer and not in meta. meta carries the state of a
// pager, and this route has none: it answers one fixed sample and the count
// behind it, and no page of it is reachable. A meta block here would offer a
// page two that no caller can ask for.
type ClaimPreview struct {
	Total  int           `json:"total"`
	People []MovedPerson `json:"people"`
}

// MovedPerson is one person a candidate domain claim moves onto the directory.
//
// The email address is in it because the domain is what moved them, so the
// console shows the operator which domain of the form carries each name.
type MovedPerson struct {
	UserID   string `json:"userId"`
	Username string `json:"username"`
	Email    string `json:"email"`
}

// LinkView is one Federation Link as the console reads it.
//
// FederationID is the handle the unlink route takes. One person holds at most one
// account per federation, which the unique key enforces, so the federation names
// exactly one link of one person.
type LinkView struct {
	FederationID   string    `json:"idpId"`
	FederationName string    `json:"idpName"`
	ExternalID     string    `json:"externalId"`
	UserID         string    `json:"userId"`
	Created        time.Time `json:"created"`
}

// newView maps one federation into the answer. The bind password is not in it, in
// any shape: the flag reports that one is stored and nothing more.
func newView(row Federation) View {
	return View{
		ID:           row.ID,
		TenantID:     row.TenantID,
		OrgID:        row.OrgID,
		Name:         row.Name,
		Type:         row.Type,
		State:        row.State,
		DefaultOrgID: row.DefaultOrgID,

		Mode:           row.Mode,
		Servers:        list(row.Servers),
		RootCA:         row.RootCA,
		TimeoutSeconds: row.TimeoutMS / 1000,

		BindDN:            row.BindDN,
		BindPasswordSet:   row.BindPassword != "",
		BaseDN:            row.BaseDN,
		UserObjectClasses: list(row.UserObjectClasses),
		UserFilters:       list(row.UserFilters),
		UserBase:          row.UserBase,

		AttrID:          row.AttrID,
		AttrUsername:    row.AttrUsername,
		AttrEmail:       row.AttrEmail,
		AttrFirstName:   row.AttrFirstName,
		AttrLastName:    row.AttrLastName,
		AttrDisplayName: row.AttrDisplayName,

		Domains: list(row.Domains),
		Created: row.CreatedAt,
	}
}

// newLinkView maps one Federation Link into the answer.
func newLinkView(row Link) LinkView {
	return LinkView{
		FederationID:   row.FederationID,
		FederationName: row.FederationName,
		ExternalID:     row.ExternalID,
		UserID:         row.UserID,
		Created:        row.CreatedAt,
	}
}

// list answers an empty array where the column held null, so the console reads a
// list it can render instead of a null it must guard.
func list(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// apply writes one body onto the stored row and answers the row to store. A
// create passes the zero row, and an update passes the row it read.
//
// The bind password follows the write-only rule, so an absent field keeps what
// is stored, an empty string clears it, and a value replaces it.
//
// The level is not written here. A create takes it from the body and an update
// keeps the stored one, so no write moves a federation between the two levels.
func (b Body) apply(stored Federation) Federation {
	stored.Name = b.Name
	stored.Type = TypeDirectory
	stored.State = b.State
	stored.DefaultOrgID = b.DefaultOrgID

	stored.Mode = b.Mode
	stored.Servers = b.Servers
	stored.RootCA = b.RootCA
	stored.TimeoutMS = b.TimeoutSeconds * 1000

	stored.BindDN = b.BindDN
	stored.BaseDN = b.BaseDN
	stored.UserObjectClasses = b.UserObjectClasses
	stored.UserFilters = b.UserFilters
	stored.UserBase = b.UserBase

	stored.AttrID = b.AttrID
	stored.AttrUsername = b.AttrUsername
	stored.AttrEmail = b.AttrEmail
	stored.AttrFirstName = b.AttrFirstName
	stored.AttrLastName = b.AttrLastName
	stored.AttrDisplayName = b.AttrDisplayName

	if b.BindPassword != nil {
		stored.BindPassword = *b.BindPassword
	}
	stored.Domains = domains(b.Domains)
	return stored
}

// domains answers the claim list a write stores. Every domain is lowercased,
// because the column holds a bare host and an identifier is matched against it.
func domains(claimed []string) []string {
	out := make([]string, 0, len(claimed))
	for _, domain := range claimed {
		out = append(out, strings.ToLower(strings.TrimSpace(domain)))
	}
	return out
}

// checkServers refuses a server string that does not match the transport. The
// egress precedent of this repo configures no TLS at all and never checks a
// scheme, so this check is written out here rather than inherited.
func checkServers(mode int, servers []string) error {
	want, ok := modeSchemes[mode]
	if !ok {
		return fmt.Errorf("%w: mode %d", ErrServerScheme, mode)
	}
	for _, server := range servers {
		if !strings.HasPrefix(strings.ToLower(server), want) {
			return fmt.Errorf("%w: %s does not start with %s", ErrServerScheme, server, want)
		}
	}
	return nil
}
