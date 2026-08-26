package application

import (
	"strings"
	"time"

	"alphaomega/identitygateway/internal/oidc"
)

// OidcBody is the client of one application, as a create and an update carry
// it. Nine fields, and no more: every one of them is read by
// internal/oidc/client_repo.go or by the authorization request, except
// ParRequired, which the column stores flat beside them.
//
// SubjectType admits public only. internal/oidc/client_service.go refuses a
// pairwise client, so a stored pairwise value would register a client that
// cannot sign anybody in.
type OidcBody struct {
	ClientID         string   `json:"clientId" validate:"omitempty,max=36"`
	TokenAuthnMethod string   `json:"tokenAuthnMethod" validate:"required,oneof=client_secret_basic client_secret_post private_key_jwt none"`
	SubjectType      string   `json:"subjectType" validate:"required,oneof=public"`
	ParRequired      bool     `json:"parRequired"`
	RedirectUris     []string `json:"redirectUris" validate:"dive,required,url,max=2048"`
	PostLogoutUris   []string `json:"postLogoutUris" validate:"dive,required,url,max=2048"`
	GrantTypes       []string `json:"grantTypes" validate:"required,min=1,dive,required,max=64"`
	ResponseTypes    []string `json:"responseTypes" validate:"dive,required,max=64"`
	ScopeIDs         []string `json:"scopeIds" validate:"dive,required,max=64,excludesall= "`
}

// CreateBody is what a create carries. An application belongs to one project,
// and the project names the organization the gate reads.
//
// A SAML application carries no client, because no SAML table exists. Every
// other type carries one.
type CreateBody struct {
	ProjectID string    `json:"projectId" validate:"required"`
	Name      string    `json:"name" validate:"required,min=1,max=255"`
	AppType   int       `json:"appType" validate:"required,min=1,max=3"`
	OIDC      *OidcBody `json:"oidc" validate:"required_unless=AppType 2"`
}

// UpdateBody is what an update carries. An application does not move between
// projects, so the body carries no project.
type UpdateBody struct {
	Name string    `json:"name" validate:"required,min=1,max=255"`
	OIDC *OidcBody `json:"oidc"`
}

// View is one application as the console reads it.
type View struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenantId"`
	ProjectID   string    `json:"projectId"`
	ProjectName string    `json:"projectName"`
	OrgID       string    `json:"orgId"`
	Name        string    `json:"name"`
	AppType     int       `json:"appType"`
	State       int       `json:"state"`
	Created     time.Time `json:"created"`
	OIDC        *OidcView `json:"oidc"`
}

// OidcView is the client of one application as the console reads it. It carries
// whether a secret is set, never the stored hash.
type OidcView struct {
	ClientID       string     `json:"clientId"`
	AuthnMethod    string     `json:"authnMethod"`
	SecretSet      bool       `json:"secretSet"`
	SecretExpires  *time.Time `json:"secretExpires"`
	SubjectType    string     `json:"subjectType"`
	ParRequired    bool       `json:"parRequired"`
	DefaultMaxAge  *int       `json:"defaultMaxAge"`
	IsFirstParty   bool       `json:"isFirstParty"`
	RedirectUris   []string   `json:"redirectUris"`
	PostLogoutUris []string   `json:"postLogoutUris"`
	GrantTypes     []string   `json:"grantTypes"`
	ResponseTypes  []string   `json:"responseTypes"`
	ScopeIDs       []string   `json:"scopeIds"`
}

// SecretView is the answer of one rotation. The secret is disclosed here and
// nowhere else, so an operator who loses it rotates again.
type SecretView struct {
	ClientID string `json:"clientId"`
	Secret   string `json:"secret"`
}

// newView maps one application, and the client it holds, into the answer. A
// nil config answers a null client, which is what a SAML application reads.
func newView(row Application, cfg *oidc.Client) View {
	view := View{
		ID:          row.ID,
		TenantID:    row.TenantID,
		ProjectID:   row.ProjectID,
		ProjectName: row.ProjectName,
		OrgID:       row.OrgID,
		Name:        row.Name,
		AppType:     row.AppType,
		State:       row.State,
		Created:     row.CreatedAt,
	}
	if cfg == nil {
		return view
	}

	view.OIDC = &OidcView{
		ClientID:       cfg.ClientID,
		AuthnMethod:    cfg.TokenAuthnMethod,
		SecretSet:      cfg.Secret != "",
		SubjectType:    cfg.SubjectType,
		ParRequired:    cfg.ParRequired,
		IsFirstParty:   cfg.IsFirstParty,
		RedirectUris:   list(cfg.RedirectURIs),
		PostLogoutUris: list(cfg.PostLogoutRedirectURIs),
		GrantTypes:     list(cfg.GrantTypes),
		ResponseTypes:  list(cfg.ResponseTypes),
		ScopeIDs:       strings.Fields(cfg.Scopes),
	}
	if !cfg.SecretExpiresAt.IsZero() {
		expires := cfg.SecretExpiresAt
		view.OIDC.SecretExpires = &expires
	}
	if cfg.DefaultMaxAge != 0 {
		maxAge := cfg.DefaultMaxAge
		view.OIDC.DefaultMaxAge = &maxAge
	}
	return view
}

// list answers an empty array where the column held null, so the console reads
// a list it can render instead of a null it must guard.
func list(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// config maps the body into the row it writes. The stored secret, the created
// timestamp, and the first-party flag are not in the body, so the caller sets
// them.
func (b OidcBody) config(tenantID, appID string) oidc.Client {
	return oidc.Client{
		AppID:            appID,
		TenantID:         tenantID,
		ClientID:         b.ClientID,
		TokenAuthnMethod: b.TokenAuthnMethod,
		SubjectType:      b.SubjectType,
		ParRequired:      b.ParRequired,
		Scopes:           strings.Join(b.ScopeIDs, " "),
		// The three columns are NOT NULL, so an omitted list is written as an
		// empty array rather than as null.
		RedirectURIs:           list(b.RedirectUris),
		GrantTypes:             list(b.GrantTypes),
		ResponseTypes:          list(b.ResponseTypes),
		PostLogoutRedirectURIs: b.PostLogoutUris,
	}
}
