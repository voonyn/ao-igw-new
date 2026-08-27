package user

import "time"

// CreateBody is what a create carries. It names an organization, because a
// person with no membership belongs nowhere, so the account and its membership
// are written together.
//
// Password is a credential. It is hashed before it is stored, and it never
// reaches a log line.
type CreateBody struct {
	OrgID    string `json:"orgId" validate:"required"`
	Username string `json:"username" validate:"required,min=1,max=255"`
	Email    string `json:"email" validate:"required,email,max=500"`

	FirstName   string `json:"firstName" validate:"max=255"`
	LastName    string `json:"lastName" validate:"max=255"`
	DisplayName string `json:"displayName" validate:"max=255"`
	Lang        string `json:"lang" validate:"max=20"`

	Password      string `json:"password" validate:"required,min=8,max=255"`
	EmailVerified bool   `json:"emailVerified"`
}

// InviteBody is what an invitation carries. An invitation is a membership
// grant for somebody who has no account yet, so it names an organization and
// the roles the membership holds, the same way a grant does.
//
// Only the two organization roles can be invited. A tenant membership is
// conferred on a person who already signed in, so no invitation carries one.
//
// Username is optional. An invitation with none names the account by the email
// address, because that is what the person types at the sign-in screen.
type InviteBody struct {
	Email string   `json:"email" validate:"required,email,max=500"`
	OrgID string   `json:"orgId" validate:"required"`
	Roles []string `json:"roles" validate:"required,min=1,max=2,dive,oneof=ORG_OWNER ORG_USER_MANAGER"`

	Username    string `json:"username" validate:"max=255"`
	DisplayName string `json:"displayName" validate:"max=255"`
}

// InviteView is the answer of one invitation. The token is disclosed here and
// nowhere else: the row stores a digest of it, and no log line carries it.
//
// Nothing sends the token yet. The transport is slice 10, so until it lands the
// operator hands the link over, and this answer is the only place it exists.
type InviteView struct {
	UserID  string    `json:"userId"`
	Email   string    `json:"email"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// UpdateBody is what an update carries: the profile of the person, and nothing
// that credentials a sign-in. The username, the email address, and the password
// are not writable here.
type UpdateBody struct {
	FirstName   string `json:"firstName" validate:"max=255"`
	LastName    string `json:"lastName" validate:"max=255"`
	DisplayName string `json:"displayName" validate:"max=255"`
	Lang        string `json:"lang" validate:"max=20"`
	Phone       string `json:"phone" validate:"max=50"`
}

// View is one account as the console reads it. Human is null for a machine
// account, which holds no person behind it.
type View struct {
	ID       string    `json:"id"`
	TenantID string    `json:"tenantId"`
	OrgID    string    `json:"orgId"`
	Username string    `json:"username"`
	UserType int       `json:"userType"`
	State    int       `json:"state"`
	Created  time.Time `json:"created"`

	// LastAuth is the most recent successful authentication. It is empty when
	// the person never authenticated, which the console renders as "Never".
	LastAuth string `json:"lastAuth"`

	MFAEnabled bool       `json:"mfaEnabled"`
	Human      *HumanView `json:"human"`
}

// HumanView is the person behind one account. It never carries the stored
// password hash.
type HumanView struct {
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	DisplayName string `json:"displayName"`
	Lang        string `json:"lang"`

	Email         string  `json:"email"`
	EmailVerified bool    `json:"emailVerified"`
	Phone         *string `json:"phone"`
	PhoneVerified bool    `json:"phoneVerified"`

	PwdChangeRequired bool       `json:"pwdChangeRequired"`
	PwdChangedAt      *time.Time `json:"pwdChangedAt"`

	// DIEnrolled says whether the Scan Verifier keeps an account for this person.
	// It is absent from the answer when this deployment runs no Scan Verifier, so
	// the console renders nothing that does not apply. The identifier itself
	// stays on the server: the console needs the state, not the value.
	DIEnrolled *bool `json:"diEnrolled,omitempty"`
}

// MembershipsView is every scope one person holds a membership in. Both halves
// come back whole, not paged: one person's memberships are bounded.
type MembershipsView struct {
	TenantMemberships []TenantMemberView `json:"tenantMemberships"`
	OrgMemberships    []OrgMemberView    `json:"orgMemberships"`
}

// TenantMemberView is the tenant roles of one person.
type TenantMemberView struct {
	TenantID string    `json:"tenantId"`
	UserID   string    `json:"userId"`
	UserName string    `json:"userName"`
	Roles    []string  `json:"roles"`
	Created  time.Time `json:"created"`
}

// OrgMemberView is the roles one person holds in one organization.
type OrgMemberView struct {
	TenantID string    `json:"tenantId"`
	OrgID    string    `json:"orgId"`
	UserID   string    `json:"userId"`
	UserName string    `json:"userName"`
	Roles    []string  `json:"roles"`
	Created  time.Time `json:"created"`
}

// ResetView is the answer of one password reset. The token is disclosed here and
// nowhere else: the row stores a digest of it, and no log line carries it.
//
// Nothing sends the token yet. The transport is slice 10, so until it lands the
// operator hands the value over, and this answer is the only place it exists.
type ResetView struct {
	UserID  string    `json:"userId"`
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// newView maps one account, and the person behind it, into the answer. di says
// whether this deployment runs a Scan Verifier, and it decides whether the
// enrolment field is in the answer at all.
func newView(row User, di bool) View {
	view := View{
		ID:         row.ID,
		TenantID:   row.TenantID,
		OrgID:      row.OrgID,
		Username:   row.Username,
		UserType:   row.UserType,
		State:      row.State,
		Created:    row.CreatedAt,
		MFAEnabled: row.MFAEnabled,
	}
	if !row.LastAuthAt.IsZero() {
		view.LastAuth = row.LastAuthAt.Format(time.RFC3339)
	}
	// A machine account holds no user_humans row, so it answers a null person.
	if row.UserType != TypeHuman {
		return view
	}

	view.Human = &HumanView{
		FirstName:         row.FirstName,
		LastName:          row.LastName,
		DisplayName:       row.DisplayName,
		Lang:              row.Lang,
		Email:             row.Email,
		EmailVerified:     row.IsEmailVerified,
		PhoneVerified:     row.IsPhoneVerified,
		PwdChangeRequired: row.PasswordChangeReq,
	}
	if row.Phone != "" {
		phone := row.Phone
		view.Human.Phone = &phone
	}
	if !row.PasswordChangedAt.IsZero() {
		changed := row.PasswordChangedAt
		view.Human.PwdChangedAt = &changed
	}
	if di {
		enrolled := row.DIUserUUID != ""
		view.Human.DIEnrolled = &enrolled
	}
	return view
}

// Me is what GET /api/v1/admin/me answers inside the envelope data. The console
// renders its shell from this one read: the person, the tenant, the roles, and
// the organizations it can switch between.
type Me struct {
	UserID      string `json:"userId"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`

	Tenant MeTenant `json:"tenant"`

	// IsTenantManager is true when TenantRoles holds a tenant role. The console
	// derives the same value for itself, so the server computes it once and both
	// agree.
	IsTenantManager bool `json:"isTenantManager"`

	TenantRoles    []string          `json:"tenantRoles"`
	OrgMemberships []MeOrgMembership `json:"orgMemberships"`

	// AccessibleOrgs holds every live organization of the tenant. The console
	// filters what it renders.
	AccessibleOrgs []MeOrg `json:"accessibleOrgs"`
}

// MeTenant is the tenant of the person, with the hostnames it answers on.
type MeTenant struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	State        int        `json:"state"`
	DefaultOrgID string     `json:"defaultOrgId"`
	Created      time.Time  `json:"created"`
	Domains      []MeDomain `json:"domains"`
}

// MeDomain is one live hostname of the tenant.
type MeDomain struct {
	Domain     string `json:"domain"`
	IsPrimary  bool   `json:"isPrimary"`
	IsVerified bool   `json:"isVerified"`
	State      int    `json:"state"`
}

// MeOrgMembership is the roles the person holds in one organization. UserName is
// empty, because the console reads the name from the person above.
type MeOrgMembership struct {
	TenantID string    `json:"tenantId"`
	OrgID    string    `json:"orgId"`
	UserID   string    `json:"userId"`
	UserName string    `json:"userName"`
	Roles    []string  `json:"roles"`
	Created  time.Time `json:"created"`
}

// MeOrg is one organization the console can switch to.
type MeOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
