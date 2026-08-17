package authpolicy

import (
	"encoding/json"
	"time"
)

// The policy every level falls back to when nothing above it stores a value.
// bootstrap seeds a tenant with these, and a tenant whose row is missing a knob
// is governed by the same numbers.
const (
	DefaultLockoutThreshold  = 5
	DefaultLockoutWindow     = 15 * time.Minute
	DefaultLockoutCooldown   = 15 * time.Minute
	DefaultPwMinLength       = 8
	DefaultPwMinClasses      = 1
	DefaultPwCheckBreach     = false
	DefaultRecoveryResetTTL  = time.Hour
	DefaultRecoveryVerifyTTL = 24 * time.Hour
	DefaultMFARequired       = false
)

// Body is the body of one policy write. Every field is optional, and an absent
// or null field inherits the level below: the tenant default for an
// organization, and the code default for the tenant.
//
// A value is an explicit setting, and zero is a value. A lockoutThreshold of 0
// disables lockout, and a pwCheckBreach of false switches the check off, so
// neither can be read as "inherit". That is why every field is a pointer.
//
// The bounds match the ones the console renders. The backend is the enforcement
// point, and the console form is a convenience for the operator.
type Body struct {
	LockoutThreshold       *int `json:"lockoutThreshold" validate:"omitnil,min=0,max=1000"`
	LockoutWindowSeconds   *int `json:"lockoutWindowSeconds" validate:"omitnil,min=0,max=2592000"`
	LockoutCooldownSeconds *int `json:"lockoutCooldownSeconds" validate:"omitnil,min=0,max=2592000"`

	PwMinLength   *int     `json:"pwMinLength" validate:"omitnil,min=0,max=72"`
	PwMinClasses  *int     `json:"pwMinClasses" validate:"omitnil,min=0,max=4"`
	PwDenyList    []string `json:"pwDenyList" validate:"omitnil,max=1000,dive,max=191"`
	PwCheckBreach *bool    `json:"pwCheckBreach"`

	RecoveryResetTtlSeconds  *int `json:"recoveryResetTtlSeconds" validate:"omitnil,min=60,max=2592000"`
	RecoveryVerifyTtlSeconds *int `json:"recoveryVerifyTtlSeconds" validate:"omitnil,min=60,max=2592000"`

	MfaRequired *bool `json:"mfaRequired"`
}

// View is the policy one level enforces, as the console reads it. Every field
// carries the resolved value, whichever level it came from, so the console
// renders what a sign-in of this organization actually meets.
//
// Overridden names, per field, whether the value is set at the level that was
// read. A false there means the value came from the level below.
//
// OrgID is empty for the tenant default. The console echoes it back to know
// which scope the answer belongs to.
type View struct {
	OrgID string `json:"orgId"`

	LockoutThreshold       int `json:"lockoutThreshold"`
	LockoutWindowSeconds   int `json:"lockoutWindowSeconds"`
	LockoutCooldownSeconds int `json:"lockoutCooldownSeconds"`

	PwMinLength   int      `json:"pwMinLength"`
	PwMinClasses  int      `json:"pwMinClasses"`
	PwDenyList    []string `json:"pwDenyList"`
	PwCheckBreach bool     `json:"pwCheckBreach"`

	RecoveryResetTtlSeconds  int `json:"recoveryResetTtlSeconds"`
	RecoveryVerifyTtlSeconds int `json:"recoveryVerifyTtlSeconds"`

	MfaRequired bool `json:"mfaRequired"`

	Overridden map[string]bool `json:"overridden"`
}

// resolve answers the policy of one level. scope is the row of the level that
// was read, and below is the level it inherits from: the tenant default for an
// organization, and an empty row for the tenant.
func resolve(orgID string, scope, below Row) View {
	seconds := func(vals ...*int) int { return firstSet(0, vals...) / 1000 }

	return View{
		OrgID: orgID,

		LockoutThreshold: firstSet(DefaultLockoutThreshold, scope.LockoutThreshold, below.LockoutThreshold),
		LockoutWindowSeconds: seconds(scope.LockoutWindowMS, below.LockoutWindowMS,
			ms(DefaultLockoutWindow)),
		LockoutCooldownSeconds: seconds(scope.LockoutCooldownMS, below.LockoutCooldownMS,
			ms(DefaultLockoutCooldown)),

		PwMinLength:   firstSet(DefaultPwMinLength, scope.PwMinLength, below.PwMinLength),
		PwMinClasses:  firstSet(DefaultPwMinClasses, scope.PwMinClasses, below.PwMinClasses),
		PwDenyList:    denyList(firstSet("", scope.PwDenyList, below.PwDenyList)),
		PwCheckBreach: firstSet(DefaultPwCheckBreach, scope.PwCheckBreach, below.PwCheckBreach),

		RecoveryResetTtlSeconds: seconds(scope.RecoveryResetTTLMS, below.RecoveryResetTTLMS,
			ms(DefaultRecoveryResetTTL)),
		RecoveryVerifyTtlSeconds: seconds(scope.RecoveryVerifyTTLMS, below.RecoveryVerifyTTLMS,
			ms(DefaultRecoveryVerifyTTL)),

		MfaRequired: firstSet(DefaultMFARequired, scope.MFARequired, below.MFARequired),

		Overridden: map[string]bool{
			"lockoutThreshold":         scope.LockoutThreshold != nil,
			"lockoutWindowSeconds":     scope.LockoutWindowMS != nil,
			"lockoutCooldownSeconds":   scope.LockoutCooldownMS != nil,
			"pwMinLength":              scope.PwMinLength != nil,
			"pwMinClasses":             scope.PwMinClasses != nil,
			"pwDenyList":               scope.PwDenyList != nil,
			"pwCheckBreach":            scope.PwCheckBreach != nil,
			"recoveryResetTtlSeconds":  scope.RecoveryResetTTLMS != nil,
			"recoveryVerifyTtlSeconds": scope.RecoveryVerifyTTLMS != nil,
			"mfaRequired":              scope.MFARequired != nil,
		},
	}
}

// row turns one write into the row of a level. A field the body left out is
// written as NULL, so the level goes back to inheriting it.
func (b Body) row(tenantID, orgID string) Row {
	return Row{
		TenantID: tenantID,
		OrgID:    orgID,

		LockoutThreshold:  b.LockoutThreshold,
		LockoutWindowMS:   millis(b.LockoutWindowSeconds),
		LockoutCooldownMS: millis(b.LockoutCooldownSeconds),

		PwMinLength:   b.PwMinLength,
		PwMinClasses:  b.PwMinClasses,
		PwDenyList:    denyJSON(b.PwDenyList),
		PwCheckBreach: b.PwCheckBreach,

		RecoveryResetTTLMS:  millis(b.RecoveryResetTtlSeconds),
		RecoveryVerifyTTLMS: millis(b.RecoveryVerifyTtlSeconds),

		MFARequired: b.MfaRequired,
	}
}

// firstSet answers the first value that is set, and the fallback when none is.
// It is what "a stored value stops the inheritance" means, and a stored zero
// stops it the same way any other value does.
func firstSet[T any](fallback T, vals ...*T) T {
	for _, v := range vals {
		if v != nil {
			return *v
		}
	}
	return fallback
}

// ms answers a code default as the milliseconds the column stores, so one
// resolution reads all three levels the same way.
func ms(d time.Duration) *int {
	v := int(d / time.Millisecond)
	return &v
}

// millis turns the seconds the API takes into the milliseconds the column
// stores. An absent field stays absent.
func millis(seconds *int) *int {
	if seconds == nil {
		return nil
	}
	v := *seconds * 1000
	return &v
}

// denyList reads the JSON array the column holds. A value that does not parse
// answers an empty list: this API is the only writer of the column, so anything
// else is a repair job and not something the console can act on.
func denyList(stored string) []string {
	var words []string
	if stored == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(stored), &words); err != nil {
		return nil
	}
	return words
}

// denyJSON writes the list as the JSON array the column holds. An absent list
// stays absent, and an empty list is an explicit setting: it says this level
// denies no word, whatever the level below denies.
func denyJSON(words []string) *string {
	if words == nil {
		return nil
	}
	encoded, err := json.Marshal(words)
	if err != nil {
		return nil
	}
	stored := string(encoded)
	return &stored
}
