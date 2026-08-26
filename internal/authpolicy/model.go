package authpolicy

import (
	"time"

	"github.com/uptrace/bun"
)

// Row is one row of auth_policy_settings: the tenant default when OrgID is
// empty, and the override of one organization otherwise.
//
// Every knob is a pointer, because the column is nullable and NULL is the
// answer "inherit the level below". A stored value is an explicit setting, and
// zero is a value: a threshold of 0 disables lockout.
//
// The durations are stored in milliseconds and the API answers seconds, so the
// two names differ on purpose.
//
// PwDenyList is the JSON array the column holds, bound as a string. The console
// reads and writes a list of words, and the DTO does that conversion.
type Row struct {
	bun.BaseModel `bun:"table:auth_policy_settings,alias:ap"`

	TenantID string `bun:"tenant_id,pk"`
	OrgID    string `bun:"org_id,pk"`

	LockoutThreshold  *int `bun:"lockout_threshold"`
	LockoutWindowMS   *int `bun:"lockout_window_ms"`
	LockoutCooldownMS *int `bun:"lockout_cooldown_ms"`

	PwMinLength   *int    `bun:"pw_min_length"`
	PwMinClasses  *int    `bun:"pw_min_classes"`
	PwDenyList    *string `bun:"pw_deny_list"`
	PwCheckBreach *bool   `bun:"pw_check_breach"`

	RecoveryResetTTLMS  *int `bun:"recovery_reset_ttl_ms"`
	RecoveryVerifyTTLMS *int `bun:"recovery_verify_ttl_ms"`

	MFARequired *bool `bun:"mfa_required"`

	DeletedAt time.Time `bun:"deleted_at,soft_delete,nullzero"`
}
