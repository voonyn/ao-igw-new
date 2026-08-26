package notification

import (
	"time"

	"github.com/uptrace/bun"
)

// Settings is the row of notification_settings: one row per tenant.
//
// Sealed holds the encrypted SMTP password the column stores. Password holds the
// same credential in the clear, and it is not a column: the repository seals it
// on the way in and opens it on the way out, so no other layer handles the
// ciphertext and no layer above reads the column name.
type Settings struct {
	bun.BaseModel `bun:"table:notification_settings,alias:ns"`

	TenantID string `bun:"tenant_id,pk"`

	Transport     string `bun:"transport"`
	SMTPHost      string `bun:"smtp_host,nullzero"`
	SMTPPort      int    `bun:"smtp_port"`
	SMTPUsername  string `bun:"smtp_username,nullzero"`
	Sealed        []byte `bun:"smtp_password,nullzero"`
	FromAddress   string `bun:"from_address,nullzero"`
	FromName      string `bun:"from_name,nullzero"`
	TLSMode       string `bun:"tls_mode"`
	SendTimeoutMS int    `bun:"send_timeout_ms"`

	DeletedAt time.Time `bun:"deleted_at,soft_delete,nullzero"`

	Password string `bun:"-"`
}

// Template is one row of notification_templates: the override of one key at one
// level. OrgID is empty for the tenant-wide override, and a real organization id
// for that organization's own.
type Template struct {
	bun.BaseModel `bun:"table:notification_templates,alias:nt"`

	ID       string `bun:"id,pk"`
	TenantID string `bun:"tenant_id"`
	OrgID    string `bun:"org_id"`
	Key      string `bun:"template_key"`

	Subject  string `bun:"subject"`
	BodyText string `bun:"body_text"`
	BodyHTML string `bun:"body_html"`

	UpdatedAt time.Time `bun:"updated_at,nullzero"`
	DeletedAt time.Time `bun:"deleted_at,soft_delete,nullzero"`
}
