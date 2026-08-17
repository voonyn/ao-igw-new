package notification

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/utils"
)

// ErrNoSettings reports that the tenant configured no delivery. It never reaches
// the client: a tenant without a row sends over the log transport, which is what
// the column defaults say.
var ErrNoSettings = errors.New("notification settings not found")

// ErrNoTemplate reports that the level holds no override of the key. It never
// reaches the client: a level that stores nothing inherits the level below, and
// a revert of an override that is not there has already reached the state it
// asks for.
var ErrNoTemplate = errors.New("notification template override not found")

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

// settingsColumns names every column a write of the delivery settings replaces.
// created_at and updated_at are left to the table.
var settingsColumns = []string{
	"transport", "smtp_host", "smtp_port", "smtp_username", "smtp_password",
	"from_address", "from_name", "tls_mode", "send_timeout_ms",
}

// templateColumns names every column a write of one override replaces.
var templateColumns = []string{"subject", "body_text", "body_html"}

// Repository reads and writes the delivery settings and the message-template
// overrides of one tenant.
//
// The cipher seals the SMTP password at rest. A nil cipher stores it in the
// clear, which matches the development bootstrap and nothing else.
type Repository struct {
	db     *bun.DB
	cipher *aocrypto.Cipher
	log    logger.Logger
}

func NewRepository(bdb *bun.DB, cipher *aocrypto.Cipher, log logger.Logger) *Repository {
	return &Repository{db: bdb, cipher: cipher, log: log}
}

// FindSettings reads the delivery settings of one tenant, with the SMTP password
// opened. A tenant that configured nothing answers ErrNoSettings, which the
// service reads as "the defaults apply".
func (r *Repository) FindSettings(ctx context.Context, tenantID string) (Settings, error) {
	r.log.Debug("read the delivery settings", logger.String("tenant_id", tenantID))

	var row Settings
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("ns.tenant_id = ?", tenantID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Settings{}, fmt.Errorf("%w: tenant %s", ErrNoSettings, tenantID)
	}
	if err != nil {
		return Settings{}, fmt.Errorf("read the delivery settings of tenant %s: %w", tenantID, err)
	}

	if len(row.Sealed) > 0 {
		if err := aocrypto.OpenJSON(r.cipher, row.Sealed, &row.Password); err != nil {
			return Settings{}, fmt.Errorf("open the SMTP password of tenant %s: %w", tenantID, err)
		}
	}
	row.Sealed = nil
	return row, nil
}

// UpsertSettings writes the whole row of one tenant. It runs on the caller's
// transaction.
//
// deleted_at is cleared with it: the primary key is the tenant, so a row that
// was soft deleted once must be writable again.
func (r *Repository) UpsertSettings(ctx context.Context, row Settings) error {
	r.log.Debug("write the delivery settings", logger.String("tenant_id", row.TenantID))

	if row.Password != "" {
		sealed, err := aocrypto.SealJSON(r.cipher, row.Password)
		if err != nil {
			return fmt.Errorf("seal the SMTP password of tenant %s: %w", row.TenantID, err)
		}
		row.Sealed = sealed
	} else {
		row.Sealed = nil
	}

	q := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column(append([]string{"tenant_id"}, settingsColumns...)...).
		On("DUPLICATE KEY UPDATE")
	for _, col := range settingsColumns {
		q = q.Set(col + " = VALUES(" + col + ")")
	}

	if _, err := q.Set("deleted_at = NULL").Exec(ctx); err != nil {
		return fmt.Errorf("write the delivery settings of tenant %s: %w", row.TenantID, err)
	}
	return nil
}

// FindTemplate reads the live override of one key at one level. An empty orgID
// reads the tenant-wide override.
func (r *Repository) FindTemplate(ctx context.Context, tenantID, orgID, key string) (Template, error) {
	r.log.Debug("read a template override",
		logger.String("tenant_id", tenantID),
		logger.String("org_id", orgID),
		logger.String("template_key", key))

	var row Template
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("nt.tenant_id = ?", tenantID).
		Where("nt.org_id = ?", orgID).
		Where("nt.template_key = ?", key).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Template{}, fmt.Errorf("%w: tenant %s, org %q, key %s", ErrNoTemplate, tenantID, orgID, key)
	}
	if err != nil {
		return Template{}, fmt.Errorf("read the %s override of tenant %s, org %q: %w",
			key, tenantID, orgID, err)
	}
	return row, nil
}

// UpsertTemplate writes the override of one key at one level. It runs on the
// caller's transaction.
//
// The unique key spans the level, the key, and the deleted marker, so a write
// over a live row replaces its content and a write after a revert inserts a new
// row beside the deleted one.
func (r *Repository) UpsertTemplate(ctx context.Context, row Template) error {
	if row.ID == "" {
		row.ID = utils.NewUUIDv7()
	}

	q := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column("id", "tenant_id", "org_id", "template_key", "subject", "body_text", "body_html").
		On("DUPLICATE KEY UPDATE")
	for _, col := range templateColumns {
		q = q.Set(col + " = VALUES(" + col + ")")
	}

	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("write the %s override of tenant %s, org %q: %w",
			row.Key, row.TenantID, row.OrgID, err)
	}
	return nil
}

// RemoveTemplate marks the override of one key at one level deleted. It runs on
// the caller's transaction.
//
// The row is soft deleted, not dropped: an operator wrote the message, and the
// trail of what a tenant once sent answers a question a dropped row cannot.
func (r *Repository) RemoveTemplate(ctx context.Context, tenantID, orgID, key string) error {
	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Template)(nil)).
		Where("nt.tenant_id = ?", tenantID).
		Where("nt.org_id = ?", orgID).
		Where("nt.template_key = ?", key).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("remove the %s override of tenant %s, org %q: %w", key, tenantID, orgID, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count the written rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: tenant %s, org %q, key %s", ErrNoTemplate, tenantID, orgID, key)
	}
	return nil
}
