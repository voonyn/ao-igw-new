package identityprovider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNotFound reports that no live provider of the tenant carries the id.
var ErrNotFound = errors.New("identity provider not found")

// ErrDomainClaimed reports that a live provider of the tenant already claims one
// of the domains the write asked for. A domain belongs to at most one provider,
// and the database enforces it.
var ErrDomainClaimed = errors.New("domain already claimed")

// ErrNameTaken reports that a live provider of the tenant already carries the
// name. uq_identity_providers_name enforces it, and the functional key part maps
// a NULL deleted_at to an epoch, so a soft-deleted provider does not hold its
// name for ever.
var ErrNameTaken = errors.New("identity provider name already used")

// ErrLinkNotFound reports that the person holds no Identity Link with the
// provider the route named.
var ErrLinkNotFound = errors.New("identity link not found")

// providerColumns names every column a write of one provider replaces. The id,
// the tenant, and the level are not in it: a create sets them and an update
// keeps them, so no write moves a provider between the two levels.
var providerColumns = []string{
	"name", "type", "state", "default_org_id",
	"mode", "servers", "root_ca", "timeout_ms",
	"bind_dn", "bind_password", "base_dn", "user_object_classes", "user_filters", "user_base",
	"attr_id", "attr_username", "attr_email", "attr_first_name", "attr_last_name",
	"attr_display_name",
}

// providerNameJoin reads the provider one Identity Link points at. It is a LEFT
// JOIN over the live providers only, so a soft-deleted provider stays invisible
// and the link it left behind is still listed and still unlinkable.
const providerNameJoin = `LEFT JOIN identity_providers AS ip
	ON ip.id = ipl.idp_id AND ip.tenant_id = ipl.tenant_id AND ip.deleted_at IS NULL`

// Repository reads and writes the identity providers, the domains they claim,
// and the Identity Links of one tenant.
//
// The cipher seals the bind password at rest. A nil cipher stores it in the
// clear, which matches the development bootstrap and nothing else.
type Repository struct {
	db     *bun.DB
	cipher *aocrypto.Cipher
	log    logger.Logger
}

func NewRepository(bdb *bun.DB, cipher *aocrypto.Cipher, log logger.Logger) *Repository {
	return &Repository{db: bdb, cipher: cipher, log: log}
}

// List reads every live provider of one tenant, newest first. The list is
// bounded — a tenant registers a handful of directories — so it answers whole
// and it is not paged.
func (r *Repository) List(ctx context.Context, tenantID string) ([]Provider, error) {
	r.log.Debug("list identity providers",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var rows []Provider
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("ip.tenant_id = ?", tenantID).
		Order("ip.created_at DESC", "ip.id DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the identity providers of tenant %s: %w", tenantID, err)
	}

	for i := range rows {
		if err := r.open(&rows[i]); err != nil {
			return nil, err
		}
	}
	r.log.Debug("listed identity providers",
		logger.String("tenant_id", tenantID), logger.Int("count", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// FindByID reads one live provider of a tenant, with the bind password opened. A
// miss returns ErrNotFound, and a soft-deleted provider is a miss.
func (r *Repository) FindByID(ctx context.Context, tenantID, idpID string) (Provider, error) {
	r.log.Debug("read identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	var row Provider
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("ip.tenant_id = ?", tenantID).
		Where("ip.id = ?", idpID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Provider{}, fmt.Errorf("%w: tenant %s, provider %s", ErrNotFound, tenantID, idpID)
	}
	if err != nil {
		return Provider{}, fmt.Errorf("read identity provider %s of tenant %s: %w", idpID, tenantID, err)
	}

	if err := r.open(&row); err != nil {
		return Provider{}, err
	}
	r.log.Debug("found identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))
	return row, nil
}

// Insert writes one new provider. It runs on the caller's transaction.
func (r *Repository) Insert(ctx context.Context, row Provider) error {
	r.log.Debug("create identity provider",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.ID), logger.RequestID(ctx))

	if err := r.seal(&row); err != nil {
		return err
	}

	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column(append([]string{"id", "tenant_id", "org_id", "created_at"}, providerColumns...)...).
		Exec(ctx)
	if err != nil {
		if db.IsUniqueViolation(err) {
			return fmt.Errorf("%w: tenant %s, name %q", ErrNameTaken, row.TenantID, row.Name)
		}
		return fmt.Errorf("create identity provider %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	r.log.Debug("created identity provider",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.ID), logger.RequestID(ctx))
	return nil
}

// Update writes every field of one provider. It runs on the caller's
// transaction.
//
// The level and the created timestamp are not written, so an update never moves
// a provider between the tenant level and an organization.
func (r *Repository) Update(ctx context.Context, row Provider) error {
	r.log.Debug("update identity provider",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.ID), logger.RequestID(ctx))

	if err := r.seal(&row); err != nil {
		return err
	}

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column(providerColumns...).
		Where("ip.tenant_id = ?", row.TenantID).
		Where("ip.id = ?", row.ID).
		Exec(ctx)
	if err != nil {
		if db.IsUniqueViolation(err) {
			return fmt.Errorf("%w: tenant %s, name %q", ErrNameTaken, row.TenantID, row.Name)
		}
		return fmt.Errorf("update identity provider %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	if err := affected(res, ErrNotFound); err != nil {
		return fmt.Errorf("%w: tenant %s, provider %s", err, row.TenantID, row.ID)
	}
	r.log.Debug("updated identity provider",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.ID), logger.RequestID(ctx))
	return nil
}

// Delete marks one provider deleted, and releases every domain it claimed. It
// runs on the caller's transaction.
//
// The claims go with it, because a domain a deleted provider still held would
// route every person who carries it to a directory nobody can reach, and no
// other provider could ever claim it.
//
// The Identity Links stay. An administrator whose directory is gone for good
// must be able to delete the provider, and the links record who was tied to it.
func (r *Repository) Delete(ctx context.Context, tenantID, idpID string) error {
	r.log.Debug("delete identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Provider)(nil)).
		Where("ip.tenant_id = ?", tenantID).
		Where("ip.id = ?", idpID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete identity provider %s of tenant %s: %w", idpID, tenantID, err)
	}
	if err := affected(res, ErrNotFound); err != nil {
		return fmt.Errorf("%w: tenant %s, provider %s", err, tenantID, idpID)
	}

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Domain)(nil)).
		Where("ipd.tenant_id = ?", tenantID).
		Where("ipd.idp_id = ?", idpID).
		Exec(ctx); err != nil {
		return fmt.Errorf("release the domains of provider %s of tenant %s: %w", idpID, tenantID, err)
	}

	r.log.Debug("deleted identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))
	return nil
}

// Domains reads the live claims of the providers it is given. A provider that
// claims nothing is simply absent from the answer.
func (r *Repository) Domains(ctx context.Context, tenantID string, idpIDs []string) ([]Domain, error) {
	r.log.Debug("read the claimed domains",
		logger.String("tenant_id", tenantID), logger.Int("count", len(idpIDs)), logger.RequestID(ctx))

	if len(idpIDs) == 0 {
		r.log.Debug("read no claimed domains",
			logger.String("tenant_id", tenantID), logger.RequestID(ctx))
		return nil, nil
	}

	var rows []Domain
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("ipd.tenant_id = ?", tenantID).
		Where("ipd.idp_id IN (?)", bun.In(idpIDs)).
		Order("ipd.domain ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the claimed domains of tenant %s: %w", tenantID, err)
	}
	r.log.Debug("found the claimed domains",
		logger.String("tenant_id", tenantID), logger.Int("count", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// Claim replaces the whole domain list of one provider. It runs on the caller's
// transaction.
//
// A domain the write dropped is released first. The claims that stay are then
// written, and the revive keeps the owner of a live row:
//
//	idp_id = IF(deleted_at IS NULL, idp_id, VALUES(idp_id))
//
// so a domain another live provider holds keeps its owner and changes nothing.
// The rows are read back, and a domain that names another provider answers
// ErrDomainClaimed. That is what makes the database, and not a read-then-write
// in Go, the thing that settles a race between two administrators.
func (r *Repository) Claim(ctx context.Context, tenantID, idpID string, claimed []string) error {
	r.log.Debug("claim domains",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID),
		logger.Int("count", len(claimed)), logger.RequestID(ctx))

	release := db.Conn(ctx, r.db).NewDelete().
		Model((*Domain)(nil)).
		Where("ipd.tenant_id = ?", tenantID).
		Where("ipd.idp_id = ?", idpID)
	if len(claimed) > 0 {
		release = release.Where("ipd.domain NOT IN (?)", bun.In(claimed))
	}
	if _, err := release.Exec(ctx); err != nil {
		return fmt.Errorf("release the domains of provider %s of tenant %s: %w", idpID, tenantID, err)
	}
	if len(claimed) == 0 {
		r.log.Debug("released every claimed domain",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))
		return nil
	}

	rows := make([]Domain, 0, len(claimed))
	for _, domain := range claimed {
		rows = append(rows, Domain{TenantID: tenantID, Domain: domain, IdpID: idpID})
	}
	if _, err := db.Conn(ctx, r.db).NewInsert().
		Model(&rows).
		Column("tenant_id", "domain", "idp_id").
		On("DUPLICATE KEY UPDATE").
		Set("idp_id = IF(deleted_at IS NULL, idp_id, VALUES(idp_id))").
		Set("deleted_at = NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("claim the domains of provider %s of tenant %s: %w", idpID, tenantID, err)
	}

	var stored []Domain
	if err := db.Conn(ctx, r.db).NewSelect().
		Model(&stored).
		Where("ipd.tenant_id = ?", tenantID).
		Where("ipd.domain IN (?)", bun.In(claimed)).
		Scan(ctx); err != nil {
		return fmt.Errorf("read back the domains of provider %s of tenant %s: %w", idpID, tenantID, err)
	}
	for _, row := range stored {
		if row.IdpID != idpID {
			return fmt.Errorf("%w: %s", ErrDomainClaimed, row.Domain)
		}
	}

	r.log.Debug("claimed domains",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))
	return nil
}

// Links reads every Identity Link of one person, with the name of the provider
// each one points at.
func (r *Repository) Links(ctx context.Context, tenantID, userID string) ([]Link, error) {
	r.log.Debug("list identity links",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	var rows []Link
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("ipl.tenant_id, ipl.idp_id, ipl.external_id, ipl.user_id, ipl.created_at").
		ColumnExpr("IFNULL(ip.name, '') AS provider_name").
		Join(providerNameJoin).
		Where("ipl.tenant_id = ?", tenantID).
		Where("ipl.user_id = ?", userID).
		Order("ipl.created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the identity links of user %s of tenant %s: %w", userID, tenantID, err)
	}
	r.log.Debug("listed identity links",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Int("count", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// DeleteLink removes the Identity Link one person holds with one provider. It
// runs on the caller's transaction.
//
// The row is hard deleted. The link is not an entity, nobody re-reads an
// unlinked account, and the idp.unlinked audit row is the record.
//
// One person holds at most one account per provider, which the unique key
// enforces, so the provider names exactly one link of one person.
func (r *Repository) DeleteLink(ctx context.Context, tenantID, idpID, userID string) error {
	r.log.Debug("delete identity link",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID),
		logger.String("user_id", userID), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Link)(nil)).
		Where("ipl.tenant_id = ?", tenantID).
		Where("ipl.idp_id = ?", idpID).
		Where("ipl.user_id = ?", userID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete the identity link of user %s with provider %s: %w", userID, idpID, err)
	}
	if err := affected(res, ErrLinkNotFound); err != nil {
		return fmt.Errorf("%w: user %s, provider %s", err, userID, idpID)
	}
	r.log.Debug("deleted identity link",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID),
		logger.String("user_id", userID), logger.RequestID(ctx))
	return nil
}

// seal encrypts the bind password into the column the write stores. The caller
// holds a copy of the row, so the plaintext field of that copy is untouched, and
// it is not a column: no write carries the credential twice.
func (r *Repository) seal(row *Provider) error {
	if row.BindPassword == "" {
		row.Sealed = nil
		return nil
	}
	sealed, err := aocrypto.SealJSON(r.cipher, row.BindPassword)
	if err != nil {
		return fmt.Errorf("seal the bind password of provider %s: %w", row.ID, err)
	}
	row.Sealed = sealed
	return nil
}

// open decrypts the bind password of one read row and nils the ciphertext, so no
// layer above this one ever holds the sealed bytes.
func (r *Repository) open(row *Provider) error {
	if len(row.Sealed) > 0 {
		if err := aocrypto.OpenJSON(r.cipher, row.Sealed, &row.BindPassword); err != nil {
			return fmt.Errorf("open the bind password of provider %s: %w", row.ID, err)
		}
	}
	row.Sealed = nil
	return nil
}

// affected answers miss when the statement wrote no row.
func affected(res sql.Result, miss error) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count the written rows: %w", err)
	}
	if rows == 0 {
		return miss
	}
	return nil
}
