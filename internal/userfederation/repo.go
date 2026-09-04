package userfederation

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

// ErrNotFound reports that no live federation of the tenant carries the id.
var ErrNotFound = errors.New("identity provider not found")

// ErrDomainClaimed reports that a live federation of the tenant already claims one
// of the domains the write asked for. A domain belongs to at most one federation,
// and the database enforces it.
var ErrDomainClaimed = errors.New("domain already claimed")

// ErrNameTaken reports that a live federation of the tenant already carries the
// name. uq_user_federations_name enforces it, and the functional key part maps
// a NULL deleted_at to an epoch, so a soft-deleted federation does not hold its
// name for ever.
var ErrNameTaken = errors.New("identity provider name already used")

// ErrLinkNotFound reports that the person holds no Federation Link with the
// federation the route named.
var ErrLinkNotFound = errors.New("identity link not found")

// federationColumns names every column a write of one federation replaces. The id,
// the tenant, and the level are not in it: a create sets them and an update
// keeps them, so no write moves a federation between the two levels.
//
// server_type is not in it either. No body carries the value yet, so a create
// takes the column default and an update leaves it alone. Add it here in the
// same change that lets the console pick the server.
var federationColumns = []string{
	"name", "type", "state", "default_org_id",
	"mode", "servers", "root_ca", "timeout_ms",
	"bind_dn", "bind_password", "base_dn", "user_object_classes", "user_filters", "user_base",
	"attr_id", "attr_username", "attr_email", "attr_first_name", "attr_last_name",
	"attr_display_name",
}

// federationNameJoin reads the federation one Federation Link points at. It is a LEFT
// JOIN over the live federations only, so a soft-deleted federation stays invisible
// and the link it left behind is still listed and still unlinkable.
const federationNameJoin = `LEFT JOIN user_federations AS uf
	ON uf.id = ufl.federation_id AND uf.tenant_id = ufl.tenant_id AND uf.deleted_at IS NULL`

// The two joins Federation Resolution reads a federation through. Each one is an
// inner join, so a domain and a link whose federation is soft deleted match
// nothing. The caller adds the state, because the value is a constant of this
// package and not a literal in a SQL string.
//
// The alias differs per table, so the two clauses cannot be one.
const (
	domainFederationJoin = `JOIN user_federations AS uf
		ON uf.id = ufd.federation_id AND uf.tenant_id = ufd.tenant_id AND uf.deleted_at IS NULL`

	linkFederationJoin = `JOIN user_federations AS uf
		ON uf.id = ufl.federation_id AND uf.tenant_id = ufl.tenant_id AND uf.deleted_at IS NULL`
)

// Repository reads and writes the user federations, the domains they claim,
// and the Federation Links of one tenant.
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

// List reads every live federation of one tenant, newest first. The list is
// bounded — a tenant registers a handful of directories — so it answers whole
// and it is not paged.
func (r *Repository) List(ctx context.Context, tenantID string) ([]Federation, error) {
	r.log.Debug("list identity providers",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var rows []Federation
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("uf.tenant_id = ?", tenantID).
		Order("uf.created_at DESC", "uf.id DESC").
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

// FindByID reads one live federation of a tenant, with the bind password opened. A
// miss returns ErrNotFound, and a soft-deleted federation is a miss.
func (r *Repository) FindByID(ctx context.Context, tenantID, federationID string) (Federation, error) {
	r.log.Debug("read identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))

	var row Federation
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("uf.tenant_id = ?", tenantID).
		Where("uf.id = ?", federationID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Federation{}, fmt.Errorf("%w: tenant %s, provider %s", ErrNotFound, tenantID, federationID)
	}
	if err != nil {
		return Federation{}, fmt.Errorf("read identity provider %s of tenant %s: %w", federationID, tenantID, err)
	}

	if err := r.open(&row); err != nil {
		return Federation{}, err
	}
	r.log.Debug("found identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))
	return row, nil
}

// Insert writes one new federation. It runs on the caller's transaction.
func (r *Repository) Insert(ctx context.Context, row Federation) error {
	r.log.Debug("create identity provider",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.ID), logger.RequestID(ctx))

	if err := r.seal(&row); err != nil {
		return err
	}

	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column(append([]string{"id", "tenant_id", "org_id", "created_at"}, federationColumns...)...).
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

// Update writes every field of one federation. It runs on the caller's
// transaction.
//
// The level and the created timestamp are not written, so an update never moves
// a federation between the tenant level and an organization.
func (r *Repository) Update(ctx context.Context, row Federation) error {
	r.log.Debug("update identity provider",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.ID), logger.RequestID(ctx))

	if err := r.seal(&row); err != nil {
		return err
	}

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column(federationColumns...).
		Where("uf.tenant_id = ?", row.TenantID).
		Where("uf.id = ?", row.ID).
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

// Delete marks one federation deleted, and releases every domain it claimed. It
// runs on the caller's transaction.
//
// The claims go with it, because a domain a deleted federation still held would
// route every person who carries it to a directory nobody can reach, and no
// other federation could ever claim it.
//
// The Federation Links stay. An administrator whose directory is gone for good
// must be able to delete the federation, and the links record who was tied to it.
func (r *Repository) Delete(ctx context.Context, tenantID, federationID string) error {
	r.log.Debug("delete identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Federation)(nil)).
		Where("uf.tenant_id = ?", tenantID).
		Where("uf.id = ?", federationID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete identity provider %s of tenant %s: %w", federationID, tenantID, err)
	}
	if err := affected(res, ErrNotFound); err != nil {
		return fmt.Errorf("%w: tenant %s, provider %s", err, tenantID, federationID)
	}

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Domain)(nil)).
		Where("ufd.tenant_id = ?", tenantID).
		Where("ufd.federation_id = ?", federationID).
		Exec(ctx); err != nil {
		return fmt.Errorf("release the domains of provider %s of tenant %s: %w", federationID, tenantID, err)
	}

	r.log.Debug("deleted identity provider",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))
	return nil
}

// Domains reads the live claims of the federations it is given. A federation that
// claims nothing is simply absent from the answer.
func (r *Repository) Domains(ctx context.Context, tenantID string, federationIDs []string) ([]Domain, error) {
	r.log.Debug("read the claimed domains",
		logger.String("tenant_id", tenantID), logger.Int("count", len(federationIDs)), logger.RequestID(ctx))

	if len(federationIDs) == 0 {
		r.log.Debug("read no claimed domains",
			logger.String("tenant_id", tenantID), logger.RequestID(ctx))
		return nil, nil
	}

	var rows []Domain
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("ufd.tenant_id = ?", tenantID).
		Where("ufd.federation_id IN (?)", bun.In(federationIDs)).
		Order("ufd.domain ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the claimed domains of tenant %s: %w", tenantID, err)
	}
	r.log.Debug("found the claimed domains",
		logger.String("tenant_id", tenantID), logger.Int("count", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// Claim replaces the whole domain list of one federation. It runs on the caller's
// transaction.
//
// A domain the write dropped is released first. The claims that stay are then
// written, and the revive keeps the owner of a live row:
//
//	federation_id = IF(deleted_at IS NULL, federation_id, VALUES(federation_id))
//
// so a domain another live federation holds keeps its owner and changes nothing.
// The rows are read back, and a domain that names another federation answers
// ErrDomainClaimed. That is what makes the database, and not a read-then-write
// in Go, the thing that settles a race between two administrators.
func (r *Repository) Claim(ctx context.Context, tenantID, federationID string, claimed []string) error {
	r.log.Debug("claim domains",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID),
		logger.Int("count", len(claimed)), logger.RequestID(ctx))

	release := db.Conn(ctx, r.db).NewDelete().
		Model((*Domain)(nil)).
		Where("ufd.tenant_id = ?", tenantID).
		Where("ufd.federation_id = ?", federationID)
	if len(claimed) > 0 {
		release = release.Where("ufd.domain NOT IN (?)", bun.In(claimed))
	}
	if _, err := release.Exec(ctx); err != nil {
		return fmt.Errorf("release the domains of provider %s of tenant %s: %w", federationID, tenantID, err)
	}
	if len(claimed) == 0 {
		r.log.Debug("released every claimed domain",
			logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))
		return nil
	}

	rows := make([]Domain, 0, len(claimed))
	for _, domain := range claimed {
		rows = append(rows, Domain{TenantID: tenantID, Domain: domain, FederationID: federationID})
	}
	if _, err := db.Conn(ctx, r.db).NewInsert().
		Model(&rows).
		Column("tenant_id", "domain", "federation_id").
		On("DUPLICATE KEY UPDATE").
		Set("federation_id = IF(deleted_at IS NULL, federation_id, VALUES(federation_id))").
		Set("deleted_at = NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("claim the domains of provider %s of tenant %s: %w", federationID, tenantID, err)
	}

	var stored []Domain
	if err := db.Conn(ctx, r.db).NewSelect().
		Model(&stored).
		Where("ufd.tenant_id = ?", tenantID).
		Where("ufd.domain IN (?)", bun.In(claimed)).
		Scan(ctx); err != nil {
		return fmt.Errorf("read back the domains of provider %s of tenant %s: %w", federationID, tenantID, err)
	}
	for _, row := range stored {
		if row.FederationID != federationID {
			return fmt.Errorf("%w: %s", ErrDomainClaimed, row.Domain)
		}
	}

	r.log.Debug("claimed domains",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))
	return nil
}

// Links reads every Federation Link of one person, with the name of the federation
// each one points at.
func (r *Repository) Links(ctx context.Context, tenantID, userID string) ([]Link, error) {
	r.log.Debug("list identity links",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	var rows []Link
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("ufl.tenant_id, ufl.federation_id, ufl.external_id, ufl.user_id, ufl.created_at").
		ColumnExpr("IFNULL(uf.name, '') AS federation_name").
		Join(federationNameJoin).
		Where("ufl.tenant_id = ?", tenantID).
		Where("ufl.user_id = ?", userID).
		Order("ufl.created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the identity links of user %s of tenant %s: %w", userID, tenantID, err)
	}
	r.log.Debug("listed identity links",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Int("count", len(rows)), logger.RequestID(ctx))
	return rows, nil
}

// LinkedUser answers the person one directory account is tied to, read by the
// stable external id the Federation Link holds. A miss answers ErrLinkNotFound.
//
// It is the read every bind after the first one takes. The typed identifier
// matches no column reliably: the federation maps the username and the email, and
// the person can type a third form that is neither, such as a User Principal
// Name. The external id is the one value that does not move.
func (r *Repository) LinkedUser(ctx context.Context, tenantID, federationID, externalID string) (string, error) {
	r.log.Debug("read the person one directory account is tied to",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))

	var userID string
	err := db.Conn(ctx, r.db).NewSelect().
		Model((*Link)(nil)).
		ColumnExpr("ufl.user_id").
		Where("ufl.tenant_id = ?", tenantID).
		Where("ufl.federation_id = ?", federationID).
		Where("ufl.external_id = ?", externalID).
		Scan(ctx, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrLinkNotFound, tenantID, federationID)
	}
	if err != nil {
		return "", fmt.Errorf("read the person tied to provider %s of tenant %s: %w", federationID, tenantID, err)
	}

	r.log.Debug("found the person one directory account is tied to",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID),
		logger.String("user_id", userID), logger.RequestID(ctx))
	return userID, nil
}

// InsertLink writes the Federation Link one first bind creates. It runs on the
// caller's transaction, so the person and the link land together.
//
// The primary key is (tenant_id, federation_id, external_id) and a second unique key
// covers (tenant_id, federation_id, user_id), so a directory account already tied to
// somebody, and a person already tied to this directory, are both refused by the
// database.
func (r *Repository) InsertLink(ctx context.Context, row Link) error {
	r.log.Debug("write identity link",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.FederationID),
		logger.String("user_id", row.UserID), logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write the identity link of user %s with provider %s: %w",
			row.UserID, row.FederationID, err)
	}
	r.log.Debug("wrote identity link",
		logger.String("tenant_id", row.TenantID), logger.String("idp_id", row.FederationID),
		logger.String("user_id", row.UserID), logger.RequestID(ctx))
	return nil
}

// DeleteLink removes the Federation Link one person holds with one federation. It
// runs on the caller's transaction.
//
// The row is hard deleted. The link is not an entity, nobody re-reads an
// unlinked account, and the idp.unlinked audit row is the record.
//
// One person holds at most one account per federation, which the unique key
// enforces, so the federation names exactly one link of one person.
func (r *Repository) DeleteLink(ctx context.Context, tenantID, federationID, userID string) error {
	r.log.Debug("delete identity link",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID),
		logger.String("user_id", userID), logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Link)(nil)).
		Where("ufl.tenant_id = ?", tenantID).
		Where("ufl.federation_id = ?", federationID).
		Where("ufl.user_id = ?", userID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete the identity link of user %s with provider %s: %w", userID, federationID, err)
	}
	if err := affected(res, ErrLinkNotFound); err != nil {
		return fmt.Errorf("%w: user %s, provider %s", err, userID, federationID)
	}
	r.log.Debug("deleted identity link",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID),
		logger.String("user_id", userID), logger.RequestID(ctx))
	return nil
}

// seal encrypts the bind password into the column the write stores. The caller
// holds a copy of the row, so the plaintext field of that copy is untouched, and
// it is not a column: no write carries the credential twice.
func (r *Repository) seal(row *Federation) error {
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
func (r *Repository) open(row *Federation) error {
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

// FindByDomain reads the federation that claims one email domain, live and active.
// A domain nobody claims, and a domain whose federation is inactive or soft
// deleted, both return ErrNotFound.
//
// The domain is part of an identifier, which is personal data, so it never
// reaches a log line.
func (r *Repository) FindByDomain(ctx context.Context, tenantID, domain string) (string, error) {
	r.log.Debug("read the identity provider that claims a domain",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var federationID string
	err := db.Conn(ctx, r.db).NewSelect().
		Model((*Domain)(nil)).
		ColumnExpr("ufd.federation_id").
		Join(domainFederationJoin).
		Where("ufd.tenant_id = ?", tenantID).
		Where("ufd.domain = ?", domain).
		Where("uf.state = ?", StateActive).
		Limit(1).
		Scan(ctx, &federationID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: tenant %s", ErrNotFound, tenantID)
	}
	if err != nil {
		return "", fmt.Errorf("read the identity provider that claims a domain of tenant %s: %w",
			tenantID, err)
	}

	r.log.Debug("found the identity provider that claims a domain",
		logger.String("tenant_id", tenantID), logger.String("idp_id", federationID), logger.RequestID(ctx))
	return federationID, nil
}

// LinkedFederations reads the federations one person holds a Federation Link with,
// narrowed to the live active ones that take a typed password.
//
// LDAP is the one type that takes a typed password. A redirect federation proves a
// sign-in somewhere else, so a link with one never routes the password step.
func (r *Repository) LinkedFederations(ctx context.Context, tenantID, userID string) ([]string, error) {
	r.log.Debug("read the linked identity providers of a person",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	var federationIDs []string
	err := db.Conn(ctx, r.db).NewSelect().
		Model((*Link)(nil)).
		ColumnExpr("ufl.federation_id").
		Join(linkFederationJoin).
		Where("ufl.tenant_id = ?", tenantID).
		Where("ufl.user_id = ?", userID).
		Where("uf.type = ?", TypeDirectory).
		Where("uf.state = ?", StateActive).
		Order("ufl.federation_id ASC").
		Scan(ctx, &federationIDs)
	if err != nil {
		return nil, fmt.Errorf("read the linked identity providers of user %s of tenant %s: %w",
			userID, tenantID, err)
	}

	r.log.Debug("found the linked identity providers of a person",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID),
		logger.Int("count", len(federationIDs)), logger.RequestID(ctx))
	return federationIDs, nil
}

// ActiveIDs reads every live active federation of one tenant, at both levels
// together. Federation Resolution counts them when an identifier names no account,
// and that case knows no organization yet.
func (r *Repository) ActiveIDs(ctx context.Context, tenantID string) ([]string, error) {
	r.log.Debug("read the active identity providers",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var federationIDs []string
	err := db.Conn(ctx, r.db).NewSelect().
		Model((*Federation)(nil)).
		ColumnExpr("uf.id").
		Where("uf.tenant_id = ?", tenantID).
		Where("uf.state = ?", StateActive).
		Order("uf.id ASC").
		Scan(ctx, &federationIDs)
	if err != nil {
		return nil, fmt.Errorf("read the active identity providers of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("found the active identity providers",
		logger.String("tenant_id", tenantID), logger.Int("count", len(federationIDs)), logger.RequestID(ctx))
	return federationIDs, nil
}
