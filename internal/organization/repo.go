// Package organization holds the organizations of a tenant and the people who
// belong to them.
package organization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNotFound reports that no live organization of the tenant carries the id.
var ErrNotFound = errors.New("organization not found")

// ErrMemberNotFound reports that no live membership puts the person in the
// organization. A revoke of a membership nobody holds answers it.
var ErrMemberNotFound = errors.New("organization member not found")

// Repository reads and writes the organizations of one tenant.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// sortColumns maps a sort key of the route's allowlist to its column. The
// ORDER BY clause is built from this map only, so no query input reaches the
// SQL.
var sortColumns = map[string]string{
	"name":    "name",
	"state":   "state",
	"created": "created_at",
}

// List reads one page of the organizations of a tenant, and the total behind
// it. Every state comes back, because the console filters by state itself. A
// soft-deleted organization never does.
func (r *Repository) List(ctx context.Context, tenantID string, q Query) ([]Organization, int64, error) {
	r.log.Debug("list organizations",
		logger.String("tenant_id", tenantID), logger.Int("offset", q.Offset))

	var rows []Organization
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID)

	if q.Search != "" {
		sel = sel.Where("name LIKE ?", q.Search+"%")
	}
	if q.State != 0 {
		sel = sel.Where("state = ?", q.State)
	}

	// The id breaks a tie, so two organizations created in the same
	// millisecond keep one order across the pages of one walk.
	sel = sel.OrderExpr(orderBy(q)).Order("id DESC").
		Limit(q.Limit).Offset(q.Offset)

	total, err := sel.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list organizations of tenant %s: %w", tenantID, err)
	}
	return rows, int64(total), nil
}

// orderBy names the column and the direction one page reads in. An unknown key
// never reaches here, because the route refuses it, so a key this map does not
// hold takes the newest-first default.
func orderBy(q Query) string {
	column, ok := sortColumns[q.Sort]
	if !ok {
		return "created_at DESC"
	}
	if q.Desc {
		return column + " DESC"
	}
	return column + " ASC"
}

// FindByID reads one live organization of a tenant. A miss returns ErrNotFound.
func (r *Repository) FindByID(ctx context.Context, tenantID, orgID string) (Organization, error) {
	r.log.Debug("read organization",
		logger.String("tenant_id", tenantID), logger.String("org_id", orgID))

	var row Organization
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", orgID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Organization{}, fmt.Errorf("%w: %s", ErrNotFound, orgID)
	}
	if err != nil {
		return Organization{}, fmt.Errorf("read organization %s of tenant %s: %w", orgID, tenantID, err)
	}
	return row, nil
}

// Insert writes one new organization. It runs on the caller's transaction.
func (r *Repository) Insert(ctx context.Context, row Organization) error {
	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write organization %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	return nil
}

// InsertMembership writes the roles one person holds in one organization. It
// runs on the caller's transaction, so an account and its membership land
// together.
//
// The organization owns this table, so the write lives here and every domain
// that needs it takes this method.
func (r *Repository) InsertMembership(ctx context.Context, row Membership) error {
	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write membership of user %s in organization %s of tenant %s: %w",
			row.UserID, row.OrgID, row.TenantID, err)
	}
	return nil
}

// ListMembers reads one page of the people of one organization, and the total
// behind it. An empty orgID reads every organization of the tenant, which is
// what the console shows before an operator picks one.
//
// Each row names the person, so the console renders a name instead of an id. A
// membership on a deleted account never comes back: the account is what the
// read joins from, so a membership nobody can sign in as is not a row an
// operator can act on.
func (r *Repository) ListMembers(
	ctx context.Context, tenantID, orgID string, desc bool, limit, offset int,
) ([]Membership, int64, error) {
	r.log.Debug("list organization members",
		logger.String("tenant_id", tenantID),
		logger.String("org_id", orgID),
		logger.Int("offset", offset))

	order := "m.created_at ASC"
	if desc {
		order = "m.created_at DESC"
	}

	var rows []Membership
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("m.tenant_id, m.org_id, m.user_id, m.roles, m.created_at").
		ColumnExpr(`COALESCE(NULLIF(h.display_name, ''), u.username, '') AS user_name`).
		Join("JOIN users AS u ON u.id = m.user_id AND u.tenant_id = m.tenant_id AND u.deleted_at IS NULL").
		Join("LEFT JOIN user_humans AS h ON h.user_id = m.user_id AND h.tenant_id = m.tenant_id").
		Where("m.tenant_id = ?", tenantID)

	if orgID != "" {
		sel = sel.Where("m.org_id = ?", orgID)
	}

	// The user id breaks a tie, so two memberships granted in the same
	// millisecond keep one order across the pages of one walk.
	total, err := sel.OrderExpr(order).Order("m.user_id DESC").
		Limit(limit).Offset(offset).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list the members of tenant %s: %w", tenantID, err)
	}
	return rows, int64(total), nil
}

// SaveMembership grants one organization membership, or replaces the roles of
// one that already exists. It runs on the caller's transaction.
//
// The key of the table does not carry deleted_at, so a revoked membership
// occupies the key its person would take again. The write therefore clears the
// mark instead of failing: re-adding a revoked membership is what the console
// offers, and it restores the access the roles grant.
//
// created_at is not written again, so the column keeps naming when the person
// first entered the organization.
func (r *Repository) SaveMembership(ctx context.Context, row Membership) error {
	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		On("DUPLICATE KEY UPDATE").
		Set("roles = VALUES(roles)").
		Set("deleted_at = NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write the membership of user %s in organization %s of tenant %s: %w",
			row.UserID, row.OrgID, row.TenantID, err)
	}
	return nil
}

// DeleteMembership revokes one organization membership. The row stays in the
// database, and every read filters it out. It runs on the caller's transaction.
//
// A membership nobody holds returns ErrMemberNotFound, so a revoke of a row
// that already went answers 404 and not a silent success.
func (r *Repository) DeleteMembership(ctx context.Context, tenantID, orgID, userID string) error {
	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Membership)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("org_id = ?", orgID).
		Where("user_id = ?", userID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("revoke the membership of user %s in organization %s of tenant %s: %w",
			userID, orgID, tenantID, err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke the membership of user %s in organization %s of tenant %s: %w",
			userID, orgID, tenantID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrMemberNotFound, userID)
	}
	return nil
}

// Rename writes the new name of one live organization. It runs on the caller's
// transaction. A row that went in the meantime returns ErrNotFound.
func (r *Repository) Rename(ctx context.Context, tenantID, orgID, name string) error {
	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*Organization)(nil)).
		Set("name = ?", name).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", orgID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("rename organization %s of tenant %s: %w", orgID, tenantID, err)
	}
	return oneRow(res, tenantID, orgID, "rename")
}

// SoftDelete marks one organization deleted. The row stays in the database, and
// every read filters it out. It runs on the caller's transaction.
func (r *Repository) SoftDelete(ctx context.Context, tenantID, orgID string) error {
	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Organization)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", orgID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete organization %s of tenant %s: %w", orgID, tenantID, err)
	}
	return oneRow(res, tenantID, orgID, "delete")
}

// oneRow reports ErrNotFound when a write matched no live row. The service read
// the row first, so this is a race, not a routine answer.
func oneRow(res sql.Result, tenantID, orgID, what string) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s organization %s of tenant %s: %w", what, orgID, tenantID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, orgID)
	}
	return nil
}

// ListByTenant reads every live organization of one tenant, by name. An
// inactive organization and a soft-deleted one never come back, so the console
// never lists an organization the tenant deactivated.
func (r *Repository) ListByTenant(ctx context.Context, tenantID string) ([]Organization, error) {
	r.log.Debug("read organizations", logger.String("tenant_id", tenantID))

	var rows []Organization
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID).
		Where("state = ?", StateActive).
		Order("name ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read organizations of tenant %s: %w", tenantID, err)
	}
	return rows, nil
}

// ListMemberships reads the live organization memberships of one person. A
// person who belongs to no organization holds no membership, which is the normal
// case, so an empty answer is not an error.
func (r *Repository) ListMemberships(ctx context.Context, tenantID, userID string) ([]Membership, error) {
	r.log.Debug("read organization members",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))

	var rows []Membership
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Order("org_id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read organization members of tenant %s: %w", tenantID, err)
	}
	return rows, nil
}
