// Package project holds the projects of a tenant: the named groups the
// applications of one product sit in.
package project

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNotFound reports that no live project of the tenant carries the id.
var ErrNotFound = errors.New("project not found")

// Repository reads and writes the projects of one tenant.
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

// List reads one page of the projects of a tenant, and the total behind it.
// Every state comes back, because the console filters by state itself. A
// soft-deleted project never does.
func (r *Repository) List(ctx context.Context, tenantID string, q Query) ([]Project, int64, error) {
	r.log.Debug("list projects",
		logger.String("tenant_id", tenantID), logger.Int("offset", q.Offset))

	var rows []Project
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID)

	if q.Search != "" {
		sel = sel.Where("name LIKE ?", q.Search+"%")
	}
	if q.State != 0 {
		sel = sel.Where("state = ?", q.State)
	}
	if q.OrgID != "" {
		sel = sel.Where("org_id = ?", q.OrgID)
	}

	// The id breaks a tie, so two projects created in the same millisecond keep
	// one order across the pages of one walk.
	sel = sel.OrderExpr(orderBy(q)).Order("id DESC").
		Limit(q.Limit).Offset(q.Offset)

	total, err := sel.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list projects of tenant %s: %w", tenantID, err)
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

// FindByID reads one live project of a tenant. A miss returns ErrNotFound.
func (r *Repository) FindByID(ctx context.Context, tenantID, projectID string) (Project, error) {
	r.log.Debug("read project",
		logger.String("tenant_id", tenantID), logger.String("project_id", projectID))

	var row Project
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", projectID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, fmt.Errorf("%w: %s", ErrNotFound, projectID)
	}
	if err != nil {
		return Project{}, fmt.Errorf("read project %s of tenant %s: %w", projectID, tenantID, err)
	}
	return row, nil
}

// Insert writes one new project. It runs on the caller's transaction.
func (r *Repository) Insert(ctx context.Context, row Project) error {
	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write project %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	return nil
}

// Update writes the name and the four settings of one live project. It runs on
// the caller's transaction. A row that went in the meantime returns
// ErrNotFound.
func (r *Repository) Update(ctx context.Context, row Project) error {
	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("name", "project_role_assertion", "project_role_check",
			"has_project_check", "private_labeling_setting").
		Where("tenant_id = ?", row.TenantID).
		Where("id = ?", row.ID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("update project %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	return oneRow(res, row.TenantID, row.ID, "update")
}

// SoftDelete marks one project deleted. The row stays in the database, and
// every read filters it out. It runs on the caller's transaction.
func (r *Repository) SoftDelete(ctx context.Context, tenantID, projectID string) error {
	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Project)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", projectID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete project %s of tenant %s: %w", projectID, tenantID, err)
	}
	return oneRow(res, tenantID, projectID, "delete")
}

// oneRow reports ErrNotFound when a write matched no live row. The service read
// the row first, so this is a race, not a routine answer.
func oneRow(res sql.Result, tenantID, projectID, what string) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s project %s of tenant %s: %w", what, projectID, tenantID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, projectID)
	}
	return nil
}
