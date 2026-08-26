// Package application holds the applications of a tenant: the products a
// tenant registers, and the OIDC client each of them is reached by.
package application

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNotFound reports that no live application of the tenant carries the id.
var ErrNotFound = errors.New("application not found")

// Repository reads and writes the applications of one tenant.
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
	"name":    "a.name",
	"state":   "a.state",
	"created": "a.created_at",
}

// appColumns names every column the Application model holds. The table carries
// updated_at as well, and a select of every column fails to scan, so the list is
// written out here.
const appColumns = `a.id, a.tenant_id, a.project_id, a.name, a.app_type, a.state,
	a.created_at, a.deleted_at`

// projectJoin reads the project of each application. The console renders the
// project name, and the write gate reads the organization of the project, so
// every read of an application carries both.
const projectJoin = "JOIN projects AS p ON p.id = a.project_id AND p.tenant_id = a.tenant_id AND p.deleted_at IS NULL"

// List reads one page of the applications of a tenant, and the total behind it.
// Every state comes back, because the console filters by state itself. A
// soft-deleted application never does.
func (r *Repository) List(ctx context.Context, tenantID string, q Query) ([]Application, int64, error) {
	r.log.Debug("list applications",
		logger.String("tenant_id", tenantID), logger.Int("offset", q.Offset), logger.RequestID(ctx))

	var rows []Application
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr(appColumns).
		ColumnExpr("p.name AS project_name").
		ColumnExpr("p.org_id AS org_id").
		Join(projectJoin).
		Where("a.tenant_id = ?", tenantID)

	if q.Search != "" {
		sel = sel.Where("a.name LIKE ?", q.Search+"%")
	}
	if q.State != 0 {
		sel = sel.Where("a.state = ?", q.State)
	}
	if q.OrgID != "" {
		sel = sel.Where("p.org_id = ?", q.OrgID)
	}

	// The id breaks a tie, so two applications created in the same millisecond
	// keep one order across the pages of one walk.
	sel = sel.OrderExpr(orderBy(q)).Order("a.id DESC").
		Limit(q.Limit).Offset(q.Offset)

	total, err := sel.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list applications of tenant %s: %w", tenantID, err)
	}
	return rows, int64(total), nil
}

// orderBy names the column and the direction one page reads in. An unknown key
// never reaches here, because the route refuses it, so a key this map does not
// hold takes the newest-first default.
func orderBy(q Query) string {
	column, ok := sortColumns[q.Sort]
	if !ok {
		return "a.created_at DESC"
	}
	if q.Desc {
		return column + " DESC"
	}
	return column + " ASC"
}

// FindByID reads one live application of a tenant. A miss returns ErrNotFound.
func (r *Repository) FindByID(ctx context.Context, tenantID, appID string) (Application, error) {
	r.log.Debug("read application",
		logger.String("tenant_id", tenantID), logger.String("app_id", appID), logger.RequestID(ctx))

	var row Application
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		ColumnExpr(appColumns).
		ColumnExpr("p.name AS project_name").
		ColumnExpr("p.org_id AS org_id").
		Join(projectJoin).
		Where("a.tenant_id = ?", tenantID).
		Where("a.id = ?", appID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Application{}, fmt.Errorf("%w: %s", ErrNotFound, appID)
	}
	if err != nil {
		return Application{}, fmt.Errorf("read application %s of tenant %s: %w", appID, tenantID, err)
	}
	return row, nil
}

// Configs reads the clients of the applications one page holds. An application
// without a client is simply absent from the answer.
func (r *Repository) Configs(ctx context.Context, tenantID string, appIDs []string) ([]oidc.Client, error) {
	if len(appIDs) == 0 {
		return nil, nil
	}
	r.log.Debug("read clients",
		logger.String("tenant_id", tenantID), logger.Int("count", len(appIDs)), logger.RequestID(ctx))

	var rows []oidc.Client
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("c.tenant_id = ?", tenantID).
		Where("c.app_id IN (?)", bun.In(appIDs)).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read clients of tenant %s: %w", tenantID, err)
	}
	return rows, nil
}

// Insert writes one new application. It runs on the caller's transaction.
func (r *Repository) Insert(ctx context.Context, row Application) error {
	r.log.Debug("write application",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.ID),
		logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write application %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	r.log.Debug("wrote application",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.ID),
		logger.RequestID(ctx))
	return nil
}

// InsertConfig writes the client of one new application. It runs on the
// caller's transaction, so the application and its client land together.
func (r *Repository) InsertConfig(ctx context.Context, row oidc.Client) error {
	r.log.Debug("write client",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.AppID),
		logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&row).Exec(ctx); err != nil {
		return fmt.Errorf("write client of application %s of tenant %s: %w", row.AppID, row.TenantID, err)
	}
	r.log.Debug("wrote client",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.AppID),
		logger.RequestID(ctx))
	return nil
}

// Update writes the name of one live application. It runs on the caller's
// transaction. A row that went in the meantime returns ErrNotFound.
func (r *Repository) Update(ctx context.Context, row Application) error {
	r.log.Debug("update application",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.ID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("name").
		Where("tenant_id = ?", row.TenantID).
		Where("id = ?", row.ID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("update application %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	r.log.Debug("updated application",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.ID),
		logger.RequestID(ctx))
	return oneRow(res, row.TenantID, row.ID, "update")
}

// UpdateConfig writes the settings of one client. It runs on the caller's
// transaction.
//
// The client id is not written. Every relying party is configured with it, so a
// changed id breaks a live integration with no error anybody reads. The stored
// secret is not written either: only a rotation replaces it.
func (r *Repository) UpdateConfig(ctx context.Context, row oidc.Client) error {
	r.log.Debug("update client",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.AppID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("token_authn_method", "subject_type", "par_is_required", "scopes",
			"redirect_uris", "grant_types", "response_types", "post_logout_redirect_uris").
		Where("tenant_id = ?", row.TenantID).
		Where("app_id = ?", row.AppID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("update client of application %s of tenant %s: %w", row.AppID, row.TenantID, err)
	}
	r.log.Debug("updated client",
		logger.String("tenant_id", row.TenantID), logger.String("app_id", row.AppID),
		logger.RequestID(ctx))
	return oneRow(res, row.TenantID, row.AppID, "update the client of")
}

// SetSecret writes the bcrypt hash of one rotated client secret. It runs on the
// caller's transaction. The secret itself is never written and never logged.
func (r *Repository) SetSecret(ctx context.Context, tenantID, appID, hash string) error {
	r.log.Debug("write client secret",
		logger.String("tenant_id", tenantID), logger.String("app_id", appID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model((*oidc.Client)(nil)).
		Set("secret = ?", hash).
		Where("tenant_id = ?", tenantID).
		Where("app_id = ?", appID).
		Where("deleted_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("rotate the secret of application %s of tenant %s: %w", appID, tenantID, err)
	}
	r.log.Debug("wrote client secret",
		logger.String("tenant_id", tenantID), logger.String("app_id", appID),
		logger.RequestID(ctx))
	return oneRow(res, tenantID, appID, "rotate the secret of")
}

// SoftDelete marks one application deleted, and its client with it. Both rows
// stay in the database, and every read filters them out. It runs on the
// caller's transaction.
//
// The client goes with the application. A client that outlived the application
// it belongs to would still mint tokens.
func (r *Repository) SoftDelete(ctx context.Context, tenantID, appID string) error {
	r.log.Debug("delete application",
		logger.String("tenant_id", tenantID), logger.String("app_id", appID),
		logger.RequestID(ctx))

	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Application)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", appID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete application %s of tenant %s: %w", appID, tenantID, err)
	}
	if err := oneRow(res, tenantID, appID, "delete"); err != nil {
		return err
	}

	// A SAML application holds no client, so no row here is the normal answer.
	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*oidc.Client)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("app_id = ?", appID).
		Exec(ctx); err != nil {
		return fmt.Errorf("delete client of application %s of tenant %s: %w", appID, tenantID, err)
	}
	r.log.Debug("deleted application",
		logger.String("tenant_id", tenantID), logger.String("app_id", appID),
		logger.RequestID(ctx))
	return nil
}

// oneRow reports ErrNotFound when a write matched no live row. The service read
// the row first, so this is a race, not a routine answer.
func oneRow(res sql.Result, tenantID, appID, what string) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("%s application %s of tenant %s: %w", what, appID, tenantID, err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, appID)
	}
	return nil
}
