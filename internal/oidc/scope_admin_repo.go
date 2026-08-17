package oidc

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ScopeRow is one row of oidc_scopes.
//
// The protocol read has its own Scope struct, which carries the three words the
// consent screen renders and nothing else. This one is the whole row, because
// the console writes it.
//
// MapperCount is not a column. It is counted by the list read, so the scopes
// page names how many claims each scope releases without a request per row.
type ScopeRow struct {
	bun.BaseModel `bun:"table:oidc_scopes,alias:s"`

	ID          string `bun:"id,pk"`
	TenantID    string `bun:"tenant_id"`
	Name        string `bun:"name"`
	DisplayName string `bun:"display_name,nullzero"`
	Description string `bun:"description,nullzero"`

	IsEnabled bool `bun:"is_enabled"`
	IsDefault bool `bun:"is_default"`
	IsBuiltin bool `bun:"is_builtin"`

	CreatedAt time.Time `bun:"created_at,nullzero"`
	UpdatedAt time.Time `bun:"updated_at,nullzero"`
	DeletedAt time.Time `bun:"deleted_at,soft_delete,nullzero"`

	MapperCount int `bun:"mapper_count,scanonly"`
}

// ClaimMapperRow is one row of oidc_claim_mappers. The claims service has its
// own ClaimMapper, which carries what a token build reads; this one is the whole
// row, because the console writes it.
//
// SourceValue is the JSON column of a static mapper. It is bound as a string and
// not as bytes: the column is MySQL JSON, and the driver sends a []byte as a
// binary string, which MySQL refuses to read as JSON.
type ClaimMapperRow struct {
	bun.BaseModel `bun:"table:oidc_claim_mappers,alias:m"`

	ID          string `bun:"id,pk"`
	TenantID    string `bun:"tenant_id"`
	ScopeID     string `bun:"scope_id"`
	ClaimName   string `bun:"claim_name"`
	SourceType  int    `bun:"source_type"`
	SourceKey   string `bun:"source_key,nullzero"`
	SourceValue string `bun:"source_value,nullzero"`

	InIDToken     bool `bun:"in_id_token"`
	InUserInfo    bool `bun:"in_userinfo"`
	InAccessToken bool `bun:"in_access_token"`

	CreatedAt time.Time `bun:"created_at,nullzero"`
	UpdatedAt time.Time `bun:"updated_at,nullzero"`
	DeletedAt time.Time `bun:"deleted_at,soft_delete,nullzero"`
}

// ListScopes reads every live scope of the tenant, the disabled ones included,
// with the number of claims each one releases.
//
// It differs from List on purpose. That read answers what the tenant advertises,
// so it drops a disabled scope; this one answers what the tenant holds, and an
// operator who cannot see a disabled scope cannot switch it back on.
func (r *ScopeRepository) ListScopes(ctx context.Context, tenantID string) ([]ScopeRow, error) {
	r.log.Debug("read every scope", logger.String("tenant_id", tenantID))

	var rows []ScopeRow
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("s.*").
		ColumnExpr("(SELECT COUNT(*) FROM oidc_claim_mappers m"+
			" WHERE m.scope_id = s.id AND m.deleted_at IS NULL) AS mapper_count").
		Where("s.tenant_id = ?", tenantID).
		Order("s.name").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read every scope of tenant %s: %w", tenantID, err)
	}
	return rows, nil
}

// FindScope reads one live scope of a tenant. A scope of another tenant reads
// the way a scope nobody holds reads, so no path parameter can reach across a
// tenant boundary.
func (r *ScopeRepository) FindScope(ctx context.Context, tenantID, id string) (ScopeRow, error) {
	r.log.Debug("read one scope",
		logger.String("tenant_id", tenantID), logger.String("scope_id", id))

	var row ScopeRow
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("s.tenant_id = ?", tenantID).
		Where("s.id = ?", id).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return ScopeRow{}, fmt.Errorf("%w: tenant %s, scope %s", ErrScopeNotFound, tenantID, id)
	}
	if err != nil {
		return ScopeRow{}, fmt.Errorf("read scope %s of tenant %s: %w", id, tenantID, err)
	}
	return row, nil
}

// FindScopeByName reads one live scope of a tenant by the name a client asks
// for. The name is unique per tenant, so two tenants can hold the same name and
// each read answers its own.
func (r *ScopeRepository) FindScopeByName(
	ctx context.Context, tenantID, name string,
) (ScopeRow, error) {
	r.log.Debug("read one scope by name", logger.String("tenant_id", tenantID))

	var row ScopeRow
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("s.tenant_id = ?", tenantID).
		Where("s.name = ?", name).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return ScopeRow{}, fmt.Errorf("%w: tenant %s, name %s", ErrScopeNotFound, tenantID, name)
	}
	if err != nil {
		return ScopeRow{}, fmt.Errorf("read scope %s of tenant %s: %w", name, tenantID, err)
	}
	return row, nil
}

// InsertScope writes one new scope. It runs on the caller's transaction.
//
// is_builtin is not written here. Only the migration writes that mark, so a
// scope an operator wrote can always be deleted.
func (r *ScopeRepository) InsertScope(ctx context.Context, row ScopeRow) error {
	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column("id", "tenant_id", "name", "display_name", "description",
			"is_enabled", "is_default").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write scope %s of tenant %s: %w", row.Name, row.TenantID, err)
	}
	return nil
}

// UpdateScope writes the five writable fields of one scope. It runs on the
// caller's transaction.
//
// is_builtin is not in the list, so no write can make a scope permanent or take
// the mark off a seeded one.
func (r *ScopeRepository) UpdateScope(ctx context.Context, row ScopeRow) error {
	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("name", "display_name", "description", "is_enabled", "is_default").
		Where("s.tenant_id = ?", row.TenantID).
		Where("s.id = ?", row.ID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write scope %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	return rowWritten(res, ErrScopeNotFound, row.ID)
}

// DeleteScope marks one scope of a tenant deleted, with the claim mappers it
// released. It runs on the caller's transaction.
//
// The mappers go with it. A mapper left behind would release a claim for a scope
// nobody can grant, and it would hold the unique key of its claim name.
func (r *ScopeRepository) DeleteScope(ctx context.Context, tenantID, id string) error {
	conn := db.Conn(ctx, r.db)

	res, err := conn.NewDelete().
		Model((*ScopeRow)(nil)).
		Where("s.tenant_id = ?", tenantID).
		Where("s.id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete scope %s of tenant %s: %w", id, tenantID, err)
	}
	if err := rowWritten(res, ErrScopeNotFound, id); err != nil {
		return err
	}

	_, err = conn.NewDelete().
		Model((*ClaimMapperRow)(nil)).
		Where("m.tenant_id = ?", tenantID).
		Where("m.scope_id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete the claims of scope %s: %w", id, err)
	}
	return nil
}

// CountClientsWithScope counts the live clients of a tenant that still name one
// scope on their allow-list.
//
// The column holds the names of one client as a space-separated string, so the
// read turns it into a comma-separated list and matches a whole name. A prefix
// of a name never matches, and neither does a pair of names.
func (r *ScopeRepository) CountClientsWithScope(
	ctx context.Context, tenantID, name string,
) (int, error) {
	r.log.Debug("count the clients of one scope", logger.String("tenant_id", tenantID))

	count, err := db.Conn(ctx, r.db).NewSelect().
		TableExpr("application_oidc_configs AS c").
		Join("JOIN applications AS a ON a.id = c.app_id AND a.tenant_id = c.tenant_id").
		Where("c.tenant_id = ?", tenantID).
		Where("c.deleted_at IS NULL").
		Where("a.deleted_at IS NULL").
		Where("FIND_IN_SET(?, REPLACE(c.scopes, ' ', ',')) > 0", name).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count the clients of scope %s in tenant %s: %w", name, tenantID, err)
	}
	return count, nil
}

// ListMappers reads every live claim mapper of one scope, by claim name.
func (r *ScopeRepository) ListMappers(
	ctx context.Context, tenantID, scopeID string,
) ([]ClaimMapperRow, error) {
	r.log.Debug("read the claim mappers of one scope",
		logger.String("tenant_id", tenantID), logger.String("scope_id", scopeID))

	var rows []ClaimMapperRow
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("m.tenant_id = ?", tenantID).
		Where("m.scope_id = ?", scopeID).
		Order("m.claim_name").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the claims of scope %s: %w", scopeID, err)
	}
	return rows, nil
}

// FindMapper reads one live claim mapper of a tenant.
func (r *ScopeRepository) FindMapper(
	ctx context.Context, tenantID, id string,
) (ClaimMapperRow, error) {
	r.log.Debug("read one claim mapper",
		logger.String("tenant_id", tenantID), logger.String("mapper_id", id))

	var row ClaimMapperRow
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Where("m.tenant_id = ?", tenantID).
		Where("m.id = ?", id).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return ClaimMapperRow{}, fmt.Errorf("%w: tenant %s, mapper %s", ErrMapperNotFound, tenantID, id)
	}
	if err != nil {
		return ClaimMapperRow{}, fmt.Errorf("read claim mapper %s of tenant %s: %w", id, tenantID, err)
	}
	return row, nil
}

// CountMappers counts the live claim mappers of one scope. The service reads it
// before a write, so one scope cannot grow past MaxMappersPerScope.
func (r *ScopeRepository) CountMappers(ctx context.Context, tenantID, scopeID string) (int, error) {
	count, err := db.Conn(ctx, r.db).NewSelect().
		Model((*ClaimMapperRow)(nil)).
		Where("m.tenant_id = ?", tenantID).
		Where("m.scope_id = ?", scopeID).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count the claims of scope %s: %w", scopeID, err)
	}
	return count, nil
}

// InsertMapper writes one new claim mapper. It runs on the caller's transaction.
func (r *ScopeRepository) InsertMapper(ctx context.Context, row ClaimMapperRow) error {
	_, err := db.Conn(ctx, r.db).NewInsert().
		Model(&row).
		Column("id", "tenant_id", "scope_id", "claim_name", "source_type",
			"source_key", "source_value", "in_id_token", "in_userinfo", "in_access_token").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write a claim of scope %s: %w", row.ScopeID, err)
	}
	return nil
}

// UpdateMapper writes the fields of one claim mapper. It runs on the caller's
// transaction.
//
// source_value is written whatever it holds, so a mapper that stops being static
// leaves no value behind for the claims service to read.
func (r *ScopeRepository) UpdateMapper(ctx context.Context, row ClaimMapperRow) error {
	res, err := db.Conn(ctx, r.db).NewUpdate().
		Model(&row).
		Column("claim_name", "source_type", "source_key", "source_value",
			"in_id_token", "in_userinfo", "in_access_token").
		Where("m.tenant_id = ?", row.TenantID).
		Where("m.id = ?", row.ID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("write claim mapper %s of tenant %s: %w", row.ID, row.TenantID, err)
	}
	return rowWritten(res, ErrMapperNotFound, row.ID)
}

// DeleteMapper marks one claim mapper of a tenant deleted. It runs on the
// caller's transaction.
func (r *ScopeRepository) DeleteMapper(ctx context.Context, tenantID, id string) error {
	res, err := db.Conn(ctx, r.db).NewDelete().
		Model((*ClaimMapperRow)(nil)).
		Where("m.tenant_id = ?", tenantID).
		Where("m.id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("delete claim mapper %s of tenant %s: %w", id, tenantID, err)
	}
	return rowWritten(res, ErrMapperNotFound, id)
}

// rowWritten turns a statement that touched nothing into the sentinel the caller
// answers with. The row was read a moment earlier on the same transaction, so
// nothing else explains a count of zero.
func rowWritten(res sql.Result, missing error, id string) error {
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("count the written rows: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("%w: %s", missing, id)
	}
	return nil
}
