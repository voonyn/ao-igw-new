package oidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrProfileNotFound reports that no live, active person of the tenant carries
// the user id. A person who cannot sign in carries no claims either.
var ErrProfileNotFound = errors.New("claim source not found")

// The users columns the claim source reads. Only a live, active person carries
// claims, so a disabled account releases nothing.
const (
	userStateActive = 1
	userTypeHuman   = 1
)

// ScopeRepository reads the scopes, the claim mappers, and the claim source of
// one tenant. The three reads live together, because they serve one job: the
// claims of one person.
type ScopeRepository struct {
	db  *bun.DB
	log logger.Logger
}

func NewScopeRepository(bdb *bun.DB, log logger.Logger) *ScopeRepository {
	return &ScopeRepository{db: bdb, log: log}
}

// List reads the scopes the tenant offers. A disabled scope is neither
// advertised nor described, so the read filters it out.
func (r *ScopeRepository) List(ctx context.Context, tenantID string) ([]Scope, error) {
	r.log.Debug("read scopes", logger.String("tenant_id", tenantID))

	var rows []struct {
		Name        string `bun:"name"`
		DisplayName string `bun:"display_name"`
		Description string `bun:"description"`
	}
	err := db.Conn(ctx, r.db).NewSelect().
		TableExpr("oidc_scopes AS s").
		ColumnExpr("s.name").
		ColumnExpr("COALESCE(s.display_name, '') AS display_name").
		ColumnExpr("COALESCE(s.description, '') AS description").
		Where("s.tenant_id = ?", tenantID).
		Where("s.is_enabled = 1").
		Where("s.deleted_at IS NULL").
		Order("s.name").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read scopes of tenant %s: %w", tenantID, err)
	}

	scopes := make([]Scope, 0, len(rows))
	for _, row := range rows {
		scopes = append(scopes, Scope{
			Name:        row.Name,
			DisplayName: row.DisplayName,
			Description: row.Description,
		})
	}
	return scopes, nil
}

// Mappers reads the claim mappers of the named scopes. A mapper of a disabled
// scope never releases a claim, so the join filters it out too.
//
// A request with no scopes reads nothing. The caller then releases no claim.
func (r *ScopeRepository) Mappers(
	ctx context.Context, tenantID string, scopes []string,
) ([]ClaimMapper, error) {
	r.log.Debug("read claim mappers", logger.String("tenant_id", tenantID))

	if len(scopes) == 0 {
		return nil, nil
	}

	var rows []struct {
		ClaimName  string `bun:"claim_name"`
		SourceType int    `bun:"source_type"`
		SourceKey  string `bun:"source_key"`
		InIDToken  bool   `bun:"in_id_token"`
		InUserInfo bool   `bun:"in_userinfo"`
	}
	err := db.Conn(ctx, r.db).NewSelect().
		TableExpr("oidc_claim_mappers AS m").
		ColumnExpr("m.claim_name").
		ColumnExpr("m.source_type").
		ColumnExpr("COALESCE(m.source_key, '') AS source_key").
		ColumnExpr("m.in_id_token").
		ColumnExpr("m.in_userinfo").
		Join("JOIN oidc_scopes AS s ON s.id = m.scope_id AND s.tenant_id = m.tenant_id").
		Where("m.tenant_id = ?", tenantID).
		Where("m.deleted_at IS NULL").
		Where("s.name IN (?)", bun.In(scopes)).
		Where("s.is_enabled = 1").
		Where("s.deleted_at IS NULL").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read claim mappers of tenant %s: %w", tenantID, err)
	}

	mappers := make([]ClaimMapper, 0, len(rows))
	for _, row := range rows {
		mappers = append(mappers, ClaimMapper{
			ClaimName:  row.ClaimName,
			SourceType: row.SourceType,
			SourceKey:  row.SourceKey,
			InIDToken:  row.InIDToken,
			InUserInfo: row.InUserInfo,
		})
	}
	return mappers, nil
}

// Profile reads the claim source of one person: the account row, the person
// row, and the custom attribute bag.
//
// updated_at is the later of the two rows, because a claim reader asks when the
// profile last changed, and either row can carry the change.
func (r *ScopeRepository) Profile(
	ctx context.Context, tenantID, userID string,
) (UserProfile, error) {
	r.log.Debug("read claim source",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))

	var row struct {
		Username      string    `bun:"username"`
		DisplayName   string    `bun:"display_name"`
		FirstName     string    `bun:"first_name"`
		LastName      string    `bun:"last_name"`
		Email         string    `bun:"email"`
		EmailVerified bool      `bun:"is_email_verified"`
		Locale        string    `bun:"locale"`
		UpdatedAt     time.Time `bun:"updated_at"`
		Attributes    []byte    `bun:"attributes"`
	}
	err := db.Conn(ctx, r.db).NewSelect().
		TableExpr("users AS u").
		ColumnExpr("COALESCE(u.username, '') AS username").
		ColumnExpr("COALESCE(h.display_name, '') AS display_name").
		ColumnExpr("COALESCE(h.first_name, '') AS first_name").
		ColumnExpr("COALESCE(h.last_name, '') AS last_name").
		ColumnExpr("COALESCE(h.email, '') AS email").
		ColumnExpr("h.is_email_verified").
		ColumnExpr("COALESCE(h.preferred_language, '') AS locale").
		ColumnExpr("GREATEST(u.updated_at, h.updated_at) AS updated_at").
		ColumnExpr("u.attributes").
		Join("JOIN user_humans AS h ON h.user_id = u.id AND h.tenant_id = u.tenant_id").
		Where("u.tenant_id = ?", tenantID).
		Where("u.id = ?", userID).
		Where("u.state = ?", userStateActive).
		Where("u.user_type = ?", userTypeHuman).
		Where("u.deleted_at IS NULL").
		Scan(ctx, &row)
	if errors.Is(err, sql.ErrNoRows) {
		return UserProfile{}, fmt.Errorf("%w: tenant %s, user %s", ErrProfileNotFound, tenantID, userID)
	}
	if err != nil {
		return UserProfile{}, fmt.Errorf("read claim source of tenant %s: %w", tenantID, err)
	}

	profile := UserProfile{
		Username:      row.Username,
		DisplayName:   row.DisplayName,
		FirstName:     row.FirstName,
		LastName:      row.LastName,
		Email:         row.Email,
		EmailVerified: row.EmailVerified,
		Locale:        row.Locale,
		UpdatedAt:     row.UpdatedAt,
	}
	if len(row.Attributes) > 0 {
		if err := json.Unmarshal(row.Attributes, &profile.Attributes); err != nil {
			return UserProfile{}, fmt.Errorf("read attributes of user %s: %w", userID, err)
		}
	}
	return profile, nil
}
