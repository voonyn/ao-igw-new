package oidc

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// grantSortColumns maps a sort key of the route's allowlist to its column. The
// ORDER BY clause is built from this map only, so no query input reaches the
// SQL.
var grantSortColumns = map[string]string{
	"created": "g.created_at",
	"expires": "g.expires_at",
}

// grantClientJoin reads the application one client identifier belongs to. Both
// halves are LEFT JOINs: a grant of a client that is gone must still appear, so
// an operator sees that the access exists.
const grantClientJoin = `LEFT JOIN application_oidc_configs AS c
	ON c.tenant_id = g.tenant_id AND c.client_id = g.client_id AND c.deleted_at IS NULL`

const grantAppJoin = `LEFT JOIN applications AS a
	ON a.id = c.app_id AND a.tenant_id = c.tenant_id AND a.deleted_at IS NULL`

// grantSubjectJoin reads the person one grant names. A client-credentials grant
// names nobody, and a person whose account is gone keeps the grant visible.
const grantSubjectJoin = `LEFT JOIN users AS u
	ON u.id = g.subject AND u.tenant_id = g.tenant_id AND u.deleted_at IS NULL`

const grantProfileJoin = `LEFT JOIN user_humans AS h
	ON h.user_id = g.subject AND h.tenant_id = g.tenant_id`

// Kind names what the grant is, derived from the columns. A grant that no person
// authorized is a client-credentials grant, one that carries a refresh token
// digest is a refresh-token grant, and the rest came from an authorization code.
func (g GrantRecord) Kind() string {
	switch {
	case g.Subject == "":
		return KindClientCredentials
	case g.HasRefreshToken:
		return KindRefreshToken
	default:
		return KindAuthorizationCode
	}
}

// ListGrants reads one page of the grants of one tenant.
func (r *StorageRepository) ListGrants(
	ctx context.Context, tenantID string, q GrantQuery,
) ([]GrantRecord, int64, error) {
	r.log.Debug("list grants",
		logger.String("tenant_id", tenantID), logger.Int("offset", q.Offset), logger.RequestID(ctx))

	var rows []GrantRecord
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("g.id, g.tenant_id, g.client_id, g.subject, g.login_session_id").
		ColumnExpr("g.created_at, g.expires_at").
		ColumnExpr("(g.refresh_token_hash IS NOT NULL) AS has_refresh_token").
		ColumnExpr("COALESCE(a.name, '') AS app_name").
		ColumnExpr(`COALESCE(NULLIF(h.display_name, ''), u.username, '') AS subject_name`).
		Join(grantClientJoin).
		Join(grantAppJoin).
		Join(grantSubjectJoin).
		Join(grantProfileJoin).
		Where("g.tenant_id = ?", tenantID)

	if q.UserID != "" {
		sel = sel.Where("g.subject = ?", q.UserID)
	}

	// The id breaks a tie, so two grants issued in the same millisecond keep one
	// order across the pages of one walk.
	total, err := sel.OrderExpr(grantOrderBy(q)).Order("g.id DESC").
		Limit(q.Limit).Offset(q.Offset).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list the grants of tenant %s: %w", tenantID, err)
	}
	return rows, int64(total), nil
}

// grantOrderBy builds the ORDER BY clause of one page from the allow-list. A
// read that asks for no order reads newest first, which is what every admin list
// answers.
func grantOrderBy(q GrantQuery) string {
	column, ok := grantSortColumns[q.Sort]
	if !ok {
		return "g.created_at DESC"
	}
	if q.Desc {
		return column + " DESC"
	}
	return column + " ASC"
}

// DeleteGrantsByLoginSession hard deletes every grant one sign-in produced, and
// answers how many went.
//
// A grant is a consumed row, so an administrative revoke removes it instead of
// marking it. No refresh token of that sign-in survives, offline_access
// included. An access token already issued is a signed value no store holds, and
// it lives out its lifetime at the relying party.
//
// An empty session id answers nothing. Such an id names no sign-in, and matching
// on it would delete every grant the tenant holds.
func (r *StorageRepository) DeleteGrantsByLoginSession(
	ctx context.Context, tenantID, sessionID string,
) (int, error) {
	if sessionID == "" {
		return 0, nil
	}
	return r.deleteGrants(ctx, tenantID, "login_session_id", sessionID)
}

// DeleteGrantsBySubject hard deletes every grant one person holds, whatever
// sign-in produced it, and answers how many went.
//
// An empty subject answers nothing. It would otherwise match the
// client-credentials grants, which no person holds.
func (r *StorageRepository) DeleteGrantsBySubject(
	ctx context.Context, tenantID, subject string,
) (int, error) {
	if subject == "" {
		return 0, nil
	}
	return r.deleteGrants(ctx, tenantID, "subject", subject)
}

// deleteGrants removes the grants one indexed column names, and the superseded
// refresh token digests that belonged to them.
//
// The digests go too, because a grant that no longer exists has nothing left to
// detect: they are kept only to recognise a replay against a live grant.
func (r *StorageRepository) deleteGrants(
	ctx context.Context, tenantID, column, value string,
) (int, error) {
	r.log.Debug("revoke grants",
		logger.String("tenant_id", tenantID), logger.String("by", column), logger.RequestID(ctx))

	var ids []string
	if err := db.Conn(ctx, r.db).NewSelect().
		Model((*GrantRecord)(nil)).
		Column("id").
		Where("g.tenant_id = ?", tenantID).
		Where("? = ?", bun.Ident("g."+column), value).
		Scan(ctx, &ids); err != nil {
		return 0, fmt.Errorf("read the grants of tenant %s by %s: %w", tenantID, column, err)
	}
	if len(ids) == 0 {
		return 0, nil
	}

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*SupersededRefreshToken)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("grant_id IN (?)", bun.In(ids)).
		Exec(ctx); err != nil {
		return 0, fmt.Errorf("drop the superseded refresh tokens of tenant %s: %w", tenantID, err)
	}

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Grant)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("id IN (?)", bun.In(ids)).
		Exec(ctx); err != nil {
		return 0, fmt.Errorf("revoke the grants of tenant %s by %s: %w", tenantID, column, err)
	}

	r.log.Debug("revoked grants",
		logger.String("tenant_id", tenantID),
		logger.String("by", column),
		logger.Int("grants", len(ids)), logger.RequestID(ctx))
	return len(ids), nil
}
