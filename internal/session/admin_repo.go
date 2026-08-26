package session

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNoSuchSession reports that no login session of the tenant carries the id
// an administrator named. It answers 404.
//
// It is a second sentinel on purpose. ErrLoginSessionNotFound describes a token
// that credentials nothing and answers 401, and this one describes a row the
// operator asked for, so the two answer different statuses.
var ErrNoSuchSession = errors.New("no such login session")

// sessionSortColumns maps a sort key of the route's allowlist to its column. The
// ORDER BY clause is built from this map only, so no query input reaches the
// SQL.
var sessionSortColumns = map[string]string{
	"created": "s.created_at",
	"expires": "s.expires_at",
	"state":   "s.state",
}

// sessionNameColumn is what the console renders for the owner of one session:
// the display name of the profile, or the username when the profile carries
// none. It repeats what the member roster reads, so one person is named the same
// way on every screen.
const sessionNameColumn = `COALESCE(NULLIF(h.display_name, ''), u.username, '') AS user_name`

// sessionOwnerJoin reads the account behind each session. Both halves are LEFT
// JOINs: a session that named nobody yet, and one whose account is gone, must
// still appear in the list.
const sessionOwnerJoin = `LEFT JOIN users AS u
	ON u.id = s.user_id AND u.tenant_id = s.tenant_id AND u.deleted_at IS NULL`

const sessionProfileJoin = `LEFT JOIN user_humans AS h
	ON h.user_id = s.user_id AND h.tenant_id = s.tenant_id`

// Revoked is what one hard-deleted login session leaves behind. The cache is
// keyed by the token digest, so the caller needs it to drop the entry, and the
// audit event names the person the session belonged to.
type Revoked struct {
	SessionID string
	UserID    string
	TokenHash string
}

// ListSessions reads one page of the login sessions of one tenant.
//
// A terminated session is not hidden. The state is a lifecycle and not a soft
// delete, so an operator investigating an account reads that a session ended and
// when. The caller narrows by state when it wants one of them.
func (r *Repository) ListSessions(
	ctx context.Context, tenantID string, q Query,
) ([]Record, int64, error) {
	r.log.Debug("list login sessions",
		logger.String("tenant_id", tenantID), logger.Int("offset", q.Offset), logger.RequestID(ctx))

	var rows []Record
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		ColumnExpr("s.id, s.tenant_id, s.user_id, s.state, s.created_at, s.expires_at, s.data").
		ColumnExpr("COALESCE(u.org_id, '') AS org_id").
		ColumnExpr(sessionNameColumn).
		Join(sessionOwnerJoin).
		Join(sessionProfileJoin).
		Where("s.tenant_id = ?", tenantID)

	if q.UserID != "" {
		sel = sel.Where("s.user_id = ?", q.UserID)
	}
	if q.OrgID != "" {
		sel = sel.Where("u.org_id = ?", q.OrgID)
	}
	if q.State != 0 {
		sel = sel.Where("s.state = ?", q.State)
	}

	// The id breaks a tie, so two sessions opened in the same millisecond keep
	// one order across the pages of one walk.
	total, err := sel.OrderExpr(sessionOrderBy(q)).Order("s.id DESC").
		Limit(q.Limit).Offset(q.Offset).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list the login sessions of tenant %s: %w", tenantID, err)
	}

	r.openRecords(tenantID, rows)
	if err := r.attachLinks(ctx, tenantID, rows); err != nil {
		return nil, 0, err
	}
	return rows, int64(total), nil
}

// sessionOrderBy builds the ORDER BY clause of one page from the allow-list. A
// read that asks for no order reads newest first, which is what every admin list
// answers.
func sessionOrderBy(q Query) string {
	column, ok := sessionSortColumns[q.Sort]
	if !ok {
		return "s.created_at DESC"
	}
	if q.Desc {
		return column + " DESC"
	}
	return column + " ASC"
}

// openRecords reads the sealed session of each row. A row that cannot be opened
// keeps its columns and carries no context, and the failure is logged once: one
// unreadable blob must not cost the operator the whole page.
func (r *Repository) openRecords(tenantID string, rows []Record) {
	for i := range rows {
		live, err := open(Row{ID: rows[i].ID, Data: rows[i].Data}, r.cipher)
		if err != nil {
			r.log.Warn("open the sealed login session",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", rows[i].ID),
				logger.Err(err))
			continue
		}
		rows[i].IP = live.IP
		rows[i].UserAgent = live.UserAgent
		rows[i].Factors = live.Factors
	}
}

// attachLinks reads the protocol flows of the whole page in one query. One query
// per row would cost a round trip per session, and the console renders the count
// on every row.
func (r *Repository) attachLinks(ctx context.Context, tenantID string, rows []Record) error {
	if len(rows) == 0 {
		return nil
	}

	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}

	var links []Link
	if err := db.Conn(ctx, r.db).NewSelect().
		Model(&links).
		Column("login_session_id", "protocol", "protocol_ref", "client_id").
		Where("l.tenant_id = ?", tenantID).
		Where("l.login_session_id IN (?)", bun.In(ids)).
		Order("l.created_at ASC", "l.protocol_ref ASC").
		Scan(ctx); err != nil {
		return fmt.Errorf("read the protocol links of tenant %s: %w", tenantID, err)
	}

	bySession := make(map[string][]Link, len(rows))
	for _, link := range links {
		bySession[link.LoginSessionID] = append(bySession[link.LoginSessionID], link)
	}
	for i := range rows {
		rows[i].Links = bySession[rows[i].ID]
	}
	return nil
}

// DeleteSession hard deletes one login session and answers with what it held.
//
// A login session is a consumed row, so an administrative revoke removes it
// instead of marking it. The token digest comes back, because the cache is keyed
// by it and the row is the only place it is known.
//
// A session that is already gone answers ErrNoSuchSession. A terminated session
// is deleted like any other: the operator asked for the row to go.
func (r *Repository) DeleteSession(ctx context.Context, tenantID, sessionID string) (Revoked, error) {
	r.log.Debug("revoke login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", sessionID), logger.RequestID(ctx))

	var row Row
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&row).
		Column("id", "user_id", "token_hash").
		Where("tenant_id = ?", tenantID).
		Where("id = ?", sessionID).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return Revoked{}, fmt.Errorf("%w: tenant %s, session %s", ErrNoSuchSession, tenantID, sessionID)
	}
	if err != nil {
		return Revoked{}, fmt.Errorf("read login session %s of tenant %s: %w", sessionID, tenantID, err)
	}

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Row)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("id = ?", sessionID).
		Exec(ctx); err != nil {
		return Revoked{}, fmt.Errorf("revoke login session %s of tenant %s: %w", sessionID, tenantID, err)
	}

	r.log.Debug("revoked login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", sessionID), logger.RequestID(ctx))
	return Revoked{SessionID: row.ID, UserID: row.UserID, TokenHash: row.TokenHash}, nil
}

// DeleteUserSessions hard deletes every login session of one person, and answers
// with what each of them held.
//
// A person with no session answers an empty list and no error. The force-logout
// says that nothing of theirs is signed in, which is what the operator asked
// for.
func (r *Repository) DeleteUserSessions(ctx context.Context, tenantID, userID string) ([]Revoked, error) {
	r.log.Debug("revoke the login sessions of one person",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID), logger.RequestID(ctx))

	var rows []Row
	if err := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Column("id", "user_id", "token_hash").
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the login sessions of user %s of tenant %s: %w", userID, tenantID, err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	if _, err := db.Conn(ctx, r.db).NewDelete().
		Model((*Row)(nil)).
		Where("tenant_id = ?", tenantID).
		Where("user_id = ?", userID).
		Exec(ctx); err != nil {
		return nil, fmt.Errorf("revoke the login sessions of user %s of tenant %s: %w", userID, tenantID, err)
	}

	revoked := make([]Revoked, 0, len(rows))
	for _, row := range rows {
		revoked = append(revoked, Revoked{
			SessionID: row.ID, UserID: row.UserID, TokenHash: row.TokenHash,
		})
	}

	r.log.Debug("revoked the login sessions of one person",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID),
		logger.Int("sessions", len(revoked)), logger.RequestID(ctx))
	return revoked, nil
}
