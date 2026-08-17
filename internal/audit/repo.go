// Package audit records what happened, for the people who must answer that
// question later. A row is written on the transaction of the change it records,
// so the trail and the change land together or not at all.
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
)

// Event is one row of audit_events. The table is append-only: a row is never
// updated and never deleted, so the model carries no soft-delete column.
//
// Metadata holds non-secret context only. The recorder decides what reaches it.
type Event struct {
	bun.BaseModel `bun:"table:audit_events"`

	ID         string `bun:"id,pk"`
	TenantID   string `bun:"tenant_id"`
	ActorID    string `bun:"actor_id,nullzero"`
	Action     string `bun:"action"`
	EntityType string `bun:"entity_type"`
	EntityID   string `bun:"entity_id,nullzero"`
	Result     string `bun:"result"`
	IP         string `bun:"ip,nullzero"`
	UserAgent  string `bun:"user_agent,nullzero"`
	// Metadata is bound as a string, not as bytes. The column is MySQL JSON,
	// and the driver sends a []byte as a binary string, which MySQL refuses to
	// read as JSON.
	Metadata  string    `bun:"metadata,nullzero"`
	CreatedAt time.Time `bun:"created_at"`
}

// Repository writes the audit trail.
type Repository struct {
	db *bun.DB
}

func NewRepository(bdb *bun.DB) *Repository {
	return &Repository{db: bdb}
}

// Insert writes one event. It runs on the caller's transaction, because
// db.Conn returns the transaction the context carries.
func (r *Repository) Insert(ctx context.Context, event Event) error {
	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&event).Exec(ctx); err != nil {
		return fmt.Errorf("write audit event %s of tenant %s: %w", event.Action, event.TenantID, err)
	}
	return nil
}

// ListEvents reads one page of the audit trail of one tenant, and counts
// everything the filters match.
//
// The five predicates are conjoined. Each one is an equality, so the read stays
// on an index: migration 00025 indexes (tenant_id, created_at) and
// (tenant_id, actor_id), and 00035 adds (tenant_id, entity_id, created_at).
//
// The count is of the whole match and not of the page, because the console
// renders its pager from it.
func (r *Repository) ListEvents(ctx context.Context, tenantID string, q Query) ([]Event, int64, error) {
	var rows []Event
	sel := db.Conn(ctx, r.db).NewSelect().
		Model(&rows).
		Where("tenant_id = ?", tenantID)

	if q.Actor != "" {
		sel = sel.Where("actor_id = ?", q.Actor)
	}
	if q.Action != "" {
		sel = sel.Where("action = ?", q.Action)
	}
	if q.EntityType != "" {
		sel = sel.Where("entity_type = ?", q.EntityType)
	}
	if q.EntityID != "" {
		sel = sel.Where("entity_id = ?", q.EntityID)
	}
	// From is inclusive and To is exclusive, so an operator who reads one hour
	// and then the next neither drops an event nor reads one twice.
	if !q.From.IsZero() {
		sel = sel.Where("created_at >= ?", q.From)
	}
	if !q.To.IsZero() {
		sel = sel.Where("created_at < ?", q.To)
	}

	// The id breaks a tie, so two events written in the same millisecond keep one
	// order across the pages of one walk.
	total, err := sel.OrderExpr(eventOrderBy(q)).Order("id DESC").
		Limit(q.Limit).Offset(q.Offset).
		ScanAndCount(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list the audit events of tenant %s: %w", tenantID, err)
	}
	return rows, int64(total), nil
}

// eventOrderBy builds the ORDER BY clause of one page. The route offers one
// sort key, because (tenant_id, created_at) is the only ordering this table
// indexes, and a read that asks for no order reads newest first.
func eventOrderBy(q Query) string {
	if q.Sort == "created" && !q.Desc {
		return "created_at ASC"
	}
	return "created_at DESC"
}
