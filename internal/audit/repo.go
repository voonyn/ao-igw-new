// Package audit records what happened, for the people who must answer that
// question later. A row is written on the transaction of the change it records,
// so the trail and the change land together or not at all.
package audit

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// Repository writes the audit trail.
type Repository struct {
	db  *bun.DB
	log logger.Logger
}

func NewRepository(bdb *bun.DB, log logger.Logger) *Repository {
	return &Repository{db: bdb, log: log}
}

// Insert writes one event. It runs on the caller's transaction, because
// db.Conn returns the transaction the context carries.
func (r *Repository) Insert(ctx context.Context, event Event) error {
	r.log.Debug("write audit event",
		logger.String("tenant_id", event.TenantID), logger.String("event_id", event.ID),
		logger.RequestID(ctx))

	if _, err := db.Conn(ctx, r.db).NewInsert().Model(&event).Exec(ctx); err != nil {
		return fmt.Errorf("write audit event %s of tenant %s: %w", event.Action, event.TenantID, err)
	}
	r.log.Debug("wrote audit event",
		logger.String("tenant_id", event.TenantID), logger.String("event_id", event.ID),
		logger.RequestID(ctx))
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
	r.log.Debug("list audit events",
		logger.String("tenant_id", tenantID), logger.Int("offset", q.Offset), logger.RequestID(ctx))

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

	r.log.Debug("listed audit events",
		logger.String("tenant_id", tenantID), logger.Int("count", len(rows)), logger.RequestID(ctx))
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
