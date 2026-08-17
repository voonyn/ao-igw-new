package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrForbidden reports that the person does not administer this tenant. The
// feed carries every organization at once, so only a tenant manager reads it.
var ErrForbidden = errors.New("only a tenant manager reads the audit trail")

// Actor is the person behind one read of the feed. A read records nothing, so
// the address and the agent of the request are not needed here.
type Actor struct {
	TenantID string
	UserID   string
}

// The reads the service composes its answer from. Each one is a function value,
// so the logic is testable without a database.
type (
	// EventLister reads one page of the audit trail of one tenant.
	EventLister func(ctx context.Context, tenantID string, q Query) ([]Event, int64, error)

	// TenantManagerFinder reports whether one person administers the tenant.
	//
	// The role names are constants of internal/tenant, and that package records
	// its own writes through this one, so an import back would close a cycle.
	// The check arrives as a function value instead.
	TenantManagerFinder func(ctx context.Context, tenantID, userID string) (bool, error)
)

// Deps is the database side of the service.
type Deps struct {
	List          EventLister
	TenantManager TenantManagerFinder
	Log           logger.Logger
}

// Service serves the audit trail of one tenant to the console.
//
// The trail is a read and nothing more. A row of audit_events records a fact, so
// it is never updated and never deleted.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// List reads one page of the audit trail of the tenant.
func (s *Service) List(ctx context.Context, a Actor, q Query) ([]EventView, int64, error) {
	s.log.Debug("list audit events",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorize(ctx, a); err != nil {
		return nil, 0, err
	}

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		return nil, 0, s.fail(a, "list audit events", err)
	}

	views := make([]EventView, 0, len(rows))
	for _, row := range rows {
		views = append(views, eventView(row))
	}

	s.log.Debug("listed audit events",
		logger.String("tenant_id", a.TenantID), logger.Int("rows", len(views)))
	return views, total, nil
}

// authorize is the gate of the feed.
//
// An audit event is written by every domain of the tenant, and the trail names
// people across every organization. A manager of one organization would
// therefore read what another organization did, so only a tenant manager reads
// it at all.
func (s *Service) authorize(ctx context.Context, a Actor) error {
	manager, err := s.deps.TenantManager(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}
	if manager {
		return nil
	}

	s.log.Warn("refused a person who does not administer the tenant",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
	return fmt.Errorf("%w: tenant %s, user %s", ErrForbidden, a.TenantID, a.UserID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *Service) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}

// eventView is one row as the console reads it. An empty metadata column
// carries no field, because the console parses the value as JSON.
func eventView(row Event) EventView {
	view := EventView{
		ID:         row.ID,
		Actor:      row.ActorID,
		Action:     row.Action,
		EntityType: row.EntityType,
		EntityID:   row.EntityID,
		Result:     row.Result,
		IP:         row.IP,
		UserAgent:  row.UserAgent,
		CreatedAt:  row.CreatedAt,
	}
	if row.Metadata != "" {
		view.Metadata = json.RawMessage(row.Metadata)
	}
	return view
}
