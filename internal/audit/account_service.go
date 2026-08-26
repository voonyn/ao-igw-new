package audit

import (
	"context"

	"alphaomega/identitygateway/internal/platform/logger"
)

// AccountDeps is the database side of the activity feed. The feed is a read and
// nothing more, so one read is the whole of it.
type AccountDeps struct {
	List EventLister
	Log  logger.Logger
}

// AccountService serves a person the audit events they caused.
//
// There is no role gate to write. The feed is narrowed to the subject of the
// caller's own token, so a person who reads it reads themselves and the answer
// is the same whatever role they hold.
//
// The feed shows the events where the person was the actor. An event where the
// person was acted upon, such as an administrator locking the account, is not
// shown. That limit is deliberate, and it has a cost: an administrator locking
// somebody's account never appears in that person's feed.
type AccountService struct {
	deps AccountDeps
	log  logger.Logger
}

func NewAccountService(deps AccountDeps) *AccountService {
	return &AccountService{deps: deps, log: deps.Log}
}

// List reads one page of the events the caller caused.
//
// The actor is overwritten with the subject of the token, so an actor the
// request named is discarded before the read. No event of another person is
// reachable, whatever the request carries.
//
// The total counts the whole match and not the page, because the portal renders
// its pager from it.
func (s *AccountService) List(ctx context.Context, a Actor, q Query) ([]ActivityView, int64, error) {
	s.log.Debug("list own activity",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	q.Actor = a.UserID

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		s.log.Error("list own activity",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID), logger.Err(err))
		return nil, 0, err
	}

	views := make([]ActivityView, 0, len(rows))
	for _, row := range rows {
		views = append(views, activityView(row))
	}

	s.log.Debug("listed own activity",
		logger.String("tenant_id", a.TenantID), logger.Int("rows", len(views)), logger.RequestID(ctx))
	return views, total, nil
}

// activityView is one row as the person reads it. The actor and the metadata of
// the row are not copied, so neither reaches the answer.
func activityView(row Event) ActivityView {
	return ActivityView{
		ID:         row.ID,
		Action:     row.Action,
		EntityType: row.EntityType,
		EntityID:   row.EntityID,
		Result:     row.Result,
		IP:         row.IP,
		UserAgent:  row.UserAgent,
		CreatedAt:  row.CreatedAt,
	}
}
