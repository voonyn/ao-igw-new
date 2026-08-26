package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// AccountDeps is the database side of the self-service session API. It reads and
// revokes with the same function values the administrative service takes, so one
// repository answers both callers.
type AccountDeps struct {
	List         SessionLister
	Revoke       SessionRevoker
	RevokeOthers UserSessionRevoker
	RevokeGrants GrantRevoker

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AccountService serves a person their own login sessions, and ends any of them.
//
// There is no role gate. Every method narrows to the subject of the caller's
// token before it reads or writes, so the caller is the only person these
// methods can reach.
type AccountService struct {
	deps AccountDeps
	log  logger.Logger
}

func NewAccountService(deps AccountDeps) *AccountService {
	return &AccountService{deps: deps, log: deps.Log}
}

// List reads the live login sessions of the person who made the request.
//
// The answer marks no session as the caller's own. The access token carries no
// session identifier, so the gateway cannot name it. The portal holds a
// validated ID token, which carries sid, and it marks the row itself.
func (s *AccountService) List(ctx context.Context, a Actor) ([]AccountSession, error) {
	s.log.Debug("list own login sessions",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	rows, err := s.own(ctx, a)
	if err != nil {
		return nil, s.fail(a, "list own login sessions", err)
	}

	views := make([]AccountSession, 0, len(rows))
	for _, row := range rows {
		views = append(views, AccountSession{
			ID:        row.ID,
			State:     row.State,
			CreatedAt: row.CreatedAt,
			ExpiresAt: row.ExpiresAt,
			IP:        row.IP,
			UserAgent: row.UserAgent,
		})
	}
	return views, nil
}

// Revoke ends one login session of the caller, and every grant it fanned out to.
//
// The delete names the caller, so the query itself is the ownership rule. A
// session that belongs to somebody else answers ErrNoSuchSession, and so does a
// session that does not exist. The two refusals read alike, so the answer never
// says which login sessions another person holds.
func (s *AccountService) Revoke(ctx context.Context, a Actor, sessionID string) (RevokedView, error) {
	s.log.Debug("revoke own login session",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("session_id", sessionID), logger.RequestID(ctx))

	if a.UserID == "" {
		return RevokedView{}, s.noSubject(a, sessionID)
	}

	var out RevokedView
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.deps.Revoke(ctx, a.TenantID, a.UserID, sessionID); err != nil {
			return err
		}
		grants, err := s.deps.RevokeGrants(ctx, a.TenantID, sessionID)
		if err != nil {
			return err
		}

		out = RevokedView{Sessions: 1, Grants: grants}
		return s.record(ctx, a, audit.EntitySession, sessionID, out)
	})
	return s.done(a, out, err)
}

// RevokeOthers ends every login session of the caller except the one named, and
// every grant those sessions fanned out to.
//
// exceptID is the session the caller is using, as the portal reads it from the
// ID token. With no session named, nothing is excepted and the caller signs out
// everywhere, their own browser included. That is the sign-out-everywhere
// control, and the portal asks before it sends no id.
//
// The delete names the person, so it reaches every session they hold. It is not
// bounded by what one page of a list read would have carried.
func (s *AccountService) RevokeOthers(ctx context.Context, a Actor, exceptID string) (RevokedView, error) {
	s.log.Debug("revoke every other own login session",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("except_session_id", exceptID), logger.RequestID(ctx))

	if a.UserID == "" {
		return RevokedView{}, s.noSubject(a, exceptID)
	}

	var out RevokedView
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		revoked, err := s.deps.RevokeOthers(ctx, a.TenantID, a.UserID, exceptID)
		if err != nil {
			return err
		}

		// A grant fans out from one session, so the grants go one session at a
		// time. The loop walks what the delete removed, and a person holds one
		// login session per device.
		for _, row := range revoked {
			grants, err := s.deps.RevokeGrants(ctx, a.TenantID, row.SessionID)
			if err != nil {
				return err
			}
			out.Grants += grants
		}
		out.Sessions = len(revoked)

		return s.record(ctx, a, audit.EntityUser, a.UserID, out)
	})
	return s.done(a, out, err)
}

// ownSessionLimit bounds one self-service read. A person holds one login session
// per browser and per device, so the list is bounded by how many things they
// sign in on. The route therefore pages nothing and answers whole.
//
// ponytail: a constant. Nobody reaches it, and a person who does reads the
// hundred newest.
const ownSessionLimit = 100

// own reads the live login sessions of the caller. It serves the list and
// nothing else: the two revokes narrow in the query they delete with, so neither
// of them is bounded by what one page of this read carried.
//
// The read narrows to active sessions and then drops the expired ones. State is
// a lifecycle and an operator must read a session that ended, but a person
// asking where they are signed in must not, because they cannot act on it.
func (s *AccountService) own(ctx context.Context, a Actor) ([]Record, error) {
	// The bearer guard verified the subject, so this cannot happen. It costs one
	// comparison to make sure that a missing subject reads nothing instead of
	// reading every session of the tenant.
	if a.UserID == "" {
		return nil, nil
	}

	rows, _, err := s.deps.List(ctx, a.TenantID, Query{
		UserID: a.UserID,
		State:  StateActive,
		Limit:  ownSessionLimit,
	})
	if err != nil {
		return nil, err
	}

	now := time.Now()
	live := make([]Record, 0, len(rows))
	for _, row := range rows {
		if row.ExpiresAt.IsZero() || row.ExpiresAt.After(now) {
			live = append(live, row)
		}
	}
	return live, nil
}

// record writes the audit event of one revoke, on the caller's transaction.
//
// A revoke that ended nothing records no event. A person with one device and
// nothing else signed in asked a real question, zero is the true answer to it,
// and no fact happened for the trail to hold.
func (s *AccountService) record(
	ctx context.Context, a Actor, entityType, entityID string, out RevokedView,
) error {
	if out.Sessions == 0 {
		return nil
	}
	return s.deps.Audit.Record(ctx, audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     audit.ActionSessionRevoked,
		EntityType: entityType,
		EntityID:   entityID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
		Metadata:   map[string]any{"sessions": out.Sessions, "grants": out.Grants},
	})
}

// done is the exit of both revokes: it drops the counts of a transaction that
// rolled back, and logs the one line production keeps of a completed write.
func (s *AccountService) done(a Actor, out RevokedView, err error) (RevokedView, error) {
	if err != nil {
		if errors.Is(err, ErrNoSuchSession) {
			return RevokedView{}, err
		}
		return RevokedView{}, s.fail(a, "revoke own login sessions", err)
	}
	if out.Sessions == 0 {
		return out, nil
	}

	s.log.Info("revoked own login sessions",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Int("sessions", out.Sessions),
		logger.Int("grants", out.Grants))
	return out, nil
}

// noSubject refuses a request whose token named nobody. The bearer guard
// verified the subject, so this cannot happen. It exists because an empty
// subject would otherwise reach the repository, where an empty owner means every
// person in the tenant.
func (s *AccountService) noSubject(a Actor, sessionID string) error {
	s.log.Warn("refused a request whose token names no subject",
		logger.String("tenant_id", a.TenantID), logger.String("session_id", sessionID))
	return fmt.Errorf("%w: tenant %s, session %s", ErrNoSuchSession, a.TenantID, sessionID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *AccountService) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}
