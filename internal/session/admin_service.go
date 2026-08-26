package session

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"time"

	"alphaomega/identitygateway/internal/actor"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// ErrForbidden reports that the person does not administer this tenant. A
// session and a grant reach every organization, so only a tenant manager reads
// or revokes one.
var ErrForbidden = errors.New("only a tenant manager reads or revokes a login session")

// Actor is the person behind one administrative request. The IP and the agent
// travel to the audit trail, so the trail names where the revoke came from.
type Actor actor.Actor

// The reads and writes the administrative service composes its answers from.
// Each one is a function value, so the logic is testable without a database and
// without Redis.
type (
	// SessionLister reads one page of the login sessions of one tenant.
	SessionLister func(ctx context.Context, tenantID string, q Query) ([]Record, int64, error)

	// SessionRevoker hard deletes one login session, from the database and from
	// the cache. It returns ErrNoSuchSession when no row carries the id.
	SessionRevoker func(ctx context.Context, tenantID, sessionID string) (Revoked, error)

	// UserSessionRevoker hard deletes every login session of one person. A
	// person with no session is not an error.
	UserSessionRevoker func(ctx context.Context, tenantID, userID string) ([]Revoked, error)

	// GrantRevoker hard deletes every grant one login session produced, and
	// answers how many went. The oidc domain owns the table, so it arrives as a
	// function value.
	GrantRevoker func(ctx context.Context, tenantID, sessionID string) (int, error)

	// UserGrantRevoker hard deletes every grant one person holds, whatever
	// sign-in produced it, and answers how many went.
	UserGrantRevoker func(ctx context.Context, tenantID, userID string) (int, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// membership holds no role, which is not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)
)

// AdminDeps is the database side of the administrative service.
type AdminDeps struct {
	List             SessionLister
	Revoke           SessionRevoker
	RevokeUser       UserSessionRevoker
	RevokeGrants     GrantRevoker
	RevokeUserGrants UserGrantRevoker
	TenantRoles      TenantRoleFinder

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AdminService serves the login sessions of a tenant to the console, and the two
// revokes that end them.
type AdminService struct {
	deps AdminDeps
	log  logger.Logger
}

func NewAdminService(deps AdminDeps) *AdminService {
	return &AdminService{deps: deps, log: deps.Log}
}

// List reads one page of the login sessions of the tenant.
func (s *AdminService) List(ctx context.Context, a Actor, q Query) ([]SessionView, int64, error) {
	s.log.Debug("list login sessions",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, "list login sessions"); err != nil {
		return nil, 0, err
	}

	rows, total, err := s.deps.List(ctx, a.TenantID, q)
	if err != nil {
		return nil, 0, s.fail(a, "list login sessions", err)
	}

	views := make([]SessionView, 0, len(rows))
	for _, row := range rows {
		views = append(views, view(row))
	}
	return views, total, nil
}

// Revoke ends one login session and every grant it produced.
//
// The session is a consumed row, so it is hard deleted from the database and
// from the cache. The grants go with it, offline_access included, so no refresh
// token of that sign-in survives. An access token already issued is a signed
// value no store holds, and it lives out its lifetime at the relying party.
func (s *AdminService) Revoke(ctx context.Context, a Actor, sessionID string) (RevokedView, error) {
	s.log.Debug("revoke a login session",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("session_id", sessionID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, "revoke a login session"); err != nil {
		return RevokedView{}, err
	}

	var out RevokedView
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		revoked, err := s.deps.Revoke(ctx, a.TenantID, sessionID)
		if err != nil {
			return err
		}
		grants, err := s.deps.RevokeGrants(ctx, a.TenantID, sessionID)
		if err != nil {
			return err
		}

		out = RevokedView{Sessions: 1, Grants: grants}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionSessionRevoked,
			EntityType: audit.EntitySession,
			EntityID:   sessionID,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
			Metadata:   map[string]any{"user_id": revoked.UserID, "grants": grants},
		})
	})
	if err != nil {
		if errors.Is(err, ErrNoSuchSession) {
			return RevokedView{}, err
		}
		return RevokedView{}, s.fail(a, "revoke a login session", err)
	}

	s.log.Info("revoked a login session",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("session_id", sessionID),
		logger.Int("grants", out.Grants))
	return out, nil
}

// RevokeForUser signs one person out of everything: every login session they
// hold, and every grant, whatever sign-in produced it.
//
// A person with nothing signed in is not an error. The answer counts what went,
// and zero is a true answer to the question the operator asked.
func (s *AdminService) RevokeForUser(ctx context.Context, a Actor, userID string) (RevokedView, error) {
	s.log.Debug("sign a person out everywhere",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID), logger.RequestID(ctx))

	if err := s.authorize(ctx, a, "sign a person out everywhere"); err != nil {
		return RevokedView{}, err
	}

	var out RevokedView
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		revoked, err := s.deps.RevokeUser(ctx, a.TenantID, userID)
		if err != nil {
			return err
		}
		grants, err := s.deps.RevokeUserGrants(ctx, a.TenantID, userID)
		if err != nil {
			return err
		}

		out = RevokedView{Sessions: len(revoked), Grants: grants}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    a.UserID,
			Action:     audit.ActionSessionRevoked,
			EntityType: audit.EntityUser,
			EntityID:   userID,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
			Metadata:   map[string]any{"sessions": len(revoked), "grants": grants},
		})
	})
	if err != nil {
		return RevokedView{}, s.fail(a, "sign a person out everywhere", err)
	}

	s.log.Info("signed a person out everywhere",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("target_user_id", userID),
		logger.Int("sessions", out.Sessions),
		logger.Int("grants", out.Grants))
	return out, nil
}

// authorize is the gate of every route of this service.
//
// A login session belongs to the tenant and not to an organization: it signs its
// owner into every application of every organization at once. Only a tenant
// manager therefore reads one or ends one.
func (s *AdminService) authorize(ctx context.Context, a Actor, what string) error {
	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}
	if slices.Contains(roles, tenant.RoleIAMOwner) || slices.Contains(roles, tenant.RoleIAMAdmin) {
		return nil
	}

	s.log.Warn("refused a person who does not administer the tenant",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *AdminService) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}

// view is one login session as the console reads it. Both collections carry []
// and never null, because the console iterates each of them without a guard.
func view(row Record) SessionView {
	return SessionView{
		ID:        row.ID,
		TenantID:  row.TenantID,
		UserID:    row.UserID,
		UserName:  row.UserName,
		OrgID:     row.OrgID,
		State:     row.State,
		Created:   row.CreatedAt,
		Expires:   row.ExpiresAt,
		IP:        row.IP,
		UserAgent: row.UserAgent,
		Factors:   factorViews(row.Factors),
		Links:     linkViews(row.Links),
	}
}

// factorViews turns the factor map into a list the console renders. A map has no
// order, so the list is sorted by the AMR name and one session reads the same
// way on every request.
func factorViews(factors map[string]time.Time) []FactorView {
	views := make([]FactorView, 0, len(factors))
	for amr, at := range factors {
		views = append(views, FactorView{AMR: amr, Time: at})
	}
	sort.Slice(views, func(i, j int) bool { return views[i].AMR < views[j].AMR })
	return views
}

func linkViews(links []Link) []LinkView {
	views := make([]LinkView, 0, len(links))
	for _, link := range links {
		views = append(views, LinkView{Protocol: link.Protocol, AppID: link.AppID, Ref: link.Ref})
	}
	return views
}
