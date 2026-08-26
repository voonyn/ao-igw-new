package oidc

import (
	"context"
	"errors"
	"strings"

	"alphaomega/identitygateway/internal/actor"
	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// AccountActor is the person behind one self-service request. Every method
// narrows to this person, so the caller is the only person these methods reach.
type AccountActor actor.Actor

// The reads and writes the self-service service composes its answers from. Each
// one is a function value, so the logic is testable without a database.
type (
	// ConsentLister reads the live consents of one person, newest first.
	ConsentLister func(ctx context.Context, tenantID, userID string) ([]ConnectionRecord, error)

	// ConsentWithdrawer soft deletes the consent of one person for one client.
	// A pair with no live consent answers ErrConsentNotFound.
	ConsentWithdrawer func(ctx context.Context, tenantID, userID, clientID string) error

	// ClientGrantRevoker hard deletes the grants of one person for one client
	// and answers how many went.
	ClientGrantRevoker func(ctx context.Context, tenantID, subject, clientID string) (int, error)
)

// AccountDeps is the database side of the connected applications API.
type AccountDeps struct {
	List     ConsentLister
	Withdraw ConsentWithdrawer
	Revoke   ClientGrantRevoker

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AccountService serves a person the applications that hold their consent, and
// disconnects one of them.
//
// There is no role gate. Both methods narrow to the subject of the caller's
// token before they read or write, so the answer is the same whatever role the
// caller holds.
type AccountService struct {
	deps AccountDeps
	log  logger.Logger
}

func NewAccountService(deps AccountDeps) *AccountService {
	return &AccountService{deps: deps, log: deps.Log}
}

// List reads the applications the caller connected.
//
// The list is bounded by how many applications one person connected, so it pages
// nothing and answers whole.
func (s *AccountService) List(ctx context.Context, a AccountActor) ([]ConnectionView, error) {
	s.log.Debug("list own connections",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	rows, err := s.deps.List(ctx, a.TenantID, a.UserID)
	if err != nil {
		s.log.Error("list own connections",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID), logger.Err(err))
		return nil, err
	}

	views := make([]ConnectionView, 0, len(rows))
	for _, row := range rows {
		views = append(views, ConnectionView{
			ClientID:     row.ClientID,
			AppName:      row.AppName,
			Scopes:       strings.Fields(row.Scopes),
			HasLiveGrant: row.HasGrant,
			CreatedAt:    row.CreatedAt,
			UpdatedAt:    row.UpdatedAt,
		})
	}

	s.log.Debug("listed own connections",
		logger.String("tenant_id", a.TenantID), logger.Int("rows", len(views)), logger.RequestID(ctx))
	return views, nil
}

// Disconnect withdraws the consent the caller gave one client, and deletes the
// grants that consent produced.
//
// The two writes and the audit event land on one transaction. Both happen or
// neither does, so the application can never keep a refresh token of a consent
// that is already withdrawn.
//
// The withdraw names the caller, so the query itself is the ownership rule. A
// client the caller never connected answers ErrConsentNotFound, and so does one
// somebody else connected. The two refusals read alike, so the answer never says
// which applications another person connected.
func (s *AccountService) Disconnect(
	ctx context.Context, a AccountActor, clientID string,
) (DisconnectedView, error) {
	s.log.Debug("disconnect an own connection",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("client_id", clientID), logger.RequestID(ctx))

	out := DisconnectedView{ClientID: clientID}
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Withdraw(ctx, a.TenantID, a.UserID, clientID); err != nil {
			return err
		}
		grants, err := s.deps.Revoke(ctx, a.TenantID, a.UserID, clientID)
		if err != nil {
			return err
		}

		out.Grants = grants
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID: a.TenantID,
			ActorID:  a.UserID,
			Action:   audit.ActionConsentRevoked,
			// The consent grant of this pair records against "consent" too,
			// so the two halves of one connection read as one entity.
			EntityType: "consent",
			EntityID:   clientID,
			IP:         a.IP,
			UserAgent:  a.UserAgent,
			Metadata:   map[string]any{"client_id": clientID, "grants": grants},
		})
	})
	if err != nil {
		if errors.Is(err, ErrConsentNotFound) {
			return DisconnectedView{}, err
		}
		s.log.Error("disconnect an own connection",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.String("client_id", clientID), logger.Err(err))
		return DisconnectedView{}, err
	}

	s.log.Info("disconnected an own connection",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("client_id", clientID),
		logger.Int("grants", out.Grants))
	return out, nil
}
