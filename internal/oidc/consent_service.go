package oidc

import (
	"context"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ConsentState is what the database knows about one person and one client:
// whether the tenant owns the client, and the scopes the person approved for it
// before now.
type ConsentState struct {
	FirstParty bool
	Scopes     []string
}

// ConsentFinder reads the consent state of one person and one client. An
// unknown pair answers with a zero state and no error, because a client with no
// consent row is the normal first visit.
type ConsentFinder func(ctx context.Context, tenantID, userID, clientID string) (ConsentState, error)

// ConsentSaver writes the scopes one person allows one client. It replaces the
// stored set, so the caller passes the union it wants held.
type ConsentSaver func(ctx context.Context, tenantID, userID, clientID string, scopes []string) error

// ConsentDeps is the database side of the consent service.
type ConsentDeps struct {
	Find  ConsentFinder
	Save  ConsentSaver
	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// Consent is the answer one person gave on the consent screen: which client
// asked, and which scopes the screen named.
type Consent struct {
	TenantID  string
	UserID    string
	ClientID  string
	Scopes    []string
	IP        string
	UserAgent string
}

// ConsentService decides whether one authorization request needs the consent
// screen, and records the answer the person gives.
type ConsentService struct {
	deps ConsentDeps
	log  logger.Logger
}

func NewConsentService(deps ConsentDeps) *ConsentService {
	return &ConsentService{deps: deps, log: deps.Log}
}

// Decide reports the scopes the person must still approve. An empty answer
// means the request needs no consent screen.
//
// A first-party client never asks, because the person already trusts the
// tenant.
func (s *ConsentService) Decide(
	ctx context.Context, tenantID, userID, clientID string, requested []string, force bool,
) ([]string, error) {
	s.log.Debug("decide consent",
		logger.String("tenant_id", tenantID),
		logger.String("client_id", clientID), logger.RequestID(ctx))

	// prompt=consent overrules everything the database holds, so no lookup runs.
	// The person answers again for the whole request.
	if force {
		return requested, nil
	}

	state, err := s.deps.Find(ctx, tenantID, userID, clientID)
	if err != nil {
		s.log.Error("read consent",
			logger.String("tenant_id", tenantID),
			logger.String("client_id", clientID),
			logger.Err(err))
		return nil, err
	}
	if state.FirstParty {
		return nil, nil
	}
	return missingScopes(requested, state.Scopes), nil
}

// Approve records that the person allowed the client the scopes the screen
// named. The stored set grows to the union, so a scope approved once is never
// asked for again.
//
// The union and the audit row land on one transaction. A failed audit write
// rolls the union back, because a consent nobody can audit is not allowed to
// stand.
func (s *ConsentService) Approve(ctx context.Context, given Consent) error {
	s.log.Debug("record consent",
		logger.String("tenant_id", given.TenantID),
		logger.String("client_id", given.ClientID), logger.RequestID(ctx))

	state, err := s.deps.Find(ctx, given.TenantID, given.UserID, given.ClientID)
	if err != nil {
		s.log.Error("read consent",
			logger.String("tenant_id", given.TenantID),
			logger.String("client_id", given.ClientID),
			logger.Err(err))
		return err
	}

	union := append(state.Scopes, missingScopes(given.Scopes, state.Scopes)...)
	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Save(ctx, given.TenantID, given.UserID, given.ClientID, union); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, given.entry(audit.ActionConsentGranted, union))
	})
	if err != nil {
		s.log.Error("record consent",
			logger.String("tenant_id", given.TenantID),
			logger.String("client_id", given.ClientID),
			logger.Err(err))
		return err
	}

	s.log.Debug("recorded consent",
		logger.String("tenant_id", given.TenantID),
		logger.String("user_id", given.UserID),
		logger.String("client_id", given.ClientID), logger.RequestID(ctx))
	return nil
}

// Deny records that the person refused the client. Nothing is stored, so the
// next authorization request asks again.
func (s *ConsentService) Deny(ctx context.Context, given Consent) error {
	s.log.Warn("consent refused",
		logger.String("tenant_id", given.TenantID),
		logger.String("user_id", given.UserID),
		logger.String("client_id", given.ClientID))

	return s.deps.Audit.Record(ctx, given.entry(audit.ActionConsentDenied, given.Scopes))
}

// entry describes one consent answer for the audit trail. It names the client
// and the scopes, and never a credential.
func (c Consent) entry(action audit.Action, scopes []string) audit.Entry {
	return audit.Entry{
		TenantID:   c.TenantID,
		ActorID:    c.UserID,
		Action:     action,
		EntityType: "consent",
		EntityID:   c.ClientID,
		IP:         c.IP,
		UserAgent:  c.UserAgent,
		Metadata: map[string]any{
			"client_id": c.ClientID,
			"scopes":    scopes,
		},
	}
}

// missingScopes reports the requested scopes the stored set does not hold. An
// empty answer means the stored set covers the request.
func missingScopes(requested, stored []string) []string {
	held := make(map[string]bool, len(stored))
	for _, scope := range stored {
		held[scope] = true
	}

	var missing []string
	for _, scope := range requested {
		if !held[scope] {
			missing = append(missing, scope)
		}
	}
	return missing
}
