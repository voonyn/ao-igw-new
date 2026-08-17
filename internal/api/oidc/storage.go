// Package oidc mounts the protocol engine. It is the only package that imports
// the go-oidc server side. It builds one provider per tenant and adapts the
// domain packages to the manager interfaces the engine calls.
package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/audit"
	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrRegistrationDisabled reports an attempt to register, change, or delete a
// client over the protocol. A client is created in the console, never by a
// request, so dynamic client registration stays closed.
var ErrRegistrationDisabled = errors.New("dynamic client registration is disabled")

// ClientFinder reads one client of one tenant. It returns
// aooidc.ErrClientNotFound when no live client carries the id.
type ClientFinder func(ctx context.Context, tenantID, clientID string) (goidc.Client, error)

// ClientManager is the goidc.DCRManager of one tenant. The provider is built per
// tenant, so the tenant id is bound here and the engine names the client alone.
// Only the read is implemented. Every write fails.
type ClientManager struct {
	tenantID string
	find     ClientFinder
	log      logger.Logger
}

func NewClientManager(tenantID string, find ClientFinder, log logger.Logger) *ClientManager {
	return &ClientManager{tenantID: tenantID, find: find, log: log}
}

// Client reads the client the engine names. A miss becomes goidc.ErrNotFound,
// which the engine answers as invalid_client.
func (m *ClientManager) Client(ctx context.Context, clientID string) (*goidc.Client, error) {
	client, err := m.find(ctx, m.tenantID, clientID)
	if errors.Is(err, aooidc.ErrClientNotFound) {
		return nil, fmt.Errorf("%w: client %s", goidc.ErrNotFound, clientID)
	}
	if err != nil {
		m.log.Error("read client",
			logger.String("tenant_id", m.tenantID),
			logger.String("client_id", clientID),
			logger.Err(err))
		return nil, err
	}
	return &client, nil
}

// SaveClient refuses to write a client. See ErrRegistrationDisabled.
func (m *ClientManager) SaveClient(context.Context, *goidc.Client) error {
	return ErrRegistrationDisabled
}

// DeleteClient refuses to delete a client. See ErrRegistrationDisabled.
func (m *ClientManager) DeleteClient(context.Context, string) error {
	return ErrRegistrationDisabled
}

// GrantSaver writes one grant of one tenant.
type GrantSaver func(ctx context.Context, tenantID string, grant *goidc.Grant) error

// GrantFinder reads one grant of one tenant by an id, an authorization code, or
// a refresh token. It returns aooidc.ErrGrantNotFound on a miss.
type GrantFinder func(ctx context.Context, tenantID, value string) (*goidc.Grant, error)

// SessionSaver writes one authn session of one tenant.
type SessionSaver func(ctx context.Context, tenantID string, session *goidc.AuthnSession) error

// SessionFinder reads one authn session of one tenant by its id. It returns
// aooidc.ErrSessionNotFound on a miss.
type SessionFinder func(ctx context.Context, tenantID, id string) (*goidc.AuthnSession, error)

// StorageFuncs is the database side of the protocol state stores. The provider
// build fills it from the storage repository.
type StorageFuncs struct {
	SaveGrant            GrantSaver
	Grant                GrantFinder
	GrantByAuthCode      GrantFinder
	GrantByRefreshToken  GrantFinder
	GrantsByLoginSession GrantLister
	SaveSession          SessionSaver
	Session              SessionFinder
}

// passingLogoutSessions is the goidc.LogoutManager of every tenant. It holds
// nothing.
//
// goidc keeps a logout session only to suspend a logout across two browser
// round trips, and it reads one back only at the continuation URL. The logout
// policy of this gateway never answers StatusPending, so no logout is ever
// suspended and nothing ever reads a session back. See logout.go.
//
// A slice that renders a sign-out screen must replace this with a real store at
// the same time as it makes the policy pend.
type passingLogoutSessions struct{}

var _ goidc.LogoutManager = passingLogoutSessions{}

func (passingLogoutSessions) SaveLogoutSession(context.Context, *goidc.LogoutSession) error {
	return nil
}

func (passingLogoutSessions) LogoutSession(context.Context, string) (*goidc.LogoutSession, error) {
	return nil, goidc.ErrNotFound
}

// StorageManager is the goidc.GrantManager, goidc.AuthManager, and
// goidc.RefreshTokenManager of one tenant. The provider is built per tenant, so
// the tenant id is bound here and the engine names the state alone.
type StorageManager struct {
	tenantID string
	store    StorageFuncs
	audit    *audit.Recorder
	log      logger.Logger
}

var (
	_ goidc.GrantManager        = (*StorageManager)(nil)
	_ goidc.AuthManager         = (*StorageManager)(nil)
	_ goidc.RefreshTokenManager = (*StorageManager)(nil)
)

// NewStorageManager binds one tenant to the protocol state stores. A nil
// recorder leaves the audit trail unwritten, which matches the development
// bootstrap.
func NewStorageManager(tenantID string, store StorageFuncs, rec *audit.Recorder, log logger.Logger) *StorageManager {
	return &StorageManager{tenantID: tenantID, store: store, audit: rec, log: log}
}

// SaveGrant writes the grant the engine issued.
//
// A grant that carries RevokedAt was just revoked. The engine has no revocation
// handler, and it reads the grant, returns early when the grant is already
// revoked, then stamps it and saves it. Every save of a revoked grant is
// therefore one fresh revocation, and this is the only place it is observable.
//
// ponytail: the transition is inferred from the saved row alone. If a caller
// ever saves an already-revoked grant a second time, read the stored grant here
// and compare.
func (m *StorageManager) SaveGrant(ctx context.Context, grant *goidc.Grant) error {
	if err := m.store.SaveGrant(ctx, m.tenantID, grant); err != nil {
		return err
	}
	if grant.RevokedAt == 0 {
		return nil
	}
	return m.recordRevocation(ctx, grant)
}

// recordRevocation writes the revocation into the audit trail. A nil recorder
// writes nothing, which matches the development bootstrap.
//
// The revocation endpoint mounts middlewares.InTx, so the row and the revoked
// grant land together or not at all. A failed write therefore fails the
// request: a revocation nobody can audit is not allowed to stand.
func (m *StorageManager) recordRevocation(ctx context.Context, grant *goidc.Grant) error {
	if m.audit == nil {
		return nil
	}

	m.log.Debug("grant revoked",
		logger.String("tenant_id", m.tenantID),
		logger.String("grant_id", grant.ID),
		RequestID(ctx))

	return m.audit.Record(ctx, audit.Entry{
		TenantID:   m.tenantID,
		ActorID:    grant.Subject,
		Action:     audit.ActionTokenRevoked,
		EntityType: "grant",
		EntityID:   grant.ID,
		Metadata: map[string]any{
			"client_id": grant.ClientID,
			"grant_id":  grant.ID,
		},
	})
}

// Grant reads the grant the engine names by id.
func (m *StorageManager) Grant(ctx context.Context, id string) (*goidc.Grant, error) {
	return m.readGrant(ctx, m.store.Grant, "id", id)
}

// GrantByAuthCode reads the grant a client redeems at the token endpoint. The
// code is a credential, so it never reaches a log line.
func (m *StorageManager) GrantByAuthCode(ctx context.Context, code string) (*goidc.Grant, error) {
	return m.readGrant(ctx, m.store.GrantByAuthCode, "auth code", code)
}

// GrantByRefreshToken reads the grant a client refreshes. The token is a
// credential, so it never reaches a log line.
//
// A token that was already rotated away is a replay. The store revoked the
// grant, so the read records the replay and fails: the engine answers
// invalid_grant, and the audit row names the grant, never the token.
func (m *StorageManager) GrantByRefreshToken(ctx context.Context, token string) (*goidc.Grant, error) {
	grant, err := m.readGrant(ctx, m.store.GrantByRefreshToken, "refresh token", token)

	var reuse *aooidc.ReuseError
	if errors.As(err, &reuse) {
		m.log.Error("refresh token reused",
			logger.String("tenant_id", m.tenantID),
			logger.String("grant_id", reuse.GrantID))
		if recErr := m.recordReuse(ctx, reuse); recErr != nil {
			return nil, recErr
		}
		return nil, fmt.Errorf("%w: refresh token of grant %s was reused", goidc.ErrNotFound, reuse.GrantID)
	}
	return grant, err
}

// recordReuse writes the replay into the audit trail. A nil recorder writes
// nothing, which matches the development bootstrap.
func (m *StorageManager) recordReuse(ctx context.Context, reuse *aooidc.ReuseError) error {
	if m.audit == nil {
		return nil
	}
	return m.audit.Record(ctx, audit.Entry{
		TenantID:   m.tenantID,
		ActorID:    reuse.Subject,
		Action:     audit.ActionTokenRefreshReused,
		EntityType: "grant",
		EntityID:   reuse.GrantID,
		Metadata: map[string]any{
			"client_id": reuse.ClientID,
			"grant_id":  reuse.GrantID,
			"reason":    "refresh token replay",
		},
	})
}

// SaveSession writes the authorization request in flight.
func (m *StorageManager) SaveSession(ctx context.Context, session *goidc.AuthnSession) error {
	return m.store.SaveSession(ctx, m.tenantID, session)
}

// Session reads the authorization request the engine names by id. A miss
// becomes goidc.ErrNotFound.
func (m *StorageManager) Session(ctx context.Context, id string) (*goidc.AuthnSession, error) {
	session, err := m.store.Session(ctx, m.tenantID, id)
	if errors.Is(err, aooidc.ErrSessionNotFound) {
		return nil, fmt.Errorf("%w: authn session %s", goidc.ErrNotFound, id)
	}
	if err != nil {
		m.log.Error("read authn session",
			logger.String("tenant_id", m.tenantID),
			logger.String("session_id", id),
			logger.Err(err))
		return nil, err
	}
	return session, nil
}

// readGrant runs one grant lookup. The value can be a credential, so only the
// name of the lookup is logged, never the value.
func (m *StorageManager) readGrant(ctx context.Context, find GrantFinder, by, value string) (*goidc.Grant, error) {
	grant, err := find(ctx, m.tenantID, value)
	if errors.Is(err, aooidc.ErrGrantNotFound) {
		return nil, fmt.Errorf("%w: no grant by %s", goidc.ErrNotFound, by)
	}
	// A replay is not a store failure. GrantByRefreshToken logs it and records
	// it, so it passes through here unlogged.
	if errors.Is(err, aooidc.ErrRefreshTokenReused) {
		return nil, err
	}
	if err != nil {
		m.log.Error("read grant",
			logger.String("tenant_id", m.tenantID),
			logger.String("by", by),
			logger.Err(err))
		return nil, err
	}
	return grant, nil
}

// RefuseRegistration is the goidc.DCRValidateInitialTokenFunc of every tenant.
// It refuses every registration attempt, so the endpoint never reaches the
// manager. The token is never logged.
func RefuseRegistration(context.Context, string) error {
	return ErrRegistrationDisabled
}
