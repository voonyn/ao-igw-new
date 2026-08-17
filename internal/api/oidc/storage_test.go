package oidc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/luikyv/go-oidc/pkg/goidc"

	"alphaomega/identitygateway/internal/audit"
	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// clientManager builds the manager over a stub finder, so the test needs no
// database. The finder answers for one client of one tenant.
func clientManager(t *testing.T, tenantID string, seen *string) *ClientManager {
	t.Helper()

	find := func(_ context.Context, tenant, clientID string) (goidc.Client, error) {
		if seen != nil {
			*seen = tenant
		}
		if clientID != "client-1" {
			return goidc.Client{}, aooidc.ErrClientNotFound
		}
		return goidc.Client{ID: clientID}, nil
	}
	return NewClientManager(tenantID, find, logger.New())
}

// memoryStore is the database side of the protocol state stores, held in a map.
// The manager is the seam under test, so the store needs no database.
type memoryStore struct {
	grants   map[string]*goidc.Grant
	sessions map[string]*goidc.AuthnSession
	tenants  []string
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		grants:   map[string]*goidc.Grant{},
		sessions: map[string]*goidc.AuthnSession{},
	}
}

func (s *memoryStore) funcs() StorageFuncs {
	saveGrant := func(_ context.Context, tenantID string, grant *goidc.Grant) error {
		s.tenants = append(s.tenants, tenantID)
		s.grants[grant.ID] = grant
		return nil
	}
	find := func(match func(*goidc.Grant) string) GrantFinder {
		return func(_ context.Context, tenantID, value string) (*goidc.Grant, error) {
			s.tenants = append(s.tenants, tenantID)
			for _, grant := range s.grants {
				if value != "" && match(grant) == value {
					return grant, nil
				}
			}
			return nil, aooidc.ErrGrantNotFound
		}
	}
	return StorageFuncs{
		SaveGrant:           saveGrant,
		Grant:               find(func(g *goidc.Grant) string { return g.ID }),
		GrantByAuthCode:     find(func(g *goidc.Grant) string { return g.AuthCode }),
		GrantByRefreshToken: find(func(g *goidc.Grant) string { return g.RefreshToken }),
		SaveSession: func(_ context.Context, tenantID string, session *goidc.AuthnSession) error {
			s.tenants = append(s.tenants, tenantID)
			s.sessions[session.ID] = session
			return nil
		},
		Session: func(_ context.Context, tenantID, id string) (*goidc.AuthnSession, error) {
			s.tenants = append(s.tenants, tenantID)
			session, ok := s.sessions[id]
			if !ok {
				return nil, aooidc.ErrSessionNotFound
			}
			return session, nil
		},
	}
}

// TestStorageManager_RefreshTokenReused covers a replayed refresh token. The
// store reports the reuse, so the manager fails the request and records the
// replay against the grant it belongs to.
func TestStorageManager_RefreshTokenReused(t *testing.T) {
	store := newMemoryStore()
	funcs := store.funcs()
	funcs.GrantByRefreshToken = func(context.Context, string, string) (*goidc.Grant, error) {
		return nil, &aooidc.ReuseError{GrantID: "grant-1", ClientID: "client-1", Subject: "user-1"}
	}

	var written []audit.Event
	recorder := audit.NewRecorder(func(_ context.Context, event audit.Event) error {
		written = append(written, event)
		return nil
	}, logger.New())
	manager := NewStorageManager("tenant-1", funcs, recorder, logger.New())

	_, err := manager.GrantByRefreshToken(context.Background(), "the-replayed-token")
	if !errors.Is(err, goidc.ErrNotFound) {
		t.Fatalf("read gives %v, want goidc.ErrNotFound", err)
	}

	if len(written) != 1 {
		t.Fatalf("recorded %d events, want one", len(written))
	}
	event := written[0]
	if event.Action != string(audit.ActionTokenRefreshReused) {
		t.Errorf("the action is %q, want %q", event.Action, audit.ActionTokenRefreshReused)
	}
	if event.TenantID != "tenant-1" || event.EntityID != "grant-1" || event.ActorID != "user-1" {
		t.Errorf("the event is %+v, want the tenant, the grant, and the subject", event)
	}
	if strings.Contains(event.Metadata, "the-replayed-token") || strings.Contains(err.Error(), "the-replayed-token") {
		t.Error("the replayed token reached the audit row or the error")
	}
}

// TestStorageManager_RevokedGrant covers a revocation. The engine stamps
// RevokedAt and saves, so the save is where the revocation becomes observable
// and where the audit row is written.
func TestStorageManager_RevokedGrant(t *testing.T) {
	var written []audit.Event
	recorder := audit.NewRecorder(func(_ context.Context, event audit.Event) error {
		written = append(written, event)
		return nil
	}, logger.New())
	manager := NewStorageManager("tenant-1", newMemoryStore().funcs(), recorder, logger.New())
	ctx := context.Background()

	live := &goidc.Grant{ID: "grant-1", ClientID: "client-1", Subject: "user-1"}
	if err := manager.SaveGrant(ctx, live); err != nil {
		t.Fatalf("save live grant: %v", err)
	}
	if len(written) != 0 {
		t.Fatalf("a live grant recorded %d events, want none", len(written))
	}

	revoked := &goidc.Grant{ID: "grant-2", ClientID: "client-1", Subject: "user-1", RevokedAt: 1755300000}
	if err := manager.SaveGrant(ctx, revoked); err != nil {
		t.Fatalf("save revoked grant: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("a revoked grant recorded %d events, want one", len(written))
	}

	event := written[0]
	if event.Action != string(audit.ActionTokenRevoked) {
		t.Errorf("the action is %q, want %q", event.Action, audit.ActionTokenRevoked)
	}
	if event.TenantID != "tenant-1" || event.EntityID != "grant-2" || event.ActorID != "user-1" {
		t.Errorf("the event is %+v, want the tenant, the grant, and the subject", event)
	}
	if !strings.Contains(event.Metadata, "client-1") {
		t.Errorf("the metadata is %q, want the client id", event.Metadata)
	}
}

// TestStorageManager_RevokedGrantAuditFails covers a failed audit write. A
// revocation nobody can audit is not allowed to stand, so the save fails with
// the error and the transaction rolls back.
func TestStorageManager_RevokedGrantAuditFails(t *testing.T) {
	writeFailed := errors.New("the audit write failed")
	recorder := audit.NewRecorder(func(context.Context, audit.Event) error {
		return writeFailed
	}, logger.New())
	manager := NewStorageManager("tenant-1", newMemoryStore().funcs(), recorder, logger.New())

	revoked := &goidc.Grant{ID: "grant-1", ClientID: "client-1", Subject: "user-1", RevokedAt: 1755300000}
	if err := manager.SaveGrant(context.Background(), revoked); !errors.Is(err, writeFailed) {
		t.Fatalf("save gives %v, want the audit write error", err)
	}
}

// TestStorageManager_Grant covers the three reads the token endpoint makes: by
// grant id, by authorization code, and by refresh token.
func TestStorageManager_Grant(t *testing.T) {
	store := newMemoryStore()
	manager := NewStorageManager("tenant-1", store.funcs(), nil, logger.New())
	ctx := context.Background()

	saved := &goidc.Grant{ID: "grant-1", ClientID: "client-1", AuthCode: "a-code", RefreshToken: "a-refresh-token"}
	if err := manager.SaveGrant(ctx, saved); err != nil {
		t.Fatalf("save grant: %v", err)
	}

	reads := map[string]func() (*goidc.Grant, error){
		"by id":            func() (*goidc.Grant, error) { return manager.Grant(ctx, "grant-1") },
		"by auth code":     func() (*goidc.Grant, error) { return manager.GrantByAuthCode(ctx, "a-code") },
		"by refresh token": func() (*goidc.Grant, error) { return manager.GrantByRefreshToken(ctx, "a-refresh-token") },
	}
	for name, read := range reads {
		grant, err := read()
		if err != nil {
			t.Fatalf("read grant %s: %v", name, err)
		}
		if grant.ID != saved.ID {
			t.Errorf("read grant %s gives id %q, want %q", name, grant.ID, saved.ID)
		}
	}

	for _, tenantID := range store.tenants {
		if tenantID != "tenant-1" {
			t.Fatalf("the store received tenant %q, want %q", tenantID, "tenant-1")
		}
	}
}

// TestStorageManager_Session covers the round trip the authorization endpoint
// makes while the person authenticates.
func TestStorageManager_Session(t *testing.T) {
	store := newMemoryStore()
	manager := NewStorageManager("tenant-1", store.funcs(), nil, logger.New())
	ctx := context.Background()

	if err := manager.SaveSession(ctx, &goidc.AuthnSession{ID: "session-1", ClientID: "client-1"}); err != nil {
		t.Fatalf("save session: %v", err)
	}
	session, err := manager.Session(ctx, "session-1")
	if err != nil {
		t.Fatalf("read session: %v", err)
	}
	if session.ClientID != "client-1" {
		t.Errorf("session client is %q, want %q", session.ClientID, "client-1")
	}
}

// TestStorageManager_NotFound covers every miss. The engine reads
// goidc.ErrNotFound and answers invalid_grant, so each domain sentinel maps.
func TestStorageManager_NotFound(t *testing.T) {
	manager := NewStorageManager("tenant-1", newMemoryStore().funcs(), nil, logger.New())
	ctx := context.Background()

	reads := map[string]func() error{
		"grant by id": func() error { _, err := manager.Grant(ctx, "nobody"); return err },
		"grant by auth code": func() error {
			_, err := manager.GrantByAuthCode(ctx, "no-such-code")
			return err
		},
		"grant by refresh token": func() error {
			_, err := manager.GrantByRefreshToken(ctx, "no-such-token")
			return err
		},
		"session by id": func() error { _, err := manager.Session(ctx, "nobody"); return err },
	}
	for name, read := range reads {
		if err := read(); !errors.Is(err, goidc.ErrNotFound) {
			t.Errorf("read %s gives %v, want goidc.ErrNotFound", name, err)
		}
	}
}

// TestClientManager_Client covers the read the protocol engine makes on every
// request: the manager binds the tenant, so the engine names the client alone.
func TestClientManager_Client(t *testing.T) {
	var seen string
	client, err := clientManager(t, "tenant-1", &seen).Client(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("read client: %v", err)
	}
	if client.ID != "client-1" {
		t.Errorf("client id is %q, want %q", client.ID, "client-1")
	}
	if seen != "tenant-1" {
		t.Errorf("the finder received tenant %q, want %q", seen, "tenant-1")
	}
}

// TestClientManager_ClientNotFound covers an unknown client id. The engine reads
// goidc.ErrNotFound and answers invalid_client, so the domain error must map.
func TestClientManager_ClientNotFound(t *testing.T) {
	_, err := clientManager(t, "tenant-1", nil).Client(context.Background(), "nobody")
	if !errors.Is(err, goidc.ErrNotFound) {
		t.Fatalf("error is %v, want goidc.ErrNotFound", err)
	}
}

// TestClientManager_RegistrationRefused covers dynamic client registration,
// which is out of scope. Every write and every initial token fails, so no
// request can add a client.
func TestClientManager_RegistrationRefused(t *testing.T) {
	manager := clientManager(t, "tenant-1", nil)

	if err := manager.SaveClient(context.Background(), &goidc.Client{ID: "new"}); !errors.Is(err, ErrRegistrationDisabled) {
		t.Errorf("SaveClient gives %v, want ErrRegistrationDisabled", err)
	}
	if err := manager.DeleteClient(context.Background(), "client-1"); !errors.Is(err, ErrRegistrationDisabled) {
		t.Errorf("DeleteClient gives %v, want ErrRegistrationDisabled", err)
	}
	if err := RefuseRegistration(context.Background(), "an-initial-token"); !errors.Is(err, ErrRegistrationDisabled) {
		t.Errorf("RefuseRegistration gives %v, want ErrRegistrationDisabled", err)
	}
}
