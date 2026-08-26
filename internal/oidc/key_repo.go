// Package oidc holds the OpenID Connect domain: the signing keys, the provider
// configuration, the clients, and the protocol state stores. It never imports
// goidc's server side — only the shared types in pkg/goidc — so the protocol
// engine stays behind internal/api/oidc.
package oidc

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// Key states, as stored in oidc_keys.state.
const (
	KeyStateActive   = 1 // signs new tokens and is published
	KeyStateInactive = 2 // published so old tokens still verify, never signs
	KeyStateRetired  = 3 // neither signs nor is published
)

// keyUseSig is oidc_keys.key_use for a signature key. Encryption keys (2) are
// out of scope.
const keyUseSig = 1

// KeyRepository reads the signing keys of one tenant.
type KeyRepository struct {
	db  *bun.DB
	log logger.Logger
}

func NewKeyRepository(bdb *bun.DB, log logger.Logger) *KeyRepository {
	return &KeyRepository{db: bdb, log: log}
}

// ListSigningKeys returns the active and the inactive signature keys of one
// tenant, active first. A retired row never comes back.
func (r *KeyRepository) ListSigningKeys(ctx context.Context, tenantID string) ([]Key, error) {
	r.log.Debug("list signing keys", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var keys []Key
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&keys).
		Where("tenant_id = ?", tenantID).
		Where("key_use = ?", keyUseSig).
		Where("state IN (?)", bun.In([]int{KeyStateActive, KeyStateInactive})).
		Order("state ASC", "created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list signing keys of tenant %s: %w", tenantID, err)
	}

	r.log.Debug("listed signing keys",
		logger.String("tenant_id", tenantID), logger.Int("count", len(keys)), logger.RequestID(ctx))
	return keys, nil
}

// ListKeys reads every key of one tenant, active first and retired last.
//
// It differs from ListSigningKeys on purpose. That read answers what the JWKS
// endpoint publishes, and this one answers what the tenant holds: the console
// renders a retired key, because the operator needs to see that a rotation
// happened and when.
//
// The private half is projected like every other column, and the view drops it.
// No key material reaches an answer.
func (r *KeyRepository) ListKeys(ctx context.Context, tenantID string) ([]Key, error) {
	r.log.Debug("list every key", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	var keys []Key
	err := db.Conn(ctx, r.db).NewSelect().
		Model(&keys).
		Where("tenant_id = ?", tenantID).
		Order("state ASC", "created_at DESC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the keys of tenant %s: %w", tenantID, err)
	}
	return keys, nil
}
