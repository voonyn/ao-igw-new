package oidc

import (
	"context"
	"net/http"
	"sync"
	"time"

	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// providerTTL is how long a built provider serves before the registry reads the
// tenant's configuration again. A configuration change goes live within it on
// every instance.
const providerTTL = 5 * time.Minute

// cached is one tenant's provider and the moment it stops serving.
type cached struct {
	handler http.Handler
	expires time.Time
}

// Registry holds the built provider of each tenant. The build reads several
// rows, so it runs once per tenant per providerTTL and not once per request.
//
// The cache is a read-through copy of the database, never a source of truth. An
// instance that loses it rebuilds from the same rows.
//
// One lock covers every tenant, and it is held while a build reads the
// database. A build runs once per tenant per providerTTL, so the wait is rare,
// and holding the lock collapses a burst of first requests into one build. Give
// each tenant its own lock if a build ever grows slow enough to matter.
type Registry struct {
	build Builder
	log   logger.Logger
	now   func() time.Time

	mu      sync.Mutex
	entries map[string]cached
}

func NewRegistry(build Builder, log logger.Logger) *Registry {
	return &Registry{
		build:   build,
		log:     log,
		now:     time.Now,
		entries: map[string]cached{},
	}
}

// Handler returns the provider of one tenant. It builds the provider on the
// first request and on the first request after providerTTL. A failed build
// never enters the cache, so a corrected row serves the next request.
func (r *Registry) Handler(ctx context.Context, tenantID string, cfg aooidc.ProviderConfig) (http.Handler, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, found := r.entries[tenantID]; found && r.now().Before(entry.expires) {
		return entry.handler, nil
	}

	r.log.Debug("cache miss, build the provider",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))
	handler, err := r.build(ctx, tenantID, cfg)
	if err != nil {
		return nil, err
	}

	r.entries[tenantID] = cached{handler: handler, expires: r.now().Add(providerTTL)}
	r.log.Debug("cached the provider",
		logger.String("tenant_id", tenantID),
		logger.String("issuer", cfg.Issuer),
		logger.RequestID(ctx))
	return handler, nil
}
