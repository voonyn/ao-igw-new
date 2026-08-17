package oidc

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	aooidc "alphaomega/identitygateway/internal/oidc"
	"alphaomega/identitygateway/internal/platform/logger"
)

// countingBuilder answers with one handler per tenant and counts every build,
// so the test observes the cache without a database.
func countingBuilder(builds map[string]int, err error) Builder {
	return func(_ context.Context, tenantID string, _ aooidc.ProviderConfig) (http.Handler, error) {
		builds[tenantID]++
		if err != nil {
			return nil, err
		}
		return http.NewServeMux(), nil
	}
}

// TestRegistry_CachesPerTenant covers the read path of every request. A tenant
// is built once and then answered from the cache, and two tenants never share
// a provider.
func TestRegistry_CachesPerTenant(t *testing.T) {
	builds := map[string]int{}
	reg := NewRegistry(countingBuilder(builds, nil), logger.New())
	ctx := context.Background()

	first, err := reg.Handler(ctx, "tenant-1", testConfig())
	if err != nil {
		t.Fatalf("read handler: %v", err)
	}
	again, err := reg.Handler(ctx, "tenant-1", testConfig())
	if err != nil {
		t.Fatalf("read handler again: %v", err)
	}
	if first != again {
		t.Error("the registry built a second handler for the same tenant")
	}
	if builds["tenant-1"] != 1 {
		t.Errorf("the registry built tenant-1 %d times, want 1", builds["tenant-1"])
	}

	other, err := reg.Handler(ctx, "tenant-2", testConfig())
	if err != nil {
		t.Fatalf("read handler of the other tenant: %v", err)
	}
	if other == first {
		t.Error("two tenants share one provider")
	}
}

// TestRegistry_RebuildsAfterTTL covers a configuration change. The cached
// provider expires after five minutes, so the next request reads the row again.
func TestRegistry_RebuildsAfterTTL(t *testing.T) {
	builds := map[string]int{}
	reg := NewRegistry(countingBuilder(builds, nil), logger.New())

	clock := time.Unix(1700000000, 0)
	reg.now = func() time.Time { return clock }
	ctx := context.Background()

	if _, err := reg.Handler(ctx, "tenant-1", testConfig()); err != nil {
		t.Fatalf("read handler: %v", err)
	}

	clock = clock.Add(providerTTL - time.Second)
	if _, err := reg.Handler(ctx, "tenant-1", testConfig()); err != nil {
		t.Fatalf("read handler inside the ttl: %v", err)
	}
	if builds["tenant-1"] != 1 {
		t.Errorf("the registry built tenant-1 %d times inside the ttl, want 1", builds["tenant-1"])
	}

	clock = clock.Add(2 * time.Second)
	if _, err := reg.Handler(ctx, "tenant-1", testConfig()); err != nil {
		t.Fatalf("read handler after the ttl: %v", err)
	}
	if builds["tenant-1"] != 2 {
		t.Errorf("the registry built tenant-1 %d times after the ttl, want 2", builds["tenant-1"])
	}
}

// TestRegistry_BuildError covers a tenant the build refuses, such as one that
// asks for an opaque access token. The failure reaches the caller and never
// enters the cache, so a fixed row serves on the next request.
func TestRegistry_BuildError(t *testing.T) {
	builds := map[string]int{}
	reg := NewRegistry(countingBuilder(builds, ErrOpaqueAccessToken), logger.New())
	ctx := context.Background()

	if _, err := reg.Handler(ctx, "tenant-1", testConfig()); !errors.Is(err, ErrOpaqueAccessToken) {
		t.Fatalf("read handler gives %v, want ErrOpaqueAccessToken", err)
	}
	if _, err := reg.Handler(ctx, "tenant-1", testConfig()); !errors.Is(err, ErrOpaqueAccessToken) {
		t.Fatalf("read handler again gives %v, want ErrOpaqueAccessToken", err)
	}
	if builds["tenant-1"] != 2 {
		t.Errorf("the registry built tenant-1 %d times, want 2: a failure must not be cached", builds["tenant-1"])
	}
}
