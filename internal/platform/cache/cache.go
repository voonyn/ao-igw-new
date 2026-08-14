package cache

import (
	"context"
	"errors"
	"time"
)

// ErrCacheMiss is returned by Get when the key does not exist.
// Callers check with errors.Is(err, cache.ErrCacheMiss).
var ErrCacheMiss = errors.New("cache: miss")

// Client is the caching interface injected across all layers.
// The underlying implementation is swappable without changing callers.
type Client interface {
	// Get returns the string value for key.
	// Returns ErrCacheMiss if the key does not exist.
	Get(ctx context.Context, key string) (string, error)

	// Set stores value under key with an optional TTL.
	// ttl == 0 means no expiry.
	Set(ctx context.Context, key string, value string, ttl time.Duration) error

	// SetNX atomically stores value under key with an optional TTL, but only if
	// key does not already exist (Redis SET NX). It reports whether the value
	// was stored: false means the key was already present, so the caller lost
	// the race. ttl == 0 means no expiry.
	//
	// Use it for one-shot markers — such as JTI replay protection — where the
	// existence check and the write must be a single atomic step.
	SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error)

	// AllowInWindow atomically records one hit against key and reports whether
	// the number of hits in the trailing window is within limit. It is the
	// narrowest primitive a sliding-window rate limiter needs: count-and-test in
	// ONE round trip, so concurrent callers cannot undercount their way past the
	// budget the way a Get-then-Set pair can, and no boundary exists for a burst
	// to straddle the way it can with a fixed window.
	//
	// A refused hit is NOT recorded, so a flood cannot extend its own ban and the
	// backing structure stays bounded by limit. Keys expire window after their
	// last recorded hit; no sweeping is required.
	//
	// Sorted-set mechanics stay inside the implementation — callers pass a key, a
	// limit and a window, and get a decision.
	AllowInWindow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)

	// Del removes one or more keys. Non-existent keys are silently ignored.
	Del(ctx context.Context, keys ...string) error

	// Ping verifies connectivity to the server. Used by readiness checks.
	Ping(ctx context.Context) error

	// Close releases the underlying connection pool.
	Close() error
}
