package cache

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/rueidis"
)

type rueidisClient struct {
	r rueidis.Client
	// seq disambiguates two sliding-window hits that land on the same microsecond.
	seq atomic.Uint64
}

// New returns a Client backed by rueidis, connected to addr.
// password may be empty for unauthenticated servers. tlsConfig enables TLS for
// the connection when non-nil; pass nil for a plaintext connection.
func New(addr, password string, tlsConfig *tls.Config) (Client, error) {
	r, err := rueidis.NewClient(rueidis.ClientOption{
		InitAddress:  []string{addr},
		Password:     password,
		DisableCache: true,
		TLSConfig:    tlsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("cache: connect to %s: %w", addr, err)
	}
	return &rueidisClient{r: r}, nil
}

func (c *rueidisClient) Get(ctx context.Context, key string) (string, error) {
	resp := c.r.Do(ctx, c.r.B().Get().Key(key).Build())
	val, err := resp.ToString()
	if err != nil {
		if rueidis.IsRedisNil(err) {
			return "", ErrCacheMiss
		}
		return "", fmt.Errorf("cache: get %q: %w", key, err)
	}
	return val, nil
}

func (c *rueidisClient) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	var cmd rueidis.Completed
	if ttl > 0 {
		cmd = c.r.B().Set().Key(key).Value(value).Ex(ttl).Build()
	} else {
		cmd = c.r.B().Set().Key(key).Value(value).Build()
	}
	if err := c.r.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("cache: set %q: %w", key, err)
	}
	return nil
}

func (c *rueidisClient) SetNX(ctx context.Context, key string, value string, ttl time.Duration) (bool, error) {
	var cmd rueidis.Completed
	if ttl > 0 {
		cmd = c.r.B().Set().Key(key).Value(value).Nx().Ex(ttl).Build()
	} else {
		cmd = c.r.B().Set().Key(key).Value(value).Nx().Build()
	}
	// SET ... NX replies with a Redis nil (not OK) when the key already exists;
	// rueidis surfaces that as a Redis-nil error. Treat it as "not stored" rather
	// than a transport failure — the key being present is the expected outcome of
	// a lost race, not an error.
	if err := c.r.Do(ctx, cmd).Error(); err != nil {
		if rueidis.IsRedisNil(err) {
			return false, nil
		}
		return false, fmt.Errorf("cache: setnx %q: %w", key, err)
	}
	return true, nil
}

// slidingWindowScript is the sliding-window-log limiter, evaluated server-side so
// the whole count-and-test is one atomic round trip.
//
// KEYS[1] the window key · ARGV: now (µs), window (µs), limit, member.
// Trim what fell out of the trailing window, count what is left, and admit only
// if that count is below the limit. A refused hit is deliberately NOT recorded:
// a flood must not extend its own ban, and the set stays bounded by limit. The
// key's TTL is refreshed on every evaluation, so an idle key expires on its own.
var slidingWindowScript = rueidis.NewLuaScript(`
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local ttl    = math.ceil(window / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local n = redis.call('ZCARD', KEYS[1])
if n >= limit then
  redis.call('PEXPIRE', KEYS[1], ttl)
  return 0
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('PEXPIRE', KEYS[1], ttl)
return 1
`)

func (c *rueidisClient) AllowInWindow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 || window <= 0 {
		return false, fmt.Errorf("cache: allow in window %q: limit and window must be positive", key)
	}
	now := time.Now().UnixMicro()
	// The member only has to be unique within the window; two hits landing on the
	// same microsecond would otherwise collapse into one sorted-set entry and
	// under-count. A counter suffix is enough and costs no syscall.
	member := strconv.FormatInt(now, 10) + "-" + strconv.FormatUint(c.seq.Add(1), 36)

	n, err := slidingWindowScript.Exec(ctx, c.r, []string{key}, []string{
		strconv.FormatInt(now, 10),
		strconv.FormatInt(window.Microseconds(), 10),
		strconv.Itoa(limit),
		member,
	}).AsInt64()
	if err != nil {
		return false, fmt.Errorf("cache: allow in window %q: %w", key, err)
	}
	return n == 1, nil
}

// ReleaseInWindow drops the newest hit of the window, which is one ZREMRANGEBYRANK
// on the sorted set AllowInWindow writes. A key that expired or that holds no hit
// removes nothing and answers no error.
func (c *rueidisClient) ReleaseInWindow(ctx context.Context, key string) error {
	cmd := c.r.B().Zremrangebyrank().Key(key).Start(-1).Stop(-1).Build()
	if err := c.r.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("cache: release in window %q: %w", key, err)
	}
	return nil
}

func (c *rueidisClient) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	cmd := c.r.B().Del().Key(keys...).Build()
	if err := c.r.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("cache: del: %w", err)
	}
	return nil
}

func (c *rueidisClient) Ping(ctx context.Context) error {
	if err := c.r.Do(ctx, c.r.B().Ping().Build()).Error(); err != nil {
		return fmt.Errorf("cache: ping: %w", err)
	}
	return nil
}

func (c *rueidisClient) Close() error {
	c.r.Close()
	return nil
}
