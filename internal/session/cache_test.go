package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/platform/cache"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// fakeCache is Redis as a map. It records what it was asked to do, and it can
// be told to fail, so a test can cover a cache that is down.
type fakeCache struct {
	values map[string]string
	ttls   map[string]time.Duration
	gets   []string
	dels   []string
	fail   error
}

func newFakeCache() *fakeCache {
	return &fakeCache{values: map[string]string{}, ttls: map[string]time.Duration{}}
}

func (f *fakeCache) Get(_ context.Context, key string) (string, error) {
	f.gets = append(f.gets, key)
	if f.fail != nil {
		return "", f.fail
	}
	value, ok := f.values[key]
	if !ok {
		return "", cache.ErrCacheMiss
	}
	return value, nil
}

func (f *fakeCache) Set(_ context.Context, key, value string, ttl time.Duration) error {
	if f.fail != nil {
		return f.fail
	}
	f.values[key] = value
	f.ttls[key] = ttl
	return nil
}

func (f *fakeCache) Del(_ context.Context, keys ...string) error {
	f.dels = append(f.dels, keys...)
	if f.fail != nil {
		return f.fail
	}
	for _, key := range keys {
		delete(f.values, key)
		delete(f.ttls, key)
	}
	return nil
}

func (f *fakeCache) SetNX(context.Context, string, string, time.Duration) (bool, error) {
	return false, nil
}

func (f *fakeCache) AllowInWindow(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}
func (f *fakeCache) ReleaseInWindow(context.Context, string) error { return nil }
func (f *fakeCache) Ping(context.Context) error                    { return nil }
func (f *fakeCache) Close() error                                  { return nil }

// liveSession is a session that still has hours to run, so the TTL of a cache
// write is a positive number the test can assert on.
func liveSession() LoginSession {
	live := testSession()
	live.ExpiresAt = time.Now().UTC().Add(time.Hour)
	return live
}

// prefill puts one sealed session in the cache, the way a write-through save
// left it there.
func prefill(t *testing.T, c *fakeCache, cipher *aocrypto.Cipher, live LoginSession, tokenHash string) {
	t.Helper()

	data, err := aocrypto.SealJSON(cipher, live)
	if err != nil {
		t.Fatalf("seal login session: %v", err)
	}
	c.values[sessionKey(live.TenantID, tokenHash)] = string(data)
}

// TestCachedFinder_ReadsCache covers the read path of the stateless rule: the
// answer comes from Redis, and the database is not touched.
func TestCachedFinder_ReadsCache(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	live := liveSession()
	prefill(t, rdb, cipher, live, "the-digest")

	log, _ := logger.NewObserved()
	find := CachedFinder(rdb, func(context.Context, string, string) (LoginSession, error) {
		t.Fatal("the database was read on a cache hit")
		return LoginSession{}, nil
	}, cipher, log)

	got, err := find(context.Background(), "tenant-1", "the-digest")
	if err != nil {
		t.Fatalf("read login session: %v", err)
	}
	if got.ID != live.ID || got.UserID != live.UserID {
		t.Errorf("cache gave %+v, want the session it holds", got)
	}
}

// TestCachedFinder_RefillsOnMiss covers a miss: the database answers, and the
// answer is put in the cache with a TTL.
func TestCachedFinder_RefillsOnMiss(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	live := liveSession()

	log, _ := logger.NewObserved()
	find := CachedFinder(rdb, func(context.Context, string, string) (LoginSession, error) {
		return live, nil
	}, cipher, log)

	got, err := find(context.Background(), "tenant-1", "the-digest")
	if err != nil {
		t.Fatalf("read login session: %v", err)
	}
	if got.ID != live.ID {
		t.Errorf("database gave %+v, want the live session", got)
	}

	key := sessionKey("tenant-1", "the-digest")
	if _, ok := rdb.values[key]; !ok {
		t.Fatal("the miss did not refill the cache")
	}
	if ttl := rdb.ttls[key]; ttl <= 0 || ttl > time.Hour {
		t.Errorf("refill TTL is %s, want a positive value up to the session lifetime", ttl)
	}
}

// TestCachedFinder_TenantIsolation covers the key: one tenant never reads the
// session of another tenant, even under the same token digest.
func TestCachedFinder_TenantIsolation(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	other := liveSession()
	other.TenantID = "tenant-2"
	other.ID = "session-of-another-tenant"
	prefill(t, rdb, cipher, other, "the-digest")

	log, _ := logger.NewObserved()
	find := CachedFinder(rdb, func(context.Context, string, string) (LoginSession, error) {
		return LoginSession{}, ErrLoginSessionNotFound
	}, cipher, log)

	if _, err := find(context.Background(), "tenant-1", "the-digest"); !errors.Is(err, ErrLoginSessionNotFound) {
		t.Errorf("tenant-1 got %v, want %v", err, ErrLoginSessionNotFound)
	}
}

// TestCachedFinder_CacheDown covers a Redis that fails. The database is the
// source of truth, so the request is still answered.
func TestCachedFinder_CacheDown(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	rdb.fail = errors.New("redis is down")
	live := liveSession()

	log, _ := logger.NewObserved()
	find := CachedFinder(rdb, func(context.Context, string, string) (LoginSession, error) {
		return live, nil
	}, cipher, log)

	got, err := find(context.Background(), "tenant-1", "the-digest")
	if err != nil {
		t.Fatalf("read login session: %v", err)
	}
	if got.ID != live.ID {
		t.Errorf("database gave %+v, want the live session", got)
	}
}

// TestCachingSaver_WritesThrough covers the write path of the stateless rule:
// the database first, then the cache with a TTL.
func TestCachingSaver_WritesThrough(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	live := liveSession()

	saved := false
	log, _ := logger.NewObserved()
	save := CachingSaver(rdb, func(context.Context, LoginSession, string, string) error {
		saved = true
		return nil
	}, cipher, log)

	if err := save(context.Background(), live, "the-digest", ""); err != nil {
		t.Fatalf("save login session: %v", err)
	}
	if !saved {
		t.Fatal("the database was not written")
	}

	key := sessionKey("tenant-1", "the-digest")
	if _, ok := rdb.values[key]; !ok {
		t.Fatal("the save did not write the cache")
	}
	if ttl := rdb.ttls[key]; ttl <= 0 || ttl > time.Hour {
		t.Errorf("cache TTL is %s, want a positive value up to the session lifetime", ttl)
	}
}

// TestCachingSaver_EvictsRotatedToken covers the token rotation of the password
// step. The old digest no longer matches the row, so its cache entry must go.
// Without this, a dead token keeps answering until the TTL runs out.
func TestCachingSaver_EvictsRotatedToken(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	live := liveSession()
	prefill(t, rdb, cipher, live, "the-old-digest")

	log, _ := logger.NewObserved()
	save := CachingSaver(rdb, func(context.Context, LoginSession, string, string) error {
		return nil
	}, cipher, log)

	if err := save(context.Background(), live, "the-new-digest", "the-old-digest"); err != nil {
		t.Fatalf("save login session: %v", err)
	}

	if _, ok := rdb.values[sessionKey("tenant-1", "the-old-digest")]; ok {
		t.Error("the rotated token still answers from the cache")
	}
	if _, ok := rdb.values[sessionKey("tenant-1", "the-new-digest")]; !ok {
		t.Error("the new token was not cached")
	}
}

// TestCachingSaver_DatabaseFailure covers a failed database write. The cache
// must not hold a session the database never took.
func TestCachingSaver_DatabaseFailure(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	broken := errors.New("the database refused the write")

	log, _ := logger.NewObserved()
	save := CachingSaver(rdb, func(context.Context, LoginSession, string, string) error {
		return broken
	}, cipher, log)

	if err := save(context.Background(), liveSession(), "the-digest", ""); !errors.Is(err, broken) {
		t.Fatalf("save gave %v, want %v", err, broken)
	}
	if len(rdb.values) != 0 {
		t.Error("the cache holds a session the database refused")
	}
}

// TestCachingTerminator_DropsTheCachedSession covers the sign-out path of the
// stateless rule: the row is terminated in the database, and the cached copy is
// dropped, so the token dies at once instead of living out its TTL.
func TestCachingTerminator_DropsTheCachedSession(t *testing.T) {
	cipher := testCipher(t)
	rdb := newFakeCache()
	live := liveSession()
	prefill(t, rdb, cipher, live, "the-digest")

	log, _ := logger.NewObserved()
	terminate := CachingTerminator(rdb, func(_ context.Context, tenantID, sessionID string) (string, error) {
		if tenantID != live.TenantID || sessionID != live.ID {
			t.Fatalf("terminated tenant %q session %q, want %q and %q",
				tenantID, sessionID, live.TenantID, live.ID)
		}
		return "the-digest", nil
	}, log)

	if err := terminate(context.Background(), live.TenantID, live.ID); err != nil {
		t.Fatalf("terminate login session: %v", err)
	}

	key := sessionKey(live.TenantID, "the-digest")
	if _, held := rdb.values[key]; held {
		t.Error("the terminated session is still cached")
	}
	if len(rdb.dels) != 1 || rdb.dels[0] != key {
		t.Errorf("dropped keys are %v, want [%s]", rdb.dels, key)
	}
}
