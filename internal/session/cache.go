package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alphaomega/identitygateway/internal/platform/cache"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// sessionKey names one login session in Redis. The tenant id is part of the
// key, so a digest of one tenant never reads the session of another tenant.
func sessionKey(tenantID, tokenHash string) string {
	return fmt.Sprintf("login_session:%s:%s", tenantID, tokenHash)
}

// CachingSaver writes one login session through to the database, then to
// Redis. The database is the source of truth, so a refused write never reaches
// the cache.
//
// prevTokenHash is the digest the session answered to before this save. The
// password step rotates the token, and the row then stops matching the old
// digest. The cache entry of that digest is dropped here, so a rotated token
// dies at once instead of living out its TTL.
//
// A Redis failure is logged and swallowed. The session is in the database by
// then, so the next read finds it and refills the cache.
func CachingSaver(rdb cache.Client, save Saver, cipher *aocrypto.Cipher, log logger.Logger) Saver {
	return func(ctx context.Context, live LoginSession, tokenHash, prevTokenHash string) error {
		if err := save(ctx, live, tokenHash, prevTokenHash); err != nil {
			return err
		}

		if prevTokenHash != "" && prevTokenHash != tokenHash {
			if err := rdb.Del(ctx, sessionKey(live.TenantID, prevTokenHash)); err != nil {
				log.Warn("drop the rotated login session from the cache",
					logger.String("tenant_id", live.TenantID),
					logger.String("session_id", live.ID),
					logger.Err(err))
			}
		}

		ttl := time.Until(live.ExpiresAt)
		if ttl <= 0 {
			return nil
		}

		data, err := aocrypto.SealJSON(cipher, live)
		if err != nil {
			log.Warn("seal the login session for the cache",
				logger.String("tenant_id", live.TenantID),
				logger.String("session_id", live.ID),
				logger.Err(err))
			return nil
		}
		if err := rdb.Set(ctx, sessionKey(live.TenantID, tokenHash), string(data), ttl); err != nil {
			log.Warn("cache the login session",
				logger.String("tenant_id", live.TenantID),
				logger.String("session_id", live.ID),
				logger.Err(err))
		}
		return nil
	}
}

// RowTerminator ends one login session in the database and answers with the
// token digest the row held. The cache is keyed by that digest, so the caller
// needs it to drop the entry.
type RowTerminator func(ctx context.Context, tenantID, sessionID string) (string, error)

// CachingTerminator ends one login session in the database, then drops the
// cached copy. The database is the source of truth, so a refused write leaves
// the cache alone.
//
// A Redis failure is logged and swallowed. The row is terminated by then, so
// the entry outlives the session by its TTL at most, and no read of it can
// resolve once it expires.
func CachingTerminator(rdb cache.Client, terminate RowTerminator, log logger.Logger) Terminator {
	return func(ctx context.Context, tenantID, sessionID string) error {
		tokenHash, err := terminate(ctx, tenantID, sessionID)
		if err != nil {
			return err
		}
		if tokenHash == "" {
			return nil
		}

		if err := rdb.Del(ctx, sessionKey(tenantID, tokenHash)); err != nil {
			log.Warn("drop the terminated login session from the cache",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", sessionID),
				logger.Err(err))
		}
		return nil
	}
}

// CachedFinder reads one login session from Redis, and falls back to the
// database. A miss refills the cache, so the next read of the same token is one
// round trip.
//
// The cached value is the same sealed blob the row holds, so no plaintext
// session reaches Redis.
//
// The TTL of the entry expires it, so an expired session is a miss here as well
// as in the database.
func CachedFinder(rdb cache.Client, find Finder, cipher *aocrypto.Cipher, log logger.Logger) Finder {
	return func(ctx context.Context, tenantID, tokenHash string) (LoginSession, error) {
		key := sessionKey(tenantID, tokenHash)

		data, err := rdb.Get(ctx, key)
		switch {
		case err == nil:
			var live LoginSession
			if err := aocrypto.OpenJSON(cipher, []byte(data), &live); err != nil {
				log.Warn("open the cached login session",
					logger.String("tenant_id", tenantID), logger.Err(err))
				break
			}
			log.Debug("read login session from the cache",
				logger.String("tenant_id", tenantID), logger.String("session_id", live.ID))
			return live, nil
		case errors.Is(err, cache.ErrCacheMiss):
		default:
			log.Warn("read the login session cache",
				logger.String("tenant_id", tenantID), logger.Err(err))
		}

		live, err := find(ctx, tenantID, tokenHash)
		if err != nil {
			return LoginSession{}, err
		}

		ttl := time.Until(live.ExpiresAt)
		if ttl <= 0 {
			return live, nil
		}
		sealed, err := aocrypto.SealJSON(cipher, live)
		if err != nil {
			log.Warn("seal the login session for the cache",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", live.ID),
				logger.Err(err))
			return live, nil
		}
		if err := rdb.Set(ctx, key, string(sealed), ttl); err != nil {
			log.Warn("refill the login session cache",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", live.ID),
				logger.Err(err))
		}
		return live, nil
	}
}

// CachingRevoker hard deletes one login session and then drops its cached copy.
// The database is the source of truth, so a refused delete leaves the cache
// alone.
//
// A Redis failure is logged and swallowed. The row is gone by then, so the entry
// outlives the session by its TTL at most, and no read of it can resolve once
// the database says the session does not exist.
//
// The delete runs inside the caller's transaction, and the cache entry is
// dropped as soon as it returns. A transaction that rolls back afterwards
// therefore leaves the row alive with no cached copy, which costs one read and
// refills the cache. The other order would leave a live cache entry for a
// session the database deleted, and that entry would still sign requests.
func CachingRevoker(rdb cache.Client, revoke SessionRevoker, log logger.Logger) SessionRevoker {
	return func(ctx context.Context, tenantID, ownerID, sessionID string) (Revoked, error) {
		revoked, err := revoke(ctx, tenantID, ownerID, sessionID)
		if err != nil {
			return Revoked{}, err
		}
		dropCached(ctx, rdb, tenantID, []Revoked{revoked}, log)
		return revoked, nil
	}
}

// CachingUserRevoker hard deletes every login session of one person and then
// drops each cached copy.
func CachingUserRevoker(rdb cache.Client, revoke UserSessionRevoker, log logger.Logger) UserSessionRevoker {
	return func(ctx context.Context, tenantID, userID, exceptID string) ([]Revoked, error) {
		revoked, err := revoke(ctx, tenantID, userID, exceptID)
		if err != nil {
			return nil, err
		}
		dropCached(ctx, rdb, tenantID, revoked, log)
		return revoked, nil
	}
}

// dropCached removes the cached copy of each revoked session. The cache is keyed
// by the token digest, which the revoked row is the only place to read it from.
func dropCached(ctx context.Context, rdb cache.Client, tenantID string, revoked []Revoked, log logger.Logger) {
	for _, row := range revoked {
		if row.TokenHash == "" {
			continue
		}
		if err := rdb.Del(ctx, sessionKey(tenantID, row.TokenHash)); err != nil {
			log.Warn("drop the revoked login session from the cache",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", row.SessionID),
				logger.Err(err))
		}
	}
}
