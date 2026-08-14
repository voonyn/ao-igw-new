-- +goose Up
-- harden-core ticket 19 — lower the shipped access-token lifetime default.
--
-- Access tokens are JWTs, deliberately not stored server-side, so nothing the
-- gateway does shortens the remaining TTL of one already in a relying party's
-- hands. After deactivation every renewal path is dead within the transaction
-- (tickets 08/09), which makes this column, exactly, the residual exposure
-- window: the distance between "revoked" and "actually unable to act".
--
-- 3600 -> 600. Ten minutes is the conventional choice for a bearer JWT with no
-- introspection requirement, and the reasoning is a straight trade: the window
-- shrinks 6x, and refresh-grant traffic rises by the same factor (a session
-- that made one refresh an hour makes six). Refreshes are one indexed lookup
-- plus one signed token, on the same path an active session already exercises,
-- so the cost being bought is proportional and cheap. Lower than five minutes
-- starts paying refresh latency on ordinary page loads for no further security
-- benefit — the remaining window is dominated by detection time, not TTL.
--
-- refresh_token_lifetime_secs gains a default in the same statement, and for a
-- related reason. NULL reads as "provider default", and the provider treats an
-- unset lifetime as no expiry at all: goidc stamps RefreshTokenExpiresAt = 0
-- and the grant lookup applies no expiry predicate, so a rotated refresh token
-- currently never expires (ticket 02's finding). That is what makes the
-- superseded-refresh-token memory tickets 20/21 introduce unbounded — its
-- retention is defined as "until the token it supersedes could no longer be
-- presented", which is never. 30 days bounds both.
--
-- NEITHER change touches an existing row. ALTER ... SET DEFAULT rewrites the
-- column default for future inserts only; retuning a live tenant is an
-- operator's decision, not a migration's.
ALTER TABLE oidc_provider_configs
    ALTER COLUMN access_token_lifetime_secs SET DEFAULT 600;

ALTER TABLE oidc_provider_configs
    ALTER COLUMN refresh_token_lifetime_secs SET DEFAULT 2592000;

-- +goose Down
ALTER TABLE oidc_provider_configs
    ALTER COLUMN access_token_lifetime_secs SET DEFAULT 3600;

ALTER TABLE oidc_provider_configs
    ALTER COLUMN refresh_token_lifetime_secs DROP DEFAULT;
