-- +goose Up
-- harden-core V-2 (tickets 20/21) — make a replayed refresh token recognisable.
--
-- Rotation reuses the grant id and replaces oidc_grants.refresh_token_hash IN
-- PLACE, so the superseded digest is destroyed at the instant of rotation. A
-- replayed token then resolves to nothing and the request fails — but the
-- gateway cannot tell theft from a client bug, does not revoke the family, and
-- the attacker's successor token stays valid. Reuse is not merely unpunished,
-- it is unobservable.
--
-- SHAPE. Two candidates were on the table: retain superseded digests against
-- the grant, or version the grant so a stale version identifies itself.
-- Digests win, for a reason that is not aesthetic: a refresh token is opaque
-- and the gateway only ever stores its SHA-256, so a version number would have
-- to be carried BY THE TOKEN to be checkable, which means reissuing every
-- token in circulation before detection starts working. Retaining digests
-- detects a replay of a token issued before this migration ran, on the same
-- indexed equality the live lookup already uses, and needs no change to what a
-- token is.
--
-- RETENTION. A superseded digest is worth keeping exactly as long as the token
-- it belongs to could still be presented — its own expiry, copied from the
-- grant at rotation time. Migration 00037 gives refresh tokens a 30-day
-- shipped default for precisely this reason: with the previous NULL lifetime
-- the provider stamped no expiry at all, and "until it could no longer be
-- presented" would have meant forever. A row whose grant had no expiry falls
-- back to that same 30-day bound rather than living indefinitely.
--
-- AGEING OUT, and by whom. There is no cron and no drainer: the rotation that
-- CREATES a row also sweeps a bounded batch of this tenant's expired ones
-- (oidcStorageService.SaveGrant). Deletion is therefore driven by the same
-- traffic as insertion and cannot fall behind it, and a tenant that stops
-- rotating stops accumulating. Family revocation additionally drops the whole
-- grant's history at once, since a revoked grant has nothing left to detect.
CREATE TABLE oidc_superseded_refresh_tokens (
    tenant_id     CHAR(36)     NOT NULL,
    token_hash    CHAR(64)     NOT NULL,  /* sha256 hex of the superseded refresh token */
    grant_id      CHAR(36)     NOT NULL,
    superseded_at DATETIME(3)  NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at    DATETIME(3)  NOT NULL,  /* when the superseded token itself would have died */

    PRIMARY KEY (tenant_id, token_hash),
    KEY idx_superseded_refresh_grant (tenant_id, grant_id),
    KEY idx_superseded_refresh_expiry (tenant_id, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- +goose Down
DROP TABLE oidc_superseded_refresh_tokens;
