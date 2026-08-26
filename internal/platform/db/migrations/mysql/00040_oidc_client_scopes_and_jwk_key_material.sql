-- +goose Up
-- Two schema changes that were first written into migrations 00005 and 00010
-- after both had run. A database that applied the originals keeps the original
-- schema, so the changes are repeated here where goose can apply them.

-- ── application_oidc_configs.scope_ids -> scopes ──────────────────────────
-- The column never held an id. It holds the scope names the client can request,
-- space separated, and it is the allow-list goidc validates an authorization
-- request against. RENAME COLUMN keeps the data and the column position.
ALTER TABLE application_oidc_configs
    RENAME COLUMN scope_ids TO scopes;

-- ── oidc_keys: DER material becomes JWK JSON ──────────────────────────────
-- internal/platform/crypto.Generate produces both halves as JWK JSON
-- (RFC 7517 / RFC 7518), so a row reaches a goidc.JSONWebKey without decoding.
-- The old rows hold PKIX and PKCS8 DER, which the current code cannot read and
-- which no statement can convert. A row written after the format change is
-- already JSON and stays.
--
-- A key is a row that stays readable after it stops working, so it is retired
-- with its own column and never deleted. state 3 takes the row out of the JWKS
-- and out of signer selection, and the console still renders it, so the
-- operator sees that the key existed. public_key becomes an empty JWK, because
-- MODIFY converts the column only when every row holds valid JSON, and the DER
-- it held has no reader left.
--
-- A deployment that retires every key here has no signing key left, and only
-- `bootstrap` generates one. Re-bootstrap that deployment.
UPDATE oidc_keys
   SET state = 3, public_key = '{}'
 WHERE NOT JSON_VALID(public_key);

ALTER TABLE oidc_keys
    MODIFY public_key JSON NOT NULL COMMENT 'public JWK — served via JWKS';

-- key_config held the JWK attributes that the DER material did not carry. The
-- JWK holds all of them, so the column has no reader left.
ALTER TABLE oidc_keys
    DROP COLUMN key_config;

-- oidc_keys carried deleted_at, but a soft delete does not fit a key. A key
-- stays readable after it stops working, so it is marked with its own column,
-- and state already marks it: 1=active 2=inactive 3=retired. The column had no
-- writer, and bun added `deleted_at IS NULL` to every JWKS read for nothing.
ALTER TABLE oidc_keys
    DROP COLUMN deleted_at;

-- +goose Down
SET FOREIGN_KEY_CHECKS = 0;

ALTER TABLE oidc_keys
    ADD COLUMN deleted_at DATETIME(6) NULL;

ALTER TABLE oidc_keys
    ADD COLUMN key_config JSON NULL DEFAULT NULL AFTER private_key;

-- The rows hold JWK JSON. The down migration restores the column type only, and
-- it cannot restore the DER material that the up migration replaced.
ALTER TABLE oidc_keys
    MODIFY public_key BLOB NOT NULL;

ALTER TABLE application_oidc_configs
    RENAME COLUMN scopes TO scope_ids;

SET FOREIGN_KEY_CHECKS = 1;
