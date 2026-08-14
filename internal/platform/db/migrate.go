package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"alphaomega/identitygateway/internal/platform/logger"
	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"
)

// Migrations are embedded so `migrate up`/`status`/`down`/`reset` work from a
// single binary — no need to ship the migrations directory alongside it.
//
// File format is goose's annotated SQL:
//
//	-- +goose Up
//	CREATE TABLE ...;
//	-- +goose Down
//	DROP TABLE ...;
//
// Create new ones with: make migration name=add_roles
//
// Migrations are grouped by SQL dialect (migrations/mysql, migrations/postgres,
// ...) so a second database can be added without touching MySQL's files.
//
//go:embed migrations/*/*.sql
var migrationFS embed.FS

// dialectDir is the subdirectory of migrationFS to run. Only MySQL exists today;
// add a postgres/ dir and select on config here when a second driver lands.
// ponytail: single hardcoded dialect, wire to config when postgres is real.
const dialectDir = "migrations/mysql"

// MigrationsFS returns the embedded migration set for the active dialect, rooted
// at the migrations directory: goose expects the .sql files at the top level of
// the fs.FS it is given. That shape suits both the Provider API used here and
// goose's classic API, which cmd points at this FS via goose.SetBaseFS so
// `migrate down`/`reset` run from a deployed binary with no files on disk.
func MigrationsFS() (fs.FS, error) {
	fsys, err := fs.Sub(migrationFS, dialectDir)
	if err != nil {
		return nil, fmt.Errorf("scoping migration fs: %w", err)
	}
	return fsys, nil
}

// Migrate applies all pending migrations using goose's Provider API.
// It runs against the underlying *sql.DB that bun wraps, so goose and bun
// share the same connection pool and DSN.
func Migrate(ctx context.Context, db *bun.DB, log logger.Logger) error {
	fsys, err := MigrationsFS()
	if err != nil {
		return err
	}

	// Refuse out-of-order (missing) migrations — goose's default, made explicit as
	// a deliberate security posture: a not-yet-applied file numbered below the DB's
	// max version aborts the run instead of being silently caught up. That surfaces
	// migration drift (a lower-numbered file merged after a higher one already
	// applied) rather than reordering schema changes into an order nobody authored.
	// Resolve such drift by renumbering the offending file above the DB max, or run
	// a one-off catch-up; do not flip this to true to paper over it.
	provider, err := goose.NewProvider(goose.DialectMySQL, db.DB, fsys, goose.WithAllowOutofOrder(false))
	if err != nil {
		return fmt.Errorf("creating goose provider: %w", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("applying migrations: %w", err)
	}

	if len(results) == 0 {
		log.Info("database is up to date")
		return nil
	}
	for _, r := range results {
		log.Info("migration applied",
			logger.String("file", r.Source.Path),
			logger.Int64("version", r.Source.Version),
			logger.Duration("took", r.Duration),
		)
	}
	return nil
}

// MigrationStatus reports an error when the schema is behind the embedded
// migration set — the readiness probe's "Migrations" check (old repo:
// internal/database.MigrationStatus). It is a single pass/fail signal; the
// operator-facing per-migration listing is `migrate status`, which prints
// goose's own table via goose.StatusContext.
func MigrationStatus(ctx context.Context, db *bun.DB) error {
	fsys, err := MigrationsFS()
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectMySQL, db.DB, fsys)
	if err != nil {
		return fmt.Errorf("creating goose provider: %w", err)
	}
	statuses, err := provider.Status(ctx)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	for _, s := range statuses {
		if s.State != goose.StateApplied {
			return fmt.Errorf("pending migrations: %s is not applied", s.Source.Path)
		}
	}
	return nil
}
