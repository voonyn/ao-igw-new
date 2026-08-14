package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pressly/goose/v3"
	"github.com/spf13/cobra"
	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// migrationsDir is the on-disk migrations directory. Only `create` uses it: it
// writes a new file into the repo checkout, so it is inherently a dev command
// that must run from the repo root. Every other subcommand reads the copies
// embedded in the binary, so a deployed binary needs no files on disk.
const migrationsDir = "internal/platform/db/migrations/mysql"

// embeddedMigrationsDir is the directory goose's classic API is given once
// useEmbeddedMigrations has rooted its base FS at the migrations directory —
// the .sql files then sit at the top level, so "." is the whole set.
const embeddedMigrationsDir = "."

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Manage database schema migrations",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all pending migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		bdb, zl, cleanup, err := openMigrateDB()
		if err != nil {
			return err
		}
		defer cleanup()
		return db.Migrate(cmd.Context(), bdb, zl)
	},
}

var migrateDownCmd = &cobra.Command{
	Use:   "down [N]",
	Short: "Roll back the last N applied migrations (default: 1)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		bdb, _, cleanup, err := openMigrateDB()
		if err != nil {
			return err
		}
		defer cleanup()

		n := 1
		if len(args) == 1 {
			var parseErr error
			n, parseErr = strconv.Atoi(args[0])
			if parseErr != nil || n < 1 {
				return fmt.Errorf("N must be a positive integer")
			}
		}
		if err := useEmbeddedMigrations(); err != nil {
			return err
		}
		for i := 0; i < n; i++ {
			if err := goose.Down(bdb.DB, embeddedMigrationsDir); err != nil {
				return fmt.Errorf("goose down (step %d): %w", i+1, err)
			}
		}
		return nil
	},
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Print applied and pending migration versions",
	RunE: func(cmd *cobra.Command, args []string) error {
		bdb, _, cleanup, err := openMigrateDB()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := useEmbeddedMigrations(); err != nil {
			return err
		}
		return goose.StatusContext(cmd.Context(), bdb.DB, embeddedMigrationsDir)
	},
}

var migrateCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Scaffold a new sequentially-numbered SQL migration file on disk",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		goose.SetSequential(true)
		if err := goose.Create(nil, migrationsDir, args[0], "sql"); err != nil {
			return fmt.Errorf("goose create: %w", err)
		}
		return nil
	},
}

var migrateResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Roll back all migrations then re-apply them (non-production only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.InitConfig()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if strings.EqualFold(cfg.App.Environment, "production") {
			fmt.Fprintln(os.Stderr, "error: migrate reset is not allowed in production")
			return fmt.Errorf("migrate reset refused in production environment")
		}

		bdb, zl, cleanup, err := openMigrateDB()
		if err != nil {
			return err
		}
		defer cleanup()

		if err := useEmbeddedMigrations(); err != nil {
			return err
		}
		if err := goose.DownTo(bdb.DB, embeddedMigrationsDir, 0); err != nil {
			return fmt.Errorf("goose down-to 0: %w", err)
		}
		if err := db.Migrate(cmd.Context(), bdb, zl); err != nil {
			return fmt.Errorf("goose up after reset: %w", err)
		}
		return nil
	},
}

// useEmbeddedMigrations points goose's classic API — the one `status`, `down`
// and `reset` use — at the migrations embedded in the binary, and selects the
// dialect that the provider-based `up` sets per-provider rather than globally.
// This is the old gateway's package-level goose.SetBaseFS, narrowed to the three
// subcommands that need it; `create` deliberately does not call it, because
// goose's Create ignores the base FS and writes to the repo checkout anyway.
//
// goose's Provider API can roll back too (Provider.Down/DownTo) — `down` and
// `reset` stayed on the classic API to keep their carried-over shape, not
// because the provider lacks the capability.
func useEmbeddedMigrations() error {
	fsys, err := db.MigrationsFS()
	if err != nil {
		return fmt.Errorf("embedded migrations: %w", err)
	}
	goose.SetBaseFS(fsys)
	if err := goose.SetDialect("mysql"); err != nil {
		return fmt.Errorf("goose dialect: %w", err)
	}
	return nil
}

func openMigrateDB() (*bun.DB, logger.Logger, func(), error) {
	cfg, err := config.InitConfig()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load config: %w", err)
	}
	zl := logger.New()
	bdb, err := db.NewDB(cfg.Database, zl)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open database: %w", err)
	}
	cleanup := func() {
		if cerr := bdb.Close(); cerr != nil {
			zl.Warn("migrate: error closing db", logger.Err(cerr))
		}
	}
	return bdb, zl, cleanup, nil
}

func init() {
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	migrateCmd.AddCommand(migrateCreateCmd)
	migrateCmd.AddCommand(migrateResetCmd)
}
