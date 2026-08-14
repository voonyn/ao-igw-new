package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/spf13/cobra"
	"github.com/uptrace/bun"

	apihttp "alphaomega/identitygateway/internal/api/http"
	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/config"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// shutdownGrace bounds graceful shutdown so a request stuck in flight cannot
// block exit (and the deferred DB/Redis cleanup) indefinitely.
const shutdownGrace = 10 * time.Second

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the Identity Gateway HTTP server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServer()
	},
}

// runServer is the composition root: config → logger → Fiber → db → cache →
// routes. Stores and services are constructed by apihttp.Routes, the same seam
// the old repo's internal/router.Routes owned; nothing here is global.
func runServer() error {
	cfg, err := config.InitConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	appLog := logger.New()
	defer appLog.Sync() //nolint:errcheck

	// A blank entry in the PAT set is a typo (a stray comma), not a configuration:
	// it is refused in every environment so a mis-typed rotation fails loudly
	// rather than quietly shrinking the accepted set.
	if err := cfg.Auth.ValidateLoginPATs(); err != nil {
		return fmt.Errorf("invalid login PAT configuration: %w", err)
	}
	if len(cfg.Auth.LoginPATs()) == 0 {
		if cfg.App.IsDevelopment() {
			appLog.Warn("AO_LOGIN_UI_PAT is empty — every /v1/authn/* request will return 401")
		} else {
			return fmt.Errorf("AO_LOGIN_UI_PAT must be set in %q environment", cfg.App.Environment)
		}
	}

	// Secret-at-rest encryption is mandatory outside development: without the key
	// the OIDC private signing keys, client secrets, and login-session blobs are
	// persisted in plaintext. Mirror the PAT/bootstrap guards — a hard failure
	// here, before any subsystem mounts, not a per-subsystem warning.
	if cfg.Database.EncryptionKey == "" {
		if cfg.App.IsDevelopment() {
			appLog.Warn("Database.EncryptionKey is empty — secrets will be stored UNENCRYPTED (dev only)")
		} else {
			return fmt.Errorf("Database.EncryptionKey must be set in %q environment", cfg.App.Environment)
		}
	}

	app := newFiberApp(cfg)

	bdb, err := initDatabase(cfg, appLog)
	if err != nil {
		return err
	}
	defer closeDB(bdb, appLog)

	redisTLS, err := redisTLSConfig(&cfg.Redis)
	if err != nil {
		return err
	}
	rdb, err := cache.New(
		fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		cfg.Redis.Password,
		redisTLS,
	)
	if err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}
	defer rdb.Close() //nolint:errcheck

	mountRoutes(app, cfg, bdb, rdb, appLog)

	serverErrors := make(chan error, 1)
	go startHTTP(app, cfg, appLog, serverErrors)
	return waitForShutdown(app, serverErrors, appLog)
}

func newFiberApp(cfg *config.Config) *fiber.App {
	return fiber.New(config.FiberConfig(cfg.Server.TrustedProxies, cfg.App.Name, cfg.Server.HeaderName))
}

// initDatabase opens the database connection, returning an error (rather than
// terminating the process) so the caller can propagate it through RunE and let
// deferred cleanup run — consistent with cmd/migrate.go's openMigrateDB.
func initDatabase(cfg *config.Config, log logger.Logger) (*bun.DB, error) {
	bdb, err := db.NewDB(cfg.Database, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}
	return bdb, nil
}

// redisTLSConfig builds the *tls.Config for the Redis connection, or nil when
// Redis TLS is disabled. When a CA path is set it verifies against that bundle;
// otherwise it verifies against the system root store. A CA that cannot be read
// or parsed fails startup rather than silently connecting without verification —
// mirroring the database TLS contract.
func redisTLSConfig(cfg *config.RedisConfig) (*tls.Config, error) {
	if !cfg.TLS {
		return nil, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSCAPath == "" {
		return tc, nil
	}
	pem, err := os.ReadFile(cfg.TLSCAPath)
	if err != nil {
		return nil, fmt.Errorf("redis TLS required but CA file %q could not be read: %w", cfg.TLSCAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("redis TLS required but CA file %q contains no valid PEM certificate", cfg.TLSCAPath)
	}
	tc.RootCAs = pool
	return tc, nil
}

func closeDB(bdb *bun.DB, log logger.Logger) {
	if err := bdb.Close(); err != nil {
		log.Error("error closing database connection", logger.Err(err))
	} else {
		log.Info("database connection closed")
	}
}

func mountRoutes(app *fiber.App, cfg *config.Config, bdb *bun.DB, rdb cache.Client, log logger.Logger) {
	apihttp.Routes(app, cfg, bdb, rdb, log)
	app.Use(apihttp.NotFoundHandler)
}

func startHTTP(app *fiber.App, cfg *config.Config, log logger.Logger, serverErrors chan<- error) {
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Info("server starting", logger.String("addr", addr))
	serverErrors <- app.Listen(addr, config.FiberListenConfig())
}

// waitForShutdown blocks until the server errors or a termination signal
// arrives, then returns any error through the normal path (RunE) instead of
// calling log.Fatalf — so the caller's deferred DB/Redis cleanup always runs.
// Graceful shutdown is bounded by shutdownGrace.
func waitForShutdown(app *fiber.App, serverErrors <-chan error, log logger.Logger) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if err != nil {
			return fmt.Errorf("server error: %w", err)
		}
	case <-quit:
		log.Info("shutting down server...")
		if err := app.ShutdownWithTimeout(shutdownGrace); err != nil {
			return fmt.Errorf("server shutdown: %w", err)
		}
	}

	log.Info("server exited")
	return nil
}
