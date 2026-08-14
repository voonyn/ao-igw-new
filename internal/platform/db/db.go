// Package db is the low-level persistence platform: the database connection,
// the transaction manager, the tx-aware connection helper every repository
// uses, migrations, and driver-error translation. Domain stores build on it;
// it knows nothing about domain types.
package db

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"os"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
	"github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mysqldialect"

	"alphaomega/identitygateway/internal/platform/config"
)

// pingTimeout bounds the startup connectivity check so an unreachable database
// host fails startup in seconds instead of hanging on the OS TCP timeout.
const pingTimeout = 5 * time.Second

func NewDB(cfg config.DatabaseConfig, log logger.Logger) (*bun.DB, error) {
	applyDefaults(&cfg)

	var driver, dsn string
	switch cfg.Driver {
	case "mysql":
		driver = "mysql"
		var err error
		if dsn, err = buildMySQLDSN(&cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}

	sqldb, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	sqldb.SetMaxOpenConns(cfg.Pool.MaxOpenConns)
	sqldb.SetMaxIdleConns(cfg.Pool.MaxIdleConns)
	sqldb.SetConnMaxLifetime(cfg.Pool.MaxConnLifetime)
	sqldb.SetConnMaxIdleTime(cfg.Pool.MaxConnIdleTime)

	pingCtx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := sqldb.PingContext(pingCtx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info("database connected")

	// The dialect is selected once, here, at connection construction — never in a
	// repository. Swap mysqldialect for pgdialect/mssqldialect when a second
	// dialect lands; repositories are dialect-agnostic and do not change.
	return bun.NewDB(sqldb, mysqldialect.New()), nil
}

func applyDefaults(cfg *config.DatabaseConfig) {
	if cfg.Pool.MaxOpenConns == 0 {
		cfg.Pool.MaxOpenConns = 100
	}
	if cfg.Pool.MaxIdleConns == 0 {
		cfg.Pool.MaxIdleConns = 10
	}
	if cfg.Pool.MaxConnLifetime == 0 {
		cfg.Pool.MaxConnLifetime = 30 * time.Minute
	}
	if cfg.Pool.MaxConnIdleTime == 0 {
		cfg.Pool.MaxConnIdleTime = 5 * time.Minute
	}
	if cfg.Port == 0 {
		switch cfg.Driver {
		case "mysql":
			cfg.Port = 3306
		case "postgres":
			cfg.Port = 5432
		}
	}
}

// buildMySQLDSN assembles the go-sql-driver DSN, wiring TLS when Database.SSLMode
// is set. It returns an error (failing startup) when SSL is required but a TLS
// config cannot be established — e.g. the configured CA file cannot be read or
// parsed — so a required-TLS setting is never silently downgraded to plaintext.
func buildMySQLDSN(cfg *config.DatabaseConfig) (string, error) {
	tlsParam, err := mysqlTLSParam(cfg)
	if err != nil {
		return "", err
	}
	// clientFoundRows=true: UPDATE reports rows *matched*, not *changed*, so a
	// no-op update (unchanged values) still reports its row — repositories can
	// treat RowsAffected==0 as "row absent" without misreading idempotent writes.
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local&clientFoundRows=true%s",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
		tlsParam,
	), nil
}

// mysqlTLSParam returns the DSN `&tls=...` fragment for the configured SSL mode,
// registering a verifying tls.Config against a custom CA when one is provided.
// Empty (no TLS) when SSLMode is off. On any failure to load the CA it returns an
// error rather than falling back to plaintext.
func mysqlTLSParam(cfg *config.DatabaseConfig) (string, error) {
	if !cfg.SSLMode {
		return "", nil
	}
	// No custom CA: verify the server cert against the system root store.
	if cfg.SSLCAPath == "" {
		return "&tls=true", nil
	}

	pem, err := os.ReadFile(cfg.SSLCAPath)
	if err != nil {
		return "", fmt.Errorf("database TLS required but CA file %q could not be read: %w", cfg.SSLCAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return "", fmt.Errorf("database TLS required but CA file %q contains no valid PEM certificate", cfg.SSLCAPath)
	}
	// RegisterTLSConfig keys the config by name for the DSN to reference. The name
	// is fixed; a fresh registration each startup simply overwrites the prior one.
	const tlsName = "ao-custom"
	if err := mysql.RegisterTLSConfig(tlsName, &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}); err != nil {
		return "", fmt.Errorf("database TLS: register CA config: %w", err)
	}
	return "&tls=" + tlsName, nil
}

// Conn returns the transaction from ctx when inside TxManager.RunInTx,
// otherwise the base *bun.DB. Every query in every repository goes through it,
// so repositories work identically inside and outside transactions.
func Conn(ctx context.Context, bdb *bun.DB) bun.IDB {
	if tx, ok := txFromContext(ctx); ok {
		return tx
	}
	return bdb
}
