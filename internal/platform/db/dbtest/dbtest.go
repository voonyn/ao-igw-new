// Package dbtest opens a scratch MySQL schema for a repository test.
//
// A repository test proves the SQL, so it needs the database the SQL is written
// for. Set AO_TEST_MYSQL_DSN to a server the test can create a schema on:
//
//	AO_TEST_MYSQL_DSN="root:secret@tcp(localhost:3306)/" go test ./internal/...
//
// Every test that calls Open skips when the variable is unset, so `go test ./...`
// stays green on a machine with no database.
package dbtest

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mysqldialect"

	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// DSNEnv names the environment variable that carries the server DSN. The schema
// in the DSN is ignored: Open always works on a scratch schema of its own.
const DSNEnv = "AO_TEST_MYSQL_DSN"

// schemaPrefix namespaces every scratch schema, so a drop can never reach a
// schema the operator cares about.
const schemaPrefix = "ao_test_"

// Open creates the scratch schema ao_test_<name>, applies every migration, and
// returns a bun connection to it. The schema is dropped when the test ends.
//
// name must differ per package, because Go runs the tests of two packages at the
// same time and they would otherwise drop each other's schema.
func Open(t *testing.T, name string) *bun.DB {
	t.Helper()

	dsn := os.Getenv(DSNEnv)
	if dsn == "" {
		t.Skipf("set %s to run this test, for example %s=\"root:secret@tcp(localhost:3306)/\"", DSNEnv, DSNEnv)
	}

	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", DSNEnv, err)
	}
	schema := schemaPrefix + name

	// The server connection creates the schema. It names no schema itself, so a
	// DSN that names one cannot be dropped here.
	cfg.DBName = ""
	server, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open the server: %v", err)
	}
	defer server.Close()

	ctx := context.Background()
	if _, err := server.ExecContext(ctx, "DROP DATABASE IF EXISTS "+schema); err != nil {
		t.Fatalf("drop the scratch schema %s: %v", schema, err)
	}
	if _, err := server.ExecContext(ctx,
		"CREATE DATABASE "+schema+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
		t.Fatalf("create the scratch schema %s: %v", schema, err)
	}

	// The same settings the application connects with, so the test reads what the
	// application reads. See buildMySQLDSN in internal/platform/db/db.go.
	cfg.DBName = schema
	cfg.ParseTime = true
	cfg.ClientFoundRows = true
	sqldb, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open the scratch schema %s: %v", schema, err)
	}
	bdb := bun.NewDB(sqldb, mysqldialect.New())

	if err := db.Migrate(ctx, bdb, logger.New()); err != nil {
		bdb.Close()
		t.Fatalf("migrate the scratch schema %s: %v", schema, err)
	}

	t.Cleanup(func() {
		bdb.Close()
		dropper, err := sql.Open("mysql", dsn)
		if err != nil {
			t.Errorf("reopen to drop the scratch schema %s: %v", schema, err)
			return
		}
		defer dropper.Close()
		if _, err := dropper.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+schema); err != nil {
			t.Errorf("drop the scratch schema %s: %v", schema, err)
		}
	})

	return bdb
}
