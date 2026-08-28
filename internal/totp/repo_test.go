package totp

import (
	"context"
	"testing"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	repoTenantID = "11111111-1111-1111-1111-111111111111"
	repoUserID   = "33333333-3333-3333-3333-333333333333"
	repoOtherID  = "44444444-4444-4444-4444-444444444444"
)

// testRepository opens a scratch schema and seeds an active factor on two
// people. The second person proves that a reset reaches one account only.
func testRepository(t *testing.T) (*Repository, *bun.DB, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "totp")
	ctx := context.Background()

	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	factor := func(userID string) {
		t.Helper()
		exec(`INSERT INTO user_totp (tenant_id, user_id, secret_encrypted, activated_at, last_step)
		      VALUES (?, ?, 'a-secret', NOW(3), 58000000)`, repoTenantID, userID)
		exec(`INSERT INTO user_totp_recovery_codes (tenant_id, user_id, code_hash)
		      VALUES (?, ?, REPEAT('a', 64))`, repoTenantID, userID)
		exec(`INSERT INTO user_totp_recovery_codes (tenant_id, user_id, code_hash)
		      VALUES (?, ?, REPEAT('b', 64))`, repoTenantID, userID)
	}

	factor(repoUserID)
	factor(repoOtherID)

	log, _ := logger.NewObserved()
	return NewRepository(bdb, log), bdb, ctx
}

// rowsHeld answers how many rows of one table one person holds.
func rowsHeld(ctx context.Context, t *testing.T, bdb *bun.DB, table, userID string) int {
	t.Helper()

	var rows int
	query := "SELECT COUNT(*) FROM " + table + " WHERE tenant_id = ? AND user_id = ?"
	if err := bdb.QueryRowContext(ctx, query, repoTenantID, userID).Scan(&rows); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return rows
}

// TestClearHardDeletesTheFactor covers what an administrator reset must do. The
// row is gone, not marked, so no secret is left readable and the next enrolment
// writes a plain INSERT. See docs/adr/0009-hard-delete-the-totp-factor.md.
func TestClearHardDeletesTheFactor(t *testing.T) {
	repo, bdb, ctx := testRepository(t)

	if err := repo.Clear(ctx, repoTenantID, repoUserID); err != nil {
		t.Fatalf("clear the factor: %v", err)
	}

	if rows := rowsHeld(ctx, t, bdb, "user_totp", repoUserID); rows != 0 {
		t.Errorf("the account holds %d totp rows, want the row hard deleted", rows)
	}
	if rows := rowsHeld(ctx, t, bdb, "user_totp_recovery_codes", repoUserID); rows != 0 {
		t.Errorf("the account holds %d recovery codes, want them hard deleted", rows)
	}

	// The reset reaches one account. The second person keeps their factor.
	if rows := rowsHeld(ctx, t, bdb, "user_totp", repoOtherID); rows != 1 {
		t.Errorf("the second account holds %d totp rows, want 1", rows)
	}
	if rows := rowsHeld(ctx, t, bdb, "user_totp_recovery_codes", repoOtherID); rows != 2 {
		t.Errorf("the second account holds %d recovery codes, want 2", rows)
	}

	// A person with no factor is the normal outcome, so a second reset is not an
	// error.
	if err := repo.Clear(ctx, repoTenantID, repoUserID); err != nil {
		t.Errorf("a second reset gives %v, want no error", err)
	}
}
