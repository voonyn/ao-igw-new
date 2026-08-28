package totp

import (
	"context"
	"errors"
	"strings"
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

// secretHeld answers the stored secret of one person.
func secretHeld(ctx context.Context, t *testing.T, bdb *bun.DB, userID string) string {
	t.Helper()

	var secret string
	query := "SELECT secret_encrypted FROM user_totp WHERE tenant_id = ? AND user_id = ?"
	if err := bdb.QueryRowContext(ctx, query, repoTenantID, userID).Scan(&secret); err != nil {
		t.Fatalf("read the stored secret: %v", err)
	}
	return secret
}

// pending replaces the seeded active factor of one person with a pending
// enrolment: a secret nobody has proved yet.
func pending(ctx context.Context, t *testing.T, bdb *bun.DB, userID, secret string) {
	t.Helper()

	_, err := bdb.ExecContext(ctx,
		"UPDATE user_totp SET secret_encrypted = ?, activated_at = NULL, last_step = 0"+
			" WHERE tenant_id = ? AND user_id = ?", secret, repoTenantID, userID)
	if err != nil {
		t.Fatalf("seed a pending enrolment: %v", err)
	}
}

// TestSavePendingRefusesAnActiveFactor covers the race the sign-in cannot stage:
// a start that arrives after the person already activated a factor.
//
// The write must not land. A start that answered a secret the database never
// stored would hand the person a dead enrolment, and a write that landed would
// destroy a factor that works.
func TestSavePendingRefusesAnActiveFactor(t *testing.T) {
	repo, bdb, ctx := testRepository(t)

	err := repo.SavePending(ctx, repoTenantID, repoUserID, []byte("a-new-secret"))
	if !errors.Is(err, ErrAlreadyEnrolled) {
		t.Fatalf("save a pending enrolment over an active factor gives %v, want %v",
			err, ErrAlreadyEnrolled)
	}
	if held := secretHeld(ctx, t, bdb, repoUserID); held != "a-secret" {
		t.Errorf("the stored secret is %q, want the active one left alone", held)
	}
}

// TestSavePendingReplacesAPendingEnrolment covers the person who abandoned a
// setup and started again. The new secret replaces the old one, and no spent
// step carries over.
func TestSavePendingReplacesAPendingEnrolment(t *testing.T) {
	repo, bdb, ctx := testRepository(t)
	pending(ctx, t, bdb, repoUserID, "an-abandoned-secret")

	if err := repo.SavePending(ctx, repoTenantID, repoUserID, []byte("a-new-secret")); err != nil {
		t.Fatalf("save a pending enrolment: %v", err)
	}

	if held := secretHeld(ctx, t, bdb, repoUserID); held != "a-new-secret" {
		t.Errorf("the stored secret is %q, want the new one", held)
	}
	row, err := repo.Find(ctx, repoTenantID, repoUserID)
	if err != nil {
		t.Fatalf("read the enrolment: %v", err)
	}
	if row.Active() {
		t.Error("the replaced enrolment reads as active")
	}
	if row.LastStep != 0 {
		t.Errorf("last_step is %d, want 0 on a fresh secret", row.LastStep)
	}
}

// TestActivateRefusesAStaleSecret covers the second race the sign-in cannot
// stage: a start that replaced the pending secret while an activation was in
// flight.
//
// The activation names the secret it verified, so a secret nobody proved is
// never made the active factor. Without the guard the person would hold a factor
// their Authenticator cannot answer.
func TestActivateRefusesAStaleSecret(t *testing.T) {
	repo, bdb, ctx := testRepository(t)
	pending(ctx, t, bdb, repoUserID, "the-newest-secret")

	err := repo.Activate(ctx, repoTenantID, repoUserID, []byte("a-stale-secret"), 58000001)
	if !errors.Is(err, ErrNoEnrolment) {
		t.Fatalf("activate a stale secret gives %v, want %v", err, ErrNoEnrolment)
	}

	row, err := repo.Find(ctx, repoTenantID, repoUserID)
	if err != nil {
		t.Fatalf("read the enrolment: %v", err)
	}
	if row.Active() {
		t.Error("a stale secret was made the active factor")
	}

	// The secret the caller verified activates, and it spends its step.
	if err := repo.Activate(ctx, repoTenantID, repoUserID,
		[]byte("the-newest-secret"), 58000001); err != nil {
		t.Fatalf("activate the verified secret: %v", err)
	}
	row, err = repo.Find(ctx, repoTenantID, repoUserID)
	if err != nil {
		t.Fatalf("read the enrolment: %v", err)
	}
	if !row.Active() || row.LastStep != 58000001 {
		t.Errorf("the enrolment is %+v, want an active factor that spent step 58000001", row)
	}
}

// TestSpendStepRefusesAReplay covers the replay guard. A code an observer read
// off the screen is accepted once, and never again.
//
// The comparison is "less than", never "not equal". verify accepts the previous
// time step as well, so a "not equal" guard would let the same code be replayed
// one step later.
func TestSpendStepRefusesAReplay(t *testing.T) {
	repo, _, ctx := testRepository(t)

	// The seed spent step 58000000. The step after it is claimed once.
	if err := repo.SpendStep(ctx, repoTenantID, repoUserID, 58000001); err != nil {
		t.Fatalf("spend the next step: %v", err)
	}

	// The same step, and every step below it, is refused.
	for _, step := range []int64{58000001, 58000000, 57999999, 1} {
		if err := repo.SpendStep(ctx, repoTenantID, repoUserID, step); !errors.Is(err, ErrCodeSpent) {
			t.Errorf("spend step %d again gives %v, want %v", step, err, ErrCodeSpent)
		}
	}

	row, err := repo.Find(ctx, repoTenantID, repoUserID)
	if err != nil {
		t.Fatalf("read the enrolment: %v", err)
	}
	if row.LastStep != 58000001 {
		t.Errorf("last_step is %d, want the newest spent step 58000001", row.LastStep)
	}

	// The spend reaches one account. The second person keeps their own step.
	other, err := repo.Find(ctx, repoTenantID, repoOtherID)
	if err != nil {
		t.Fatalf("read the second enrolment: %v", err)
	}
	if other.LastStep != 58000000 {
		t.Errorf("the second account spent step %d, want 58000000", other.LastStep)
	}
}

// TestRedeemRecoveryCodeSpendsOneCodeOnce covers the single-use rule. The row is
// the code, so the first delete to reach it is the one that redeems it.
func TestRedeemRecoveryCodeSpendsOneCodeOnce(t *testing.T) {
	repo, bdb, ctx := testRepository(t)

	held := strings.Repeat("a", 64)
	if err := repo.RedeemRecoveryCode(ctx, repoTenantID, repoUserID, held); err != nil {
		t.Fatalf("redeem a recovery code: %v", err)
	}

	// The row is gone, not marked. A code is consumed once, so no row may stay
	// readable.
	if rows := rowsHeld(ctx, t, bdb, "user_totp_recovery_codes", repoUserID); rows != 1 {
		t.Errorf("the account holds %d recovery codes, want 1 left", rows)
	}
	if err := repo.RedeemRecoveryCode(ctx, repoTenantID, repoUserID, held); !errors.Is(err, ErrCodeSpent) {
		t.Fatalf("redeem the same code again gives %v, want %v", err, ErrCodeSpent)
	}

	// A code the account never held answers the same way, so the response never
	// says whether the code existed.
	unknown := strings.Repeat("c", 64)
	if err := repo.RedeemRecoveryCode(ctx, repoTenantID, repoUserID, unknown); !errors.Is(err, ErrCodeSpent) {
		t.Errorf("redeem an unknown code gives %v, want %v", err, ErrCodeSpent)
	}

	// A redemption reaches one account. The second person keeps both codes.
	if rows := rowsHeld(ctx, t, bdb, "user_totp_recovery_codes", repoOtherID); rows != 2 {
		t.Errorf("the second account holds %d recovery codes, want 2", rows)
	}
}

// TestAuthenticatorCodeTellsTheTwoKindsApart covers the branch that decides what
// one submission is. A submission is never tried against both kinds, so this
// classification is the whole of that rule.
func TestAuthenticatorCodeTellsTheTwoKindsApart(t *testing.T) {
	cases := map[string]bool{
		"123456":      true,  // what an Authenticator shows, as the caller trims it
		"000000":      true,  // a leading zero is a digit like any other
		"12345":       false, // too short to be a code
		"1234567":     false, // too long to be a code
		"12345A":      false, // a letter, so it is a Recovery Code
		"":            false,
		"ABCDE-FGHJK": false, // a Recovery Code as it is printed
		"A1B2C3D4E5":  false, // a Recovery Code as it is stored
	}

	for code, want := range cases {
		if got := authenticatorCode(code); got != want {
			t.Errorf("authenticatorCode(%q) is %v, want %v", code, got, want)
		}
	}
}
