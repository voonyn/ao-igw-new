package totp

// This file proves the two guards that only hold under a race: a time step is
// claimed once, and a Recovery Code is redeemed once.
//
// Both guards are the SQL and nothing above it, so both tests drive the real
// database. A test with a stub repository proves the Go, never the row lock.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db"
)

// raceWriters is how many writers spend the same value at the same moment. Two
// is the race both guards exist for, and more writers prove nothing further.
const raceWriters = 2

// TestSpendStepClaimsOneWriter proves that two sign-ins spending the same time
// step produce exactly one success.
//
// A person who submits the code shown by their Authenticator twice, or an
// attacker who observed one, reaches the update at the same moment as the sign-in
// that owns it. The guard is last_step < ?, and the row lock serialises the two
// updates. The second writer re-reads the claimed step, matches no row, and is
// refused. Without it an observed code is good twice inside its own time step.
func TestSpendStepClaimsOneWriter(t *testing.T) {
	repo, bdb, ctx := testRepository(t)

	// The seed spent step 58000000, so this is a step the account can still
	// claim.
	const step = 58000001

	won := raceToSpend(t, bdb, func(ctx context.Context) error {
		return repo.SpendStep(ctx, repoTenantID, repoUserID, step)
	})
	if won != 1 {
		t.Errorf("%d writers spent the time step, want 1", won)
	}

	var spent int64
	err := bdb.QueryRowContext(ctx,
		"SELECT last_step FROM user_totp WHERE tenant_id = ? AND user_id = ?",
		repoTenantID, repoUserID).Scan(&spent)
	if err != nil {
		t.Fatalf("read the spent step: %v", err)
	}
	if spent != step {
		t.Errorf("the account spent step %d, want %d", spent, step)
	}
}

// TestRedeemRecoveryCodeSpendsOneWriter proves that two sign-ins redeeming the
// same Recovery Code produce exactly one success.
//
// The row is the code, so the delete is the whole guard. The first writer to
// reach the row redeems it, and the second one deletes nothing. Two sign-ins that
// both succeeded would spend one code twice, and one Recovery Code would sign a
// person in as often as they sent it.
func TestRedeemRecoveryCodeSpendsOneWriter(t *testing.T) {
	repo, bdb, ctx := testRepository(t)

	// The seed wrote two codes on this person. Both writers redeem the first, so
	// the second one must survive the race untouched.
	digest := strings.Repeat("a", 64)

	won := raceToSpend(t, bdb, func(ctx context.Context) error {
		return repo.RedeemRecoveryCode(ctx, repoTenantID, repoUserID, digest)
	})
	if won != 1 {
		t.Errorf("%d writers redeemed the code, want 1", won)
	}
	if held := rowsHeld(ctx, t, bdb, "user_totp_recovery_codes", repoUserID); held != 1 {
		t.Errorf("the account holds %d recovery codes, want 1", held)
	}
}

// raceToSpend runs raceWriters copies of one write at the same moment, each on a
// transaction of its own, and answers how many of them succeeded.
//
// Every writer opens its transaction before any of them runs its statement, so
// the writers really do contend for the row. The service runs the same write on a
// transaction, so this is the shape production takes.
//
// A writer that loses must lose with ErrCodeSpent. A lock wait that timed out, or
// any other error, is reported: it means the guard did not decide the race.
func raceToSpend(t *testing.T, bdb *bun.DB, write func(ctx context.Context) error) int {
	t.Helper()

	tx := db.NewTxManager(bdb)
	start := make(chan struct{})
	errs := make([]error, raceWriters)

	var open, done sync.WaitGroup
	open.Add(raceWriters)
	done.Add(raceWriters)

	for i := range raceWriters {
		go func() {
			defer done.Done()

			// A transaction that never began must not hold the barrier shut, so
			// the deferred call releases it once either way.
			opened := sync.OnceFunc(open.Done)
			defer opened()

			errs[i] = tx.RunInTx(t.Context(), func(ctx context.Context) error {
				opened()
				<-start
				return write(ctx)
			})
		}()
	}

	open.Wait()
	close(start)
	done.Wait()

	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrCodeSpent):
		default:
			t.Errorf("a writer failed with %v, want nil or %v", err, ErrCodeSpent)
		}
	}
	return won
}
