package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.uber.org/zap/zapcore"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The two passwords every change test uses. The stored hash is built from
// currentPassword, so a test that presents it proves that the caller holds the
// password of the account.
const (
	currentPassword = "Curr3nt-Pass!"
	nextPassword    = "N3xt-Pass-Word!"
)

// policyRefusal is what a policy refusal looks like to this domain. The real one
// is authpolicy.ErrWeakPassword, and this domain never names it: the check
// arrives as a function value, and whatever it answers travels back unchanged.
var policyRefusal = errors.New("password does not meet the policy")

// policyUnreadable is what a failed policy read looks like to this domain. It is
// not the refusal, and the mapper registers neither, so the request answers a
// server error instead of a weak-password refusal.
var policyUnreadable = errors.New("read the auth policy: the database is down")

// passwordDeps is what one change-password test varies.
type passwordDeps struct {
	// noAccount makes the credential read answer ErrNotFound, as it does for an
	// account that was deleted, deactivated, or locked behind a live token.
	noAccount bool
	// policyErr is what the password check answers.
	policyErr error
	// revokeErr is what the bulk session revoke answers.
	revokeErr error
}

// What the writes of one change-password test did. passwordService clears them,
// and the tests of one package run one after another, so each test reads its own
// writes.
var (
	writtenHashes  []string
	revokedExcepts []string
)

// TestChangePasswordWritesTheNewHashAndKeepsTheCallersSession proves the whole
// success path. The caller presents the current password, the new one is hashed
// and written, every other login session ends, and one event records the change.
func TestChangePasswordWritesTheNewHashAndKeepsTheCallersSession(t *testing.T) {
	svc := passwordService(t, passwordDeps{})

	if err := svc.ChangePassword(context.Background(), person, passwordBody(), "a-session-id"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if len(writtenHashes) != 1 {
		t.Fatalf("the service wrote %d hashes, want 1", len(writtenHashes))
	}
	if err := crypto.VerifyPassword(writtenHashes[0], nextPassword); err != nil {
		t.Errorf("the stored hash does not verify the new password: %v", err)
	}
	if err := crypto.VerifyPassword(writtenHashes[0], currentPassword); err == nil {
		t.Error("the stored hash still verifies the old password, want the new one")
	}

	if len(revokedExcepts) != 1 || revokedExcepts[0] != "a-session-id" {
		t.Errorf("the revoke spared %v, want the one session the portal named", revokedExcepts)
	}
	if len(events) != 1 {
		t.Fatalf("the service recorded %d events, want 1", len(events))
	}
	if events[0].Action != string(audit.ActionPasswordChanged) {
		t.Errorf("the event records the action %q, want %q", events[0].Action, audit.ActionPasswordChanged)
	}
	if events[0].ActorID != testUserID || events[0].EntityID != testUserID {
		t.Errorf("the event names actor %s and entity %s, want %s for both",
			events[0].ActorID, events[0].EntityID, testUserID)
	}
}

// TestChangePasswordSignsOutEverywhereWithNoSessionNamed proves the degradation.
// A caller that names no session keeps none, their own included.
func TestChangePasswordSignsOutEverywhereWithNoSessionNamed(t *testing.T) {
	svc := passwordService(t, passwordDeps{})

	if err := svc.ChangePassword(context.Background(), person, passwordBody(), ""); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if len(revokedExcepts) != 1 || revokedExcepts[0] != "" {
		t.Errorf("the revoke spared %v, want nothing", revokedExcepts)
	}
}

// TestChangePasswordRefusesAWrongCurrentPassword proves that the caller must
// hold the password of the account, and that a refusal writes nothing.
func TestChangePasswordRefusesAWrongCurrentPassword(t *testing.T) {
	svc := passwordService(t, passwordDeps{})

	wrong := PasswordBody{CurrentPassword: "not-the-password", NewPassword: nextPassword}
	err := svc.ChangePassword(context.Background(), person, wrong, "a-session-id")
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("err = %v, want ErrBadPassword", err)
	}
	wantNothingWritten(t)
}

// TestChangePasswordRefusesAMissingAccountAlike proves that a token whose
// account can no longer sign in reads what a wrong password reads. The answer
// never says which accounts a tenant holds.
func TestChangePasswordRefusesAMissingAccountAlike(t *testing.T) {
	svc := passwordService(t, passwordDeps{noAccount: true})

	err := svc.ChangePassword(context.Background(), person, passwordBody(), "a-session-id")
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("err = %v, want the ErrBadPassword a wrong password answers", err)
	}
	wantNothingWritten(t)
}

// TestChangePasswordCarriesThePolicyRefusalUnchanged proves that the refusal of
// the check travels back as it came. The handler maps it, and this domain names
// no rule of the policy.
func TestChangePasswordCarriesThePolicyRefusalUnchanged(t *testing.T) {
	svc := passwordService(t, passwordDeps{policyErr: policyRefusal})

	err := svc.ChangePassword(context.Background(), person, passwordBody(), "a-session-id")
	if !errors.Is(err, policyRefusal) {
		t.Fatalf("err = %v, want the refusal of the check", err)
	}
	wantNothingWritten(t)
}

// TestChangePasswordLeavesAFailedPolicyReadToThePolicyDomain proves two rules.
// The failed read is logged where it happened and not again here, and it is not
// the refusal, so the request answers a server error and not a 400.
func TestChangePasswordLeavesAFailedPolicyReadToThePolicyDomain(t *testing.T) {
	svc := passwordService(t, passwordDeps{policyErr: policyUnreadable})

	err := svc.ChangePassword(context.Background(), person, passwordBody(), "a-session-id")
	if !errors.Is(err, policyUnreadable) {
		t.Fatalf("err = %v, want the error of the policy read", err)
	}
	if errors.Is(err, policyRefusal) {
		t.Error("the failed read reads as a weak-password refusal, want a server error")
	}
	if got := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); got != 0 {
		t.Errorf("the service logged %d error lines, want none: the policy domain logged it", got)
	}
	wantNothingWritten(t)
}

// TestChangePasswordRollsBackAFailedRevoke proves that the write and the revoke
// land together. A password that changed with the other devices still signed in
// leaves the leak the person is closing wide open.
func TestChangePasswordRollsBackAFailedRevoke(t *testing.T) {
	svc := passwordService(t, passwordDeps{revokeErr: errors.New("the revoke failed")})

	if err := svc.ChangePassword(context.Background(), person, passwordBody(), "a-session-id"); err == nil {
		t.Fatal("err = nil, want the error of the revoke")
	}
	if len(events) != 0 {
		t.Errorf("the service recorded %d events, want none", len(events))
	}
	if !rolledBack {
		t.Error("the transaction committed, want a rollback")
	}
}

// TestChangePasswordKeepsBothPasswordsOutOfEveryLog reads every line the service
// wrote, at every level, on the paths that succeed and on the paths that refuse.
func TestChangePasswordKeepsBothPasswordsOutOfEveryLog(t *testing.T) {
	for _, d := range []passwordDeps{{}, {noAccount: true}, {policyErr: policyRefusal}} {
		svc := passwordService(t, d)
		_ = svc.ChangePassword(context.Background(), person, passwordBody(), "a-session-id")

		for _, entry := range logs.All() {
			line := entry.Message + fmt.Sprint(entry.ContextMap())
			if strings.Contains(line, currentPassword) || strings.Contains(line, nextPassword) {
				t.Errorf("the log line %q carries a password", line)
			}
		}
	}
}

// passwordBody is the request every change-password test sends, with the
// password the account holds now.
func passwordBody() PasswordBody {
	return PasswordBody{CurrentPassword: currentPassword, NewPassword: nextPassword}
}

// wantNothingWritten proves that a refused change touched nothing.
func wantNothingWritten(t *testing.T) {
	t.Helper()

	if len(writtenHashes) != 0 {
		t.Errorf("the service wrote %d hashes, want none", len(writtenHashes))
	}
	if len(revokedExcepts) != 0 {
		t.Errorf("the service revoked sessions %d times, want none", len(revokedExcepts))
	}
	if len(events) != 0 {
		t.Errorf("the service recorded %d events, want none", len(events))
	}
}

// passwordService builds the account service with the four dependencies of a
// password change substituted by closures. No database and no HTTP, so the test
// runs on any machine.
func passwordService(t *testing.T, d passwordDeps) *AccountService {
	t.Helper()
	var log logger.Logger
	log, logs = logger.NewObserved()
	events, rolledBack = nil, false
	writtenHashes, revokedExcepts = nil, nil

	stored, err := crypto.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("hash the current password: %v", err)
	}

	record := func(_ context.Context, e audit.Event) error {
		events = append(events, e)
		return nil
	}

	return NewAccountService(AccountDeps{
		Credential: func(_ context.Context, tenantID, userID string) (User, error) {
			if d.noAccount {
				return User{}, ErrNotFound
			}
			return User{ID: userID, TenantID: tenantID, OrgID: testOrgID, PasswordHash: stored}, nil
		},
		SetPassword: func(_ context.Context, _, _, hash string) error {
			writtenHashes = append(writtenHashes, hash)
			return nil
		},
		CheckPassword: func(context.Context, string, string, string) error { return d.policyErr },
		// No Directory proves this person, so the local compare answers every
		// proof below. The directory re-proof has tests of its own.
		Directory: func(context.Context, string, string) (string, string, error) { return "", "", nil },
		RevokeOthers: func(_ context.Context, _ Actor, exceptID string) error {
			if d.revokeErr != nil {
				return d.revokeErr
			}
			revokedExcepts = append(revokedExcepts, exceptID)
			return nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			if err := fn(ctx); err != nil {
				rolledBack = true
				return err
			}
			return nil
		},
		Audit: audit.NewRecorder(record, log),
		Log:   log,
	})
}
