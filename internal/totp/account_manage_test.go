package totp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/user"
)

// The two destructive portal addresses, proved with no database.
//
// The password is the whole guard here. The access token carries no session
// identifier and the bearer guard reads no store, so a body field is the only
// place a proof can go, and the order these tests measure is what makes it a
// guard: nothing is read and nothing is written until the password is proved.

// errWrongPassword stands in for the sentinel the user domain answers. The
// router closes over the real credential read, so this module never names it.
var errWrongPassword = errors.New("current password is wrong")

// manageCalls records what one request touched, in the order it touched it.
type manageCalls struct {
	proved  bool
	found   bool
	cleared bool
	saved   []string
	actions []audit.Action
}

// manageService builds a service whose reads answer what the test names.
//
// row is the enrolment the person holds, and verify is what the password check
// answers. Every write records itself on the calls, so a test can prove both
// what ran and what did not.
func manageService(row Enrolment, find, verify error) (*Service, *manageCalls) {
	calls := &manageCalls{}
	log := logger.New()

	return NewService(Deps{
		VerifyPassword: func(context.Context, string, string, string) error {
			calls.proved = true
			return verify
		},
		Find: func(context.Context, string, string) (Enrolment, error) {
			calls.found = true
			return row, find
		},
		ClearFactor: func(context.Context, string, string) error {
			calls.cleared = true
			return nil
		},
		SaveRecoveryCodes: func(_ context.Context, _, _ string, digests []string) error {
			calls.saved = digests
			return nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			return fn(ctx)
		},
		Audit: audit.NewRecorder(func(_ context.Context, event audit.Event) error {
			calls.actions = append(calls.actions, audit.Action(event.Action))
			return nil
		}, log),
		Log: log,
	}), calls
}

// active is one person holding a live Second Factor.
func active() Enrolment {
	return Enrolment{
		TenantID:    statusTenantID,
		UserID:      statusUserID,
		ActivatedAt: time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC),
	}
}

func manager() Principal { return Principal{UserID: statusUserID} }

// TestAccountRemoveClearsTheFactorAndRecordsIt proves the whole removal: the
// hard delete of the secret and every Recovery Code, and the one audit event the
// activity feed renders.
func TestAccountRemoveClearsTheFactorAndRecordsIt(t *testing.T) {
	svc, calls := manageService(active(), nil, nil)

	if err := svc.AccountRemove(t.Context(), statusTenantID, manager(), "the-password"); err != nil {
		t.Fatalf("AccountRemove: %v", err)
	}
	if !calls.cleared {
		t.Error("the factor was not cleared")
	}
	if len(calls.actions) != 1 || calls.actions[0] != audit.ActionMFARemoved {
		t.Errorf("audit actions are %v, want [%s]", calls.actions, audit.ActionMFARemoved)
	}
}

// TestAccountReplaceRecoveryCodesIssuesAFreshSet proves that a replacement mints
// ten codes, shows them once, and stores a digest of each.
func TestAccountReplaceRecoveryCodesIssuesAFreshSet(t *testing.T) {
	svc, calls := manageService(active(), nil, nil)

	shown, err := svc.AccountReplaceRecoveryCodes(t.Context(), statusTenantID, manager(), "the-password")
	if err != nil {
		t.Fatalf("AccountReplaceRecoveryCodes: %v", err)
	}
	if len(shown) != recoveryCodeCount {
		t.Fatalf("%d codes were shown, want %d", len(shown), recoveryCodeCount)
	}
	if len(calls.saved) != recoveryCodeCount {
		t.Fatalf("%d digests were stored, want %d", len(calls.saved), recoveryCodeCount)
	}
	// The store holds digests and never a code. A stored plaintext would let a
	// database read sign the person in.
	for _, code := range shown {
		for _, digest := range calls.saved {
			if digest == code {
				t.Fatal("a recovery code was stored in the clear")
			}
		}
	}
	if calls.cleared {
		t.Error("a replacement removed the factor")
	}
	if len(calls.actions) != 1 || calls.actions[0] != audit.ActionMFARecoveryCodesRegenerated {
		t.Errorf("audit actions are %v, want [%s]", calls.actions,
			audit.ActionMFARecoveryCodesRegenerated)
	}
}

// TestTheWrongPasswordStopsEveryChange proves the guard that this whole slice
// exists for. A leaked access token alone must strip nothing.
//
// The refusal is carried back as it was given, so the mapper answers the slug
// the password change already answers.
func TestTheWrongPasswordStopsEveryChange(t *testing.T) {
	t.Run("removal", func(t *testing.T) {
		svc, calls := manageService(active(), nil, errWrongPassword)

		err := svc.AccountRemove(t.Context(), statusTenantID, manager(), "not-the-password")
		if !errors.Is(err, errWrongPassword) {
			t.Fatalf("error is %v, want %v", err, errWrongPassword)
		}
		assertNothingRan(t, calls)
	})

	t.Run("replacement", func(t *testing.T) {
		svc, calls := manageService(active(), nil, errWrongPassword)

		_, err := svc.AccountReplaceRecoveryCodes(t.Context(), statusTenantID, manager(), "not-the-password")
		if !errors.Is(err, errWrongPassword) {
			t.Fatalf("error is %v, want %v", err, errWrongPassword)
		}
		assertNothingRan(t, calls)
	})
}

// assertNothingRan proves that the password was checked before any other work,
// and that no other work followed a refusal.
func assertNothingRan(t *testing.T, calls *manageCalls) {
	t.Helper()

	if !calls.proved {
		t.Error("the password was not checked")
	}
	if calls.found {
		t.Error("the enrolment was read after a refused password")
	}
	if calls.cleared || calls.saved != nil || calls.actions != nil {
		t.Errorf("a refused password still wrote: %+v", calls)
	}
}

// TestAnAccountWithNoFactorHasNothingToChange proves that neither address acts
// on an account that holds none, so the activity feed never records a removal
// that removed nothing.
//
// A pending enrolment counts as no factor, the way it does everywhere else.
func TestAnAccountWithNoFactorHasNothingToChange(t *testing.T) {
	pending := Enrolment{TenantID: statusTenantID, UserID: statusUserID}

	tests := []struct {
		name string
		row  Enrolment
		find error
	}{
		{name: "no row at all", find: ErrNoEnrolment},
		{name: "a pending enrolment", row: pending},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, calls := manageService(tc.row, tc.find, nil)

			if err := svc.AccountRemove(t.Context(), statusTenantID, manager(), "the-password"); !errors.Is(err, ErrNoActiveFactor) {
				t.Errorf("removal answered %v, want %v", err, ErrNoActiveFactor)
			}
			if _, err := svc.AccountReplaceRecoveryCodes(t.Context(), statusTenantID, manager(), "the-password"); !errors.Is(err, ErrNoActiveFactor) {
				t.Errorf("replacement answered %v, want %v", err, ErrNoActiveFactor)
			}
			if calls.cleared || calls.saved != nil || calls.actions != nil {
				t.Errorf("an account with no factor was still written to: %+v", calls)
			}
		})
	}
}

// TestNeitherChangeLogsThePasswordOrACode reads every line the two methods
// write, at every level, on the path that succeeds and on the path that refuses.
//
// Two credentials must be absent. The password is one, and a Recovery Code is
// the other: a code on a log line signs the person in.
func TestNeitherChangeLogsThePasswordOrACode(t *testing.T) {
	const password = "correct-horse-battery-staple"

	log, logs := logger.NewObserved()

	svc, _ := manageService(active(), nil, nil)
	svc.log = log
	svc.deps.Log = log
	shown, err := svc.AccountReplaceRecoveryCodes(t.Context(), statusTenantID, manager(), password)
	if err != nil {
		t.Fatalf("AccountReplaceRecoveryCodes: %v", err)
	}
	if err := svc.AccountRemove(t.Context(), statusTenantID, manager(), password); err != nil {
		t.Fatalf("AccountRemove: %v", err)
	}

	refused, _ := manageService(active(), nil, errWrongPassword)
	refused.log = log
	refused.deps.Log = log
	_ = refused.AccountRemove(t.Context(), statusTenantID, manager(), password)

	secrets := append([]string{password}, shown...)
	for _, entry := range logs.All() {
		line := entry.Message + fmt.Sprint(entry.ContextMap())
		for _, secret := range secrets {
			if strings.Contains(line, secret) {
				t.Errorf("the log line %q carries a credential", line)
			}
		}
	}
}

// TestAccountRemoveTakesTheBindOfAPersonTheDirectoryOwns proves the seam the
// router composes: the disable of a Second Factor is proved by the real user
// domain, and a person who holds no local password hash re-proves with a bind.
//
// The service under test is the one the portal calls, and the proof it takes is
// the whole user.AccountService, so the two halves are measured together. A
// bcrypt compare on an empty hash would refuse here, which is what would close
// this route to every person the Directory owns.
//
// See docs/specs/0002-directory-sign-in.md.
func TestAccountRemoveTakesTheBindOfAPersonTheDirectoryOwns(t *testing.T) {
	log := logger.New()
	bound := ""

	account := user.NewAccountService(user.AccountDeps{
		// A person the Directory owns. The stored hash is empty, always.
		Credential: func(_ context.Context, tenantID, userID string) (user.User, error) {
			return user.User{ID: userID, TenantID: tenantID, PasswordHash: ""}, nil
		},
		ProveDirectory: func(_ context.Context, _, _, userID, _, plain string) error {
			bound = userID + ":" + plain
			return nil
		},
		Directory: func(context.Context, string, string) (string, string, error) {
			return "federation-one", "alice", nil
		},
		Log: log,
	})

	svc, calls := manageService(active(), nil, nil)
	svc.deps.VerifyPassword = func(ctx context.Context, tenantID, userID, plain string) error {
		calls.proved = true
		return account.VerifyPassword(ctx,
			user.Actor{TenantID: tenantID, UserID: userID}, plain)
	}

	if err := svc.AccountRemove(t.Context(), statusTenantID, manager(), "the-directory-password"); err != nil {
		t.Fatalf("AccountRemove: %v", err)
	}
	if want := statusUserID + ":the-directory-password"; bound != want {
		t.Errorf("the directory was asked %q, want %q", bound, want)
	}
	if !calls.cleared {
		t.Error("the factor was not cleared")
	}
}

// TestTheTwoRoutesCarryTheBrokenAccountOfADirectoryPerson proves the answer a
// person reads when no single directory entry proves them.
//
// The state is permanent. The person holds no live active Federation Link, or more
// than one, or the search of the directory matched none, or it matched two. No
// try of theirs changes any of that, so the sentinel must reach the caller whole
// and never collapse into the refusal a wrong password gets.
//
// Both destructive addresses of this module take the same proof, so both are
// measured here.
func TestTheTwoRoutesCarryTheBrokenAccountOfADirectoryPerson(t *testing.T) {
	prove := func(ctx context.Context, tenantID, userID, plain string) error {
		account := user.NewAccountService(user.AccountDeps{
			Credential: func(_ context.Context, tenantID, userID string) (user.User, error) {
				return user.User{ID: userID, TenantID: tenantID, PasswordHash: ""}, nil
			},
			ProveDirectory: func(context.Context, string, string, string, string, string) error {
				return user.ErrFederationNoAccount
			},
			Directory: func(context.Context, string, string) (string, string, error) {
				return "federation-one", "alice", nil
			},
			Log: logger.New(),
		})
		return account.VerifyPassword(ctx,
			user.Actor{TenantID: tenantID, UserID: userID}, plain)
	}

	t.Run("the second factor disable", func(t *testing.T) {
		svc, calls := manageService(active(), nil, nil)
		svc.deps.VerifyPassword = prove

		err := svc.AccountRemove(t.Context(), statusTenantID, manager(), "the-directory-password")
		if !errors.Is(err, user.ErrFederationNoAccount) {
			t.Fatalf("AccountRemove answered %v, want %v", err, user.ErrFederationNoAccount)
		}
		if calls.cleared {
			t.Error("the factor was cleared for an account no directory entry proves")
		}
	})

	t.Run("the recovery code regeneration", func(t *testing.T) {
		svc, calls := manageService(active(), nil, nil)
		svc.deps.VerifyPassword = prove

		_, err := svc.AccountReplaceRecoveryCodes(
			t.Context(), statusTenantID, manager(), "the-directory-password")
		if !errors.Is(err, user.ErrFederationNoAccount) {
			t.Fatalf("AccountReplaceRecoveryCodes answered %v, want %v", err, user.ErrFederationNoAccount)
		}
		if calls.saved != nil {
			t.Error("the codes were replaced for an account no directory entry proves")
		}
	})
}

// TestTheTwoRoutesBindForAClaimedPersonWhoKeepsAStaleHash proves the seam for
// the second person the Directory owns: the one a domain claim routes.
//
// Federation Resolution case 1 claims the email domain of a person the tenant
// already held. The claim writes no row, so password_hash keeps the value it
// held, and the bind signs the person in from that moment. A compare against the
// stale hash would refuse the password that signs them in, and both destructive
// addresses of this module would shut on them.
//
// See .scratch/directory-sign-in/issues/21.
func TestTheTwoRoutesBindForAClaimedPersonWhoKeepsAStaleHash(t *testing.T) {
	stale, err := crypto.HashPassword("the-retired-local-password")
	if err != nil {
		t.Fatalf("hash the retired local password: %v", err)
	}

	bound := ""
	account := user.NewAccountService(user.AccountDeps{
		// The person keeps every column they had, the hash included.
		Credential: func(_ context.Context, tenantID, userID string) (user.User, error) {
			return user.User{ID: userID, TenantID: tenantID, PasswordHash: stale}, nil
		},
		ProveDirectory: func(_ context.Context, _, _, _, _, plain string) error {
			bound = plain
			return nil
		},
		Directory: func(context.Context, string, string) (string, string, error) {
			return "federation-one", "alice", nil
		},
		Log: logger.New(),
	})
	prove := func(ctx context.Context, tenantID, userID, plain string) error {
		return account.VerifyPassword(ctx,
			user.Actor{TenantID: tenantID, UserID: userID}, plain)
	}

	t.Run("the second factor disable", func(t *testing.T) {
		bound = ""
		svc, calls := manageService(active(), nil, nil)
		svc.deps.VerifyPassword = prove

		if err := svc.AccountRemove(
			t.Context(), statusTenantID, manager(), "the-directory-password"); err != nil {
			t.Fatalf("AccountRemove: %v", err)
		}
		if bound != "the-directory-password" {
			t.Errorf("the directory was asked %q, want the password the person typed", bound)
		}
		if !calls.cleared {
			t.Error("the factor was not cleared")
		}
	})

	t.Run("the recovery code regeneration", func(t *testing.T) {
		bound = ""
		svc, calls := manageService(active(), nil, nil)
		svc.deps.VerifyPassword = prove

		if _, err := svc.AccountReplaceRecoveryCodes(
			t.Context(), statusTenantID, manager(), "the-directory-password"); err != nil {
			t.Fatalf("AccountReplaceRecoveryCodes: %v", err)
		}
		if bound != "the-directory-password" {
			t.Errorf("the directory was asked %q, want the password the person typed", bound)
		}
		if calls.saved == nil {
			t.Error("the codes were not replaced")
		}
	})
}
