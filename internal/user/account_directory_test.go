package user

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zapcore"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The portal re-proof of a person the Directory owns.
//
// Two people are one case here. The person the first bind created holds no local
// password hash. The person a domain claim routes keeps the hash the claim
// retired, because the claim writes no row. Federation Resolution answers for
// both, and the stored hash answers for neither.
//
// Four portal routes ask them for a password: the TOTP disable, the
// recovery-code regeneration, the Passkey removal, and the password change. The
// first three prove the credential through VerifyPassword, and the fourth
// refuses outright, because there is no local password to replace.
//
// The empty hash never reaches bcrypt. It would trip crypto.ErrMalformedHash and
// write an error line that says the stored hash cannot be read, which is a false
// alarm on every attempt. Each test below reads the log to prove that no such
// line was written.

// directoryDeps is what one re-proof test varies.
type directoryDeps struct {
	// hash is the stored password of the account. An empty hash is what the
	// person the first bind created holds.
	hash string
	// claimed is what Federation Resolution answers for the person. A domain claim
	// routes a person the tenant already held, and it writes no row, so such a
	// person is claimed and keeps the hash the claim retired.
	claimed bool
	// proveErr is what the directory answers.
	proveErr error
}

// What one re-proof test observed.
var (
	provedPasswords []string
	provedUsers     []string
)

// directoryService builds an account service whose credential read answers the
// hash the test names, and whose bind answers the error the test names.
func directoryService(t *testing.T, d directoryDeps) *AccountService {
	t.Helper()
	var log logger.Logger
	log, logs = logger.NewObserved()
	events, rolledBack = nil, false
	writtenHashes, revokedExcepts = nil, nil
	provedPasswords, provedUsers = nil, nil

	record := func(_ context.Context, e audit.Event) error {
		events = append(events, e)
		return nil
	}

	return NewAccountService(AccountDeps{
		Credential: func(_ context.Context, tenantID, userID string) (User, error) {
			return User{ID: userID, TenantID: tenantID, OrgID: testOrgID, PasswordHash: d.hash}, nil
		},
		SetPassword: func(_ context.Context, _, _, hash string) error {
			writtenHashes = append(writtenHashes, hash)
			return nil
		},
		CheckPassword: func(context.Context, string, string, string) error { return nil },
		RevokeOthers: func(_ context.Context, _ Actor, exceptID string) error {
			revokedExcepts = append(revokedExcepts, exceptID)
			return nil
		},
		ProveDirectory: func(_ context.Context, _, _, userID, _, plain string) error {
			provedUsers = append(provedUsers, userID)
			provedPasswords = append(provedPasswords, plain)
			return d.proveErr
		},
		Directory: func(context.Context, string, string) (string, string, error) {
			if d.claimed {
				return "idp-one", "alice", nil
			}
			return "", "", nil
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

// localHash is the stored password of a person the local compare signs in.
func localHash(t *testing.T) string {
	t.Helper()
	hash, err := crypto.HashPassword(currentPassword)
	if err != nil {
		t.Fatalf("hash the current password: %v", err)
	}
	return hash
}

// noErrorLine fails the test when the service wrote an error line. An empty hash
// is what a person the Directory owns stores, so it is never a defect.
func noErrorLine(t *testing.T) {
	t.Helper()
	if got := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); got != 0 {
		for _, entry := range logs.All() {
			t.Logf("%s: %s", entry.Level, entry.Message)
		}
		t.Errorf("the service wrote %d error lines, want 0", got)
	}
}

// TestVerifyPasswordBindsForAPersonTheDirectoryOwns proves the re-proof the
// three destructive portal routes run. A person with no stored hash is proved by
// the bind, with the password they typed, and the answer holds.
func TestVerifyPasswordBindsForAPersonTheDirectoryOwns(t *testing.T) {
	svc := directoryService(t, directoryDeps{})

	if err := svc.VerifyPassword(t.Context(), person, currentPassword); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}

	if len(provedPasswords) != 1 || provedPasswords[0] != currentPassword {
		t.Errorf("the directory proved %d passwords, want the one the person typed", len(provedPasswords))
	}
	if len(provedUsers) != 1 || provedUsers[0] != testUserID {
		t.Errorf("the directory proved %v, want user %s", provedUsers, testUserID)
	}
	noErrorLine(t)
}

// TestVerifyPasswordRefusesAWrongDirectoryPassword proves that a bind the
// directory refused answers the one sentinel a wrong password answers.
func TestVerifyPasswordRefusesAWrongDirectoryPassword(t *testing.T) {
	svc := directoryService(t, directoryDeps{proveErr: ErrBadPassword})

	err := svc.VerifyPassword(t.Context(), person, "the-wrong-one")
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("VerifyPassword answered %v, want %v", err, ErrBadPassword)
	}
	noErrorLine(t)
}

// TestVerifyPasswordAnswersADirectoryOutageAsItself proves the rule a person
// depends on: a directory that could not answer never reads as a wrong password.
// The person is told to try again, and not to hunt for a password that is right.
func TestVerifyPasswordAnswersADirectoryOutageAsItself(t *testing.T) {
	svc := directoryService(t, directoryDeps{proveErr: ErrFederationUnavailable})

	err := svc.VerifyPassword(t.Context(), person, currentPassword)
	if !errors.Is(err, ErrFederationUnavailable) {
		t.Fatalf("VerifyPassword answered %v, want %v", err, ErrFederationUnavailable)
	}
	if errors.Is(err, ErrBadPassword) {
		t.Error("a directory outage answered a wrong password, want the outage")
	}
}

// TestVerifyPasswordAnswersABrokenDirectoryAccountAsItself proves the second
// rule a person depends on: a state no try of theirs can clear is never told to
// try again.
//
// A person whom no single directory entry proves holds a broken account: no live
// active Identity Link, or more than one, or a search that matched none, or a
// search that matched two. Only an administrator can mend it, so the sentinel
// travels back whole, and never as a wrong password or a directory outage.
func TestVerifyPasswordAnswersABrokenDirectoryAccountAsItself(t *testing.T) {
	svc := directoryService(t, directoryDeps{proveErr: ErrFederationNoAccount})

	err := svc.VerifyPassword(t.Context(), person, currentPassword)
	if !errors.Is(err, ErrFederationNoAccount) {
		t.Fatalf("VerifyPassword answered %v, want %v", err, ErrFederationNoAccount)
	}
	if errors.Is(err, ErrBadPassword) {
		t.Error("a broken directory account answered a wrong password, want the broken account")
	}
	if errors.Is(err, ErrFederationUnavailable) {
		t.Error("a broken directory account answered a directory outage, want the broken account")
	}
}

// TestVerifyPasswordKeepsTheLocalCompare proves that nothing changed for a
// person who holds a local password. The bcrypt compare runs, and no bind does.
func TestVerifyPasswordKeepsTheLocalCompare(t *testing.T) {
	svc := directoryService(t, directoryDeps{hash: localHash(t)})

	if err := svc.VerifyPassword(t.Context(), person, currentPassword); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if len(provedPasswords) != 0 {
		t.Errorf("the directory was asked %d times, want 0 for a local password", len(provedPasswords))
	}

	if err := svc.VerifyPassword(t.Context(), person, "the-wrong-one"); !errors.Is(err, ErrBadPassword) {
		t.Errorf("a wrong local password answered %v, want %v", err, ErrBadPassword)
	}
}

// TestChangePasswordRefusesAPersonTheDirectoryOwns proves the fourth portal
// route. There is no local password to replace, so the change refuses before it
// asks for a proof, writes nothing, and asks no directory.
func TestChangePasswordRefusesAPersonTheDirectoryOwns(t *testing.T) {
	svc := directoryService(t, directoryDeps{})

	err := svc.ChangePassword(t.Context(), person, passwordBody(), "a-session-id")
	if !errors.Is(err, ErrPasswordNotLocal) {
		t.Fatalf("ChangePassword answered %v, want %v", err, ErrPasswordNotLocal)
	}
	if len(writtenHashes) != 0 {
		t.Errorf("the service wrote %d hashes, want 0", len(writtenHashes))
	}
	if len(provedPasswords) != 0 {
		t.Errorf("the directory was asked %d times, want 0", len(provedPasswords))
	}
	if len(events) != 0 {
		t.Errorf("the service recorded %d events, want 0", len(events))
	}
	noErrorLine(t)
}

// TestVerifyPasswordBindsForAClaimedPersonWhoKeepsAStaleHash proves the fix of
// ticket 21. The three destructive portal routes reach it through VerifyPassword.
//
// Federation Resolution case 1 routes a person whose email domain a live active
// provider claims. The claim writes no row, so the person keeps every column
// they had, and password_hash keeps the value it held. The bind signs them in
// from that moment, so the bind is what re-proves them, and a compare against
// the stale hash would refuse the password that signs them in.
func TestVerifyPasswordBindsForAClaimedPersonWhoKeepsAStaleHash(t *testing.T) {
	svc := directoryService(t, directoryDeps{hash: localHash(t), claimed: true})

	if err := svc.VerifyPassword(t.Context(), person, "the-directory-password"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}

	if len(provedPasswords) != 1 || provedPasswords[0] != "the-directory-password" {
		t.Errorf("the directory proved %d passwords, want the one the person typed", len(provedPasswords))
	}
	noErrorLine(t)
}

// TestVerifyPasswordRefusesTheStaleHashOfAClaimedPerson proves the other half of
// the same rule. The password that once signed the person in locally no longer
// does, so the directory decides it, and a directory that refuses it refuses the
// proof.
func TestVerifyPasswordRefusesTheStaleHashOfAClaimedPerson(t *testing.T) {
	svc := directoryService(t, directoryDeps{
		hash: localHash(t), claimed: true, proveErr: ErrBadPassword,
	})

	err := svc.VerifyPassword(t.Context(), person, currentPassword)
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("VerifyPassword answered %v, want %v", err, ErrBadPassword)
	}
	if len(provedPasswords) != 1 {
		t.Errorf("the directory was asked %d times, want 1 for a claimed person", len(provedPasswords))
	}
}

// TestTheTwoRefusalsHoldForAClaimedPersonWithAStaleHash proves that the stale
// hash changes neither answer a broken directory gives.
func TestTheTwoRefusalsHoldForAClaimedPersonWithAStaleHash(t *testing.T) {
	for _, want := range []error{ErrFederationUnavailable, ErrFederationNoAccount} {
		svc := directoryService(t, directoryDeps{
			hash: localHash(t), claimed: true, proveErr: want,
		})

		err := svc.VerifyPassword(t.Context(), person, currentPassword)
		if !errors.Is(err, want) {
			t.Errorf("VerifyPassword answered %v, want %v", err, want)
		}
		if errors.Is(err, ErrBadPassword) {
			t.Errorf("%v answered a wrong password, want itself", want)
		}
	}
}

// TestChangePasswordRefusesAClaimedPersonWhoKeepsAStaleHash proves the fourth
// portal route. The column holds a hash, and it is not a password to replace: a
// write to it would leave the person a password no sign-in ever reads.
func TestChangePasswordRefusesAClaimedPersonWhoKeepsAStaleHash(t *testing.T) {
	svc := directoryService(t, directoryDeps{hash: localHash(t), claimed: true})

	err := svc.ChangePassword(t.Context(), person, passwordBody(), "a-session-id")
	if !errors.Is(err, ErrPasswordNotLocal) {
		t.Fatalf("ChangePassword answered %v, want %v", err, ErrPasswordNotLocal)
	}
	if len(writtenHashes) != 0 {
		t.Errorf("the service wrote %d hashes, want 0", len(writtenHashes))
	}
	if len(provedPasswords) != 0 {
		t.Errorf("the directory was asked %d times, want 0", len(provedPasswords))
	}
	if len(events) != 0 {
		t.Errorf("the service recorded %d events, want 0", len(events))
	}
	noErrorLine(t)
}

// TestPasswordLocalSaysWhichCredentialThePersonHolds proves the read the portal
// takes to hide the password change. It answers a boolean and never the hash.
func TestPasswordLocalSaysWhichCredentialThePersonHolds(t *testing.T) {
	owned := directoryService(t, directoryDeps{})
	local, err := owned.PasswordLocal(t.Context(), person)
	if err != nil {
		t.Fatalf("PasswordLocal: %v", err)
	}
	if local {
		t.Error("a person the Directory owns reads a local password, want none")
	}

	held := directoryService(t, directoryDeps{hash: localHash(t)})
	local, err = held.PasswordLocal(t.Context(), person)
	if err != nil {
		t.Fatalf("PasswordLocal: %v", err)
	}
	if !local {
		t.Error("a person who holds a local password reads none, want one")
	}

	// The person a domain claim routes. The column still holds the hash the
	// claim retired, and the portal must hide the control all the same.
	claimed := directoryService(t, directoryDeps{hash: localHash(t), claimed: true})
	local, err = claimed.PasswordLocal(t.Context(), person)
	if err != nil {
		t.Fatalf("PasswordLocal: %v", err)
	}
	if local {
		t.Error("a person a domain claim routes reads a local password, want none")
	}
}

// TestABrokenResolverReadStopsThePasswordProof proves the rule the sign-in path
// holds: a read that broke stops the request. A proof that fell back to the
// local compare would prove a person against the hash a domain claim retired.
func TestABrokenResolverReadStopsThePasswordProof(t *testing.T) {
	broken := errors.New("the read of the identity providers failed")
	svc := directoryService(t, directoryDeps{hash: localHash(t)})
	svc.deps.Directory = func(context.Context, string, string) (string, string, error) {
		return "", "", broken
	}

	if err := svc.VerifyPassword(t.Context(), person, currentPassword); !errors.Is(err, broken) {
		t.Errorf("VerifyPassword answered %v, want %v", err, broken)
	}
	if err := svc.ChangePassword(t.Context(), person, passwordBody(), "a-session-id"); !errors.Is(err, broken) {
		t.Errorf("ChangePassword answered %v, want %v", err, broken)
	}
	if _, err := svc.PasswordLocal(t.Context(), person); !errors.Is(err, broken) {
		t.Errorf("PasswordLocal answered %v, want %v", err, broken)
	}
	if len(writtenHashes) != 0 {
		t.Errorf("the service wrote %d hashes, want 0", len(writtenHashes))
	}
}
