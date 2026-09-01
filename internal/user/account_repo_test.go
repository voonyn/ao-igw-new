package user

import (
	"errors"
	"testing"
)

// TestUpdateProfile covers the one write the self-service account API makes.
//
// Three rules are proved together. The write reaches the four identity columns
// and leaves the contact and credential columns alone. It reaches a live account
// only, so a token that outlived the account it names writes nothing. It reaches
// one tenant only.
func TestUpdateProfile(t *testing.T) {
	repo, ctx := testRepo(t)

	err := repo.UpdateProfile(ctx, Human{
		UserID: testUserID, TenantID: testTenantID, FirstName: "Ada", LastName: "King",
		DisplayName: "Ada King", Lang: "th",
	})
	if err != nil {
		t.Fatalf("update the profile: %v", err)
	}

	read, err := repo.Read(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the account: %v", err)
	}
	if read.FirstName != "Ada" || read.LastName != "King" ||
		read.DisplayName != "Ada King" || read.Lang != "th" {
		t.Errorf("the account reads %+v, want the four updated identity fields", read)
	}
	if read.Email != "admin@acme.com" {
		t.Errorf("the account reads %+v, want the stored email left alone", read)
	}

	// The hash comes from FindCredential, which is the one read that projects it.
	// An administrative read never carries a credential, so Read leaves the field
	// empty whatever the row holds.
	cred, err := repo.FindCredential(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the credential: %v", err)
	}
	if cred.PasswordHash != "a-bcrypt-hash" {
		t.Errorf("the account holds the hash %q, want the stored one left alone", cred.PasswordHash)
	}

	// A soft-deleted account. The bearer guard reads no store, so a token of one
	// still verifies, and the predicate on users is what refuses the write.
	err = repo.UpdateProfile(ctx, Human{UserID: deletedUserID, TenantID: testTenantID, FirstName: "Ada"})
	if !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("err = %v, want ErrNoSuchUser for a soft-deleted account", err)
	}

	// An account the lockout policy stopped. It cannot sign in, so it cannot
	// write either.
	err = repo.UpdateProfile(ctx, Human{UserID: lockedUserID, TenantID: testTenantID, FirstName: "Ada"})
	if !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("err = %v, want ErrNoSuchUser for a locked account", err)
	}

	// The same account id under another tenant.
	err = repo.UpdateProfile(ctx, Human{UserID: testUserID, TenantID: testOrgID, FirstName: "Ada"})
	if !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("err = %v, want ErrNoSuchUser for another tenant", err)
	}
}

// TestFindCredential covers the read one password change makes. It answers the
// organization of the person and the hash of the password they hold.
//
// The predicate is what refuses an account behind a token that outlived it. A
// locked account, a soft-deleted account, a machine account, and another tenant
// all answer ErrNotFound, so a caller cannot tell which of them is the case.
func TestFindCredential(t *testing.T) {
	repo, ctx := testRepo(t)

	row, err := repo.FindCredential(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the credential: %v", err)
	}
	if row.OrgID != testOrgID || row.PasswordHash != "a-bcrypt-hash" {
		t.Errorf("the read answers %+v, want the organization and the stored hash", row)
	}

	for name, userID := range map[string]string{
		"a locked account":       lockedUserID,
		"a soft-deleted account": deletedUserID,
		"a machine account":      machineUserID,
	} {
		if _, err := repo.FindCredential(ctx, testTenantID, userID); !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v for %s, want ErrNotFound", err, name)
		}
	}

	if _, err := repo.FindCredential(ctx, testOrgID, testUserID); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v for another tenant, want ErrNotFound", err)
	}
}

// TestSetPassword covers the write one password change makes. It replaces the
// hash, stamps the change, and clears the flag that forces a change at the next
// sign-in.
//
// It reaches a live account only, for the reason UpdateProfile does: the bearer
// guard reads no store, so the query is what refuses a token of an account that
// can no longer sign in.
func TestSetPassword(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.SetPassword(ctx, testTenantID, testUserID, "a-new-bcrypt-hash"); err != nil {
		t.Fatalf("set the password: %v", err)
	}

	read, err := repo.Read(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the account: %v", err)
	}
	// The hash comes from FindCredential. Read projects no credential.
	cred, err := repo.FindCredential(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the credential: %v", err)
	}
	if cred.PasswordHash != "a-new-bcrypt-hash" {
		t.Errorf("the account holds the hash %q, want the new one", cred.PasswordHash)
	}
	if read.PasswordChangedAt.IsZero() {
		t.Error("the account carries no password_changed_at, want the moment of the change")
	}
	if read.PasswordChangeReq {
		t.Error("the account still forces a change at the next sign-in, want the flag cleared")
	}
	if read.Email != "admin@acme.com" || read.DisplayName != "AlphaOmega Admin" {
		t.Errorf("the account reads %+v, want the identity fields left alone", read)
	}

	err = repo.SetPassword(ctx, testTenantID, deletedUserID, "a-new-bcrypt-hash")
	if !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("err = %v for a soft-deleted account, want ErrNoSuchUser", err)
	}
	err = repo.SetPassword(ctx, testTenantID, lockedUserID, "a-new-bcrypt-hash")
	if !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("err = %v for a locked account, want ErrNoSuchUser", err)
	}
	err = repo.SetPassword(ctx, testOrgID, testUserID, "a-new-bcrypt-hash")
	if !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("err = %v for another tenant, want ErrNoSuchUser", err)
	}
}

// TestHasPassword covers the read behind the second guard rail of
// docs/specs/0002-directory-sign-in.md.
//
// The question is what the row holds, not who can sign in, so the read filters
// neither the state nor the lock. A person the directory owns holds a NULL
// password_hash, and the removal of their last Identity Link locks them out for
// ever whatever state the account is in.
func TestHasPassword(t *testing.T) {
	repo, ctx := testRepo(t)

	held, err := repo.HasPassword(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read whether the person holds a password: %v", err)
	}
	if !held {
		t.Error("the seeded person reads no password, want the stored hash")
	}

	// A locked account still holds the hash it holds.
	held, err = repo.HasPassword(ctx, testTenantID, lockedUserID)
	if err != nil {
		t.Fatalf("read whether the locked person holds a password: %v", err)
	}
	if !held {
		t.Error("the locked person reads no password, want the stored hash")
	}

	// The shape a first bind writes: an active person with a NULL hash.
	if _, err := repo.db.ExecContext(ctx,
		`UPDATE user_humans SET password_hash = NULL WHERE user_id = ?`, testUserID); err != nil {
		t.Fatalf("clear the stored hash: %v", err)
	}
	held, err = repo.HasPassword(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read whether the person holds a password: %v", err)
	}
	if held {
		t.Error("a NULL hash reads as a password, want none")
	}

	// A machine account holds no user_humans row, and a soft-deleted account is
	// no longer live. Neither holds a password.
	for what, userID := range map[string]string{
		"a machine account":     machineUserID,
		"a soft-deleted person": deletedUserID,
	} {
		held, err := repo.HasPassword(ctx, testTenantID, userID)
		if err != nil {
			t.Fatalf("read whether %s holds a password: %v", what, err)
		}
		if held {
			t.Errorf("%s reads a password, want none", what)
		}
	}
}
