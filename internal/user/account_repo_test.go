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
	if read.Email != "admin@acme.com" || read.PasswordHash != "a-bcrypt-hash" {
		t.Errorf("the account reads %+v, want the stored email and hash left alone", read)
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
