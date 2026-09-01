package http

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/identityprovider"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/user"
)

const (
	personTenantID = "11111111-1111-1111-1111-111111111111"
	personOrgID    = "22222222-2222-2222-2222-222222222222"
)

// alice is the person one first bind creates, as the provider domain hands her
// over.
var alice = identityprovider.Person{
	TenantID: personTenantID, OrgID: personOrgID, Username: "alice",
	Email: "alice@corp.example", FirstName: "Alice", LastName: "Adams",
	DisplayName: "Alice Adams",
}

// TestDirectoryPerson covers the local rows one first bind writes.
//
// Four properties are the point, and each one is a rule of
// docs/specs/0002-directory-sign-in.md: the account is active, it is human, it
// holds no password hash, and it holds no role.
func TestDirectoryPerson(t *testing.T) {
	bdb := dbtest.Open(t, "httpdirectoryperson")
	log := logger.New()
	create := directoryPerson(user.NewRepository(bdb, log), organization.NewRepository(bdb, log))
	ctx := context.Background()

	userID, err := create(ctx, alice)
	if err != nil {
		t.Fatalf("create the person the directory proved: %v", err)
	}
	if userID == "" {
		t.Fatal("the create answered no person")
	}

	var row struct {
		OrgID    string
		Username string
		UserType int
		State    int
	}
	if err := bdb.NewRaw(
		`SELECT org_id, username, user_type, state FROM users WHERE id = ?`, userID,
	).Scan(ctx, &row.OrgID, &row.Username, &row.UserType, &row.State); err != nil {
		t.Fatalf("read the account: %v", err)
	}
	if row.State != user.StateActive {
		t.Errorf("the account is in state %d, want %d", row.State, user.StateActive)
	}
	// An invited person is written in state 5 with no hash, and SetPassword
	// requires an active account, so such a person could never set a first
	// password. This path must not ride on that defect.
	if row.UserType != user.TypeHuman {
		t.Errorf("the account is of type %d, want a human account", row.UserType)
	}
	if row.OrgID != personOrgID {
		t.Errorf("the account belongs to organization %q, want %q", row.OrgID, personOrgID)
	}
	if row.Username != "alice" {
		t.Errorf("the account is named %q, want the username the directory carried", row.Username)
	}

	var hash sql.NullString
	var email, first, last, display sql.NullString
	if err := bdb.NewRaw(
		`SELECT password_hash, email, first_name, last_name, display_name
		 FROM user_humans WHERE user_id = ?`, userID,
	).Scan(ctx, &hash, &email, &first, &last, &display); err != nil {
		t.Fatalf("read the person: %v", err)
	}
	// The directory owns the password. There is no local one, ever.
	if hash.Valid {
		t.Errorf("the person holds the password hash %q, want NULL", hash.String)
	}
	for what, got := range map[string]sql.NullString{
		"email": email, "first name": first, "last name": last, "display name": display,
	} {
		if !got.Valid || got.String == "" {
			t.Errorf("the person carries no %s, want the value the directory carried", what)
		}
	}

	var roles string
	if err := bdb.NewRaw(
		`SELECT roles FROM organization_members WHERE user_id = ?`, userID,
	).Scan(ctx, &roles); err != nil {
		t.Fatalf("read the membership: %v", err)
	}
	// An administrator grants the first role. Until then the person reaches
	// nothing in the console.
	if roles != "[]" {
		t.Errorf("the membership holds the roles %q, want none", roles)
	}
}

// TestDirectoryPersonRefusesATakenUsername covers a username another live
// account of the tenant already holds. The unique key refuses it, and the
// caller's transaction rolls the whole first bind back.
func TestDirectoryPersonRefusesATakenUsername(t *testing.T) {
	bdb := dbtest.Open(t, "httpdirectorytaken")
	log := logger.New()
	create := directoryPerson(user.NewRepository(bdb, log), organization.NewRepository(bdb, log))
	ctx := context.Background()

	if _, err := create(ctx, alice); err != nil {
		t.Fatalf("create the person the directory proved: %v", err)
	}
	if _, err := create(ctx, alice); !errors.Is(err, user.ErrDuplicateUsername) {
		t.Fatalf("err = %v, want ErrDuplicateUsername", err)
	}
}
