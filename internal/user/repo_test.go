package user

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	testTenantID  = "11111111-1111-1111-1111-111111111111"
	testOrgID     = "22222222-2222-2222-2222-222222222222"
	testUserID    = "33333333-3333-3333-3333-333333333333"
	lockedUserID  = "44444444-4444-4444-4444-444444444444"
	deletedUserID = "55555555-5555-5555-5555-555555555555"
	otherOrgID    = "66666666-6666-6666-6666-666666666666"
	machineUserID = "77777777-7777-7777-7777-777777777777"
	otherUserID   = "88888888-8888-8888-8888-888888888888"
)

// seed writes the admin bootstrap writes, plus the people the administrative
// reads must separate: one locked account, one soft-deleted account, one account
// of a second organization, and one machine account with no person behind it.
//
// The admin account also carries a second factor of each kind, so a reset has
// something to clear.
func seed(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	account := func(id, orgID, username string, userType, state int, deleted bool) {
		t.Helper()
		if deleted {
			exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state, deleted_at)
			      VALUES (?, ?, ?, ?, ?, ?, NOW(6))`, id, testTenantID, orgID, username, userType, state)
			return
		}
		exec(`INSERT INTO users (id, tenant_id, org_id, username, user_type, state)
		      VALUES (?, ?, ?, ?, ?, ?)`, id, testTenantID, orgID, username, userType, state)
	}

	person := func(id, orgID, username string, state int, deleted bool) {
		t.Helper()
		account(id, orgID, username, TypeHuman, state, deleted)
		exec(`INSERT INTO user_humans
		        (user_id, tenant_id, first_name, last_name, display_name, preferred_language,
		         email, is_email_verified, password_hash, failed_login_count, locked_until)
		      VALUES (?, ?, 'AlphaOmega', 'Admin', 'AlphaOmega Admin', 'en', ?, 1,
		              'a-bcrypt-hash', 3, NOW(3))`,
			id, testTenantID, username+"@acme.com")
	}

	person(testUserID, testOrgID, "admin", StateActive, false)
	person(lockedUserID, testOrgID, "locked", StateLocked, false)
	person(deletedUserID, testOrgID, "gone", StateActive, true)
	person(otherUserID, otherOrgID, "beta", StateActive, false)
	account(machineUserID, testOrgID, "robot", TypeMachine, StateActive, false)

	exec(`INSERT INTO user_totp (tenant_id, user_id, secret_encrypted, activated_at)
	      VALUES (?, ?, 'a-secret', NOW(3))`, testTenantID, testUserID)
	exec(`INSERT INTO user_totp_recovery_codes (tenant_id, user_id, code_hash)
	      VALUES (?, ?, REPEAT('a', 64))`, testTenantID, testUserID)
	exec(`INSERT INTO user_webauthn_credentials
	        (tenant_id, credential_id, user_id, rp_id, credential)
	      VALUES (?, 'a-credential-id', ?, 'acme.com', '{}')`, testTenantID, testUserID)
}

func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "user")
	seed(t, bdb)
	return NewRepository(bdb, logger.New()), context.Background()
}

// TestFindByID covers the read the admin front door makes, once the bearer guard
// names the caller. The existing reads take an identifier, and this one takes the
// id the token carries.
//
// An inactive account and a soft-deleted account never come back, so a person a
// tenant disabled cannot reach the console with a token that still has time left.
func TestFindByID(t *testing.T) {
	repo, ctx := testRepo(t)

	row, err := repo.FindByID(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the user: %v", err)
	}
	if row.ID != testUserID || row.TenantID != testTenantID || row.OrgID != testOrgID {
		t.Errorf("the user reads %+v, want the seeded admin", row)
	}
	if row.Username != "admin" {
		t.Errorf("the username is %q, want %q", row.Username, "admin")
	}
	if row.DisplayName != "AlphaOmega Admin" {
		t.Errorf("the display name is %q, want %q", row.DisplayName, "AlphaOmega Admin")
	}
	if row.Email != "admin@acme.com" {
		t.Errorf("the email is %q, want %q", row.Email, "admin@acme.com")
	}

	for _, id := range []string{lockedUserID, deletedUserID, "no-such-user"} {
		if _, err := repo.FindByID(ctx, testTenantID, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("reading user %s gives %v, want ErrNotFound", id, err)
		}
	}

	if _, err := repo.FindByID(ctx, "other-tenant", testUserID); !errors.Is(err, ErrNotFound) {
		t.Errorf("reading the user through another tenant gives %v, want ErrNotFound", err)
	}
}

// TestListPagesTheWholeTenant covers the admin list: the soft-deleted row
// excluded, every other state included, the person joined, the machine account
// without one, the window the pager asks for, the search, and the two filters
// the console sends.
func TestListPagesTheWholeTenant(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, total, err := repo.List(ctx, testTenantID, Query{Limit: 20})
	if err != nil {
		t.Fatalf("list the users: %v", err)
	}
	if total != 4 || len(rows) != 4 {
		t.Fatalf("the page holds %d of %d rows, want 4 of 4", len(rows), total)
	}

	byID := make(map[string]User, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	if byID[testUserID].Email != "admin@acme.com" || byID[testUserID].DisplayName != "AlphaOmega Admin" {
		t.Errorf("the admin reads %+v, want the person joined", byID[testUserID])
	}
	if !byID[testUserID].MFAEnabled {
		t.Error("the admin holds a TOTP factor and a passkey, want mfa_enabled")
	}
	if byID[machineUserID].Email != "" || byID[machineUserID].MFAEnabled {
		t.Errorf("the machine account reads %+v, want no person and no factor", byID[machineUserID])
	}
	if byID[lockedUserID].State != StateLocked {
		t.Errorf("the locked account reads state %d, want %d", byID[lockedUserID].State, StateLocked)
	}
	if _, ok := byID[deletedUserID]; ok {
		t.Error("the list holds the soft-deleted account, want it excluded")
	}
	if byID[testUserID].PasswordHash != "" {
		t.Error("the list projects the stored hash, want it never selected")
	}

	page, total, err := repo.List(ctx, testTenantID, Query{Sort: "username", Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("list the second page: %v", err)
	}
	if total != 4 {
		t.Errorf("the total reads %d, want 4 on every page", total)
	}
	if len(page) != 2 || page[0].Username != "locked" {
		t.Fatalf("the second page by username reads %+v, want it to start at locked", page)
	}

	found, _, err := repo.List(ctx, testTenantID, Query{Search: "rob", Limit: 20})
	if err != nil {
		t.Fatalf("search the users: %v", err)
	}
	if len(found) != 1 || found[0].ID != machineUserID {
		t.Fatalf("the search reads %+v, want the robot account", found)
	}

	mine, _, err := repo.List(ctx, testTenantID, Query{OrgID: otherOrgID, Limit: 20})
	if err != nil {
		t.Fatalf("filter the users by organization: %v", err)
	}
	if len(mine) != 1 || mine[0].ID != otherUserID {
		t.Fatalf("the filtered page reads %+v, want the account of %s", mine, otherOrgID)
	}

	humans, _, err := repo.List(ctx, testTenantID, Query{UserType: TypeHuman, State: StateActive, Limit: 20})
	if err != nil {
		t.Fatalf("filter the users by type and state: %v", err)
	}
	if len(humans) != 2 {
		t.Fatalf("the filtered page reads %+v, want the two active people", humans)
	}
}

// TestReadReadsAnyState covers the administrative read. It answers the account a
// tenant disabled, which FindByID above refuses, because an administrator must
// be able to read the account they are about to reactivate.
func TestReadReadsAnyState(t *testing.T) {
	repo, ctx := testRepo(t)

	row, err := repo.Read(ctx, testTenantID, lockedUserID)
	if err != nil {
		t.Fatalf("read the locked user: %v", err)
	}
	if row.State != StateLocked || row.Username != "locked" {
		t.Errorf("the account reads %+v, want the locked account", row)
	}

	for _, id := range []string{deletedUserID, "no-such-user"} {
		if _, err := repo.Read(ctx, testTenantID, id); !errors.Is(err, ErrNoSuchUser) {
			t.Errorf("reading user %s gives %v, want ErrNoSuchUser", id, err)
		}
	}
	if _, err := repo.Read(ctx, "other-tenant", testUserID); !errors.Is(err, ErrNoSuchUser) {
		t.Errorf("reading the user through another tenant gives %v, want ErrNoSuchUser", err)
	}
}

// TestWriteOneUser covers the writes: the insert of an account and the person
// behind it, the profile update, the state write, the reset token, and the soft
// delete.
func TestWriteOneUser(t *testing.T) {
	repo, ctx := testRepo(t)

	const newUserID = "99999999-9999-9999-9999-999999999999"
	now := time.Now().UTC()

	row := User{
		ID: newUserID, TenantID: testTenantID, OrgID: testOrgID, Username: "ada",
		UserType: TypeHuman, State: StateActive, CreatedAt: now,
	}
	if err := repo.Insert(ctx, row); err != nil {
		t.Fatalf("write the account: %v", err)
	}
	if err := repo.InsertHuman(ctx, Human{
		UserID: newUserID, TenantID: testTenantID, FirstName: "Ada", LastName: "Lovelace",
		DisplayName: "Ada Lovelace", Lang: "en", Email: "ada@acme.com", IsEmailVerified: true,
		PasswordHash: "another-bcrypt-hash", CreatedAt: now,
	}); err != nil {
		t.Fatalf("write the person: %v", err)
	}

	if err := repo.UpdateHuman(ctx, Human{
		UserID: newUserID, TenantID: testTenantID, FirstName: "Ada", LastName: "King",
		DisplayName: "Ada King", Lang: "th", Phone: "+66123456789",
	}); err != nil {
		t.Fatalf("update the person: %v", err)
	}
	if err := repo.SetState(ctx, testTenantID, newUserID, StateInactive); err != nil {
		t.Fatalf("set the state: %v", err)
	}

	read, err := repo.Read(ctx, testTenantID, newUserID)
	if err != nil {
		t.Fatalf("read the account: %v", err)
	}
	if read.DisplayName != "Ada King" || read.Lang != "th" || read.Phone != "+66123456789" {
		t.Errorf("the account reads %+v, want the updated profile", read)
	}
	if read.State != StateInactive {
		t.Errorf("the state reads %d, want %d", read.State, StateInactive)
	}
	if read.Email != "ada@acme.com" {
		t.Errorf("the email reads %q, want the stored one: an update never writes it", read.Email)
	}

	if err := repo.InsertToken(ctx, AccountToken{
		ID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", TenantID: testTenantID, UserID: newUserID,
		Purpose: PurposePasswordReset, TokenHash: "a-digest", ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("write the reset token: %v", err)
	}

	if err := repo.SoftDelete(ctx, testTenantID, newUserID); err != nil {
		t.Fatalf("delete the account: %v", err)
	}
	if _, err := repo.Read(ctx, testTenantID, newUserID); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("err = %v, want ErrNoSuchUser after the delete", err)
	}
	if err := repo.SoftDelete(ctx, testTenantID, newUserID); !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("err = %v, want ErrNoSuchUser on a second delete", err)
	}
}

// TestInsertRefusesADuplicateUsername covers the unique key on users. The answer
// names the collision, so the console reports it instead of a failure.
func TestInsertRefusesADuplicateUsername(t *testing.T) {
	repo, ctx := testRepo(t)

	err := repo.Insert(ctx, User{
		ID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", TenantID: testTenantID, OrgID: testOrgID,
		Username: "admin", UserType: TypeHuman, State: StateActive, CreatedAt: time.Now().UTC(),
	})
	if !errors.Is(err, ErrDuplicateUsername) {
		t.Fatalf("err = %v, want ErrDuplicateUsername", err)
	}
}

// TestUnlockClearsBothHalves covers the unlock. The three lockout columns and
// the account state are cleared together, because either half left behind keeps
// the person locked out.
func TestUnlockClearsBothHalves(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.Unlock(ctx, testTenantID, lockedUserID); err != nil {
		t.Fatalf("unlock the account: %v", err)
	}

	row, err := repo.Read(ctx, testTenantID, lockedUserID)
	if err != nil {
		t.Fatalf("read the account: %v", err)
	}
	if row.State != StateActive {
		t.Errorf("the state reads %d, want %d", row.State, StateActive)
	}

	var count int
	var lockedUntil sql.NullTime
	if err := repo.db.QueryRowContext(ctx,
		`SELECT failed_login_count, locked_until FROM user_humans WHERE tenant_id = ? AND user_id = ?`,
		testTenantID, lockedUserID).Scan(&count, &lockedUntil); err != nil {
		t.Fatalf("read the lockout: %v", err)
	}
	if count != 0 || lockedUntil.Valid {
		t.Errorf("the lockout reads %d and %v, want it cleared", count, lockedUntil)
	}
}

// TestUnlockKeepsADeactivatedAccountOff covers the state guard. Deactivate and
// the lockout both stop a sign-in, so an unlock that wrote the active state
// without a guard turned a deactivated account back on.
func TestUnlockKeepsADeactivatedAccountOff(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.SetState(ctx, testTenantID, lockedUserID, StateInactive); err != nil {
		t.Fatalf("deactivate the account: %v", err)
	}
	if err := repo.Unlock(ctx, testTenantID, lockedUserID); err != nil {
		t.Fatalf("unlock the account: %v", err)
	}

	row, err := repo.Read(ctx, testTenantID, lockedUserID)
	if err != nil {
		t.Fatalf("read the account: %v", err)
	}
	if row.State != StateInactive {
		t.Errorf("the state reads %d, want %d", row.State, StateInactive)
	}

	// The lockout still clears. Only the state is guarded.
	var count int
	var lockedUntil sql.NullTime
	if err := repo.db.QueryRowContext(ctx,
		`SELECT failed_login_count, locked_until FROM user_humans WHERE tenant_id = ? AND user_id = ?`,
		testTenantID, lockedUserID).Scan(&count, &lockedUntil); err != nil {
		t.Fatalf("read the lockout: %v", err)
	}
	if count != 0 || lockedUntil.Valid {
		t.Errorf("the lockout reads %d and %v, want it cleared", count, lockedUntil)
	}
}

// TestClearPasskeysRemovesEveryPasskey covers this domain's half of a
// second-factor reset. The TOTP half belongs to internal/totp and is proved
// there.
func TestClearPasskeysRemovesEveryPasskey(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.ClearPasskeys(ctx, testTenantID, testUserID); err != nil {
		t.Fatalf("clear the passkeys: %v", err)
	}

	var passkeys int
	if err := repo.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_webauthn_credentials
		 WHERE tenant_id = ? AND user_id = ? AND deleted_at IS NULL`,
		testTenantID, testUserID).Scan(&passkeys); err != nil {
		t.Fatalf("count the passkeys: %v", err)
	}
	if passkeys != 0 {
		t.Errorf("the account holds %d live passkeys, want them marked", passkeys)
	}

	// The TOTP factor is untouched, so the account still reads as protected.
	// Only the composed reset in the router clears both halves.
	row, err := repo.Read(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the account: %v", err)
	}
	if !row.MFAEnabled {
		t.Error("the account reads as unprotected, want the TOTP factor left alone")
	}

	// A person with no passkey left is the normal outcome, so a second reset is
	// not an error.
	if err := repo.ClearPasskeys(ctx, testTenantID, testUserID); err != nil {
		t.Errorf("a second reset gives %v, want no error", err)
	}
}

// TestHoldsIdentifier is the second read Provider Resolution makes. It reads
// whether the tenant holds an account at all, so it filters neither the state,
// nor the soft delete, nor the type of the account.
//
// Every person below reads as absent through FindByIdentifier, which filters
// state = active inside the query. A sign-in that took that for "nobody" would
// resolve a directory and let the first bind write a brand-new row over them.
func TestHoldsIdentifier(t *testing.T) {
	repo, ctx := testRepo(t)

	held := []string{
		"admin",          // the active person, by username
		"admin@acme.com", // the same person, by email
		"locked",         // a locked account
		"gone",           // a soft-deleted account
		"gone@acme.com",  // the same account, by email
		"robot",          // a machine account, which holds the username too
	}
	for _, identifier := range held {
		got, err := repo.HoldsIdentifier(ctx, testTenantID, identifier)
		if err != nil {
			t.Fatalf("read whether the tenant holds %q: %v", identifier, err)
		}
		if !got {
			t.Errorf("%q reads as absent, want the account the tenant holds", identifier)
		}
	}

	// Nobody holds these. The second one proves the tenant scope: another
	// tenant's people never make this one's identifier look taken.
	for _, absent := range []string{"nobody", "nobody@acme.com"} {
		got, err := repo.HoldsIdentifier(ctx, "99999999-9999-9999-9999-999999999999", absent)
		if err != nil {
			t.Fatalf("read whether the tenant holds %q: %v", absent, err)
		}
		if got {
			t.Errorf("%q reads as held, want nothing", absent)
		}
	}
	got, err := repo.HoldsIdentifier(ctx, "99999999-9999-9999-9999-999999999999", "admin")
	if err != nil {
		t.Fatalf("read whether another tenant holds the identifier: %v", err)
	}
	if got {
		t.Error("another tenant reads the identifier as held, want the tenant scope kept")
	}
}
