package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/di"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

var testCreated = time.Date(2026, 8, 16, 9, 0, 0, 0, time.UTC)

// admin is the person every admin service test acts as.
var admin = Actor{TenantID: testTenantID, UserID: testUserID, IP: "203.0.113.7", UserAgent: "a-browser"}

// TestAdminListRefusesPersonWithoutAdminRole refuses a person who holds none of
// the four administrative roles. The bearer guard admits any token minted for
// the admin resource, so the roles decide here.
func TestAdminListRefusesPersonWithoutAdminRole(t *testing.T) {
	svc := adminService(t, adminDeps{})

	_, _, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if !errors.Is(err, ErrNoAdminRole) {
		t.Fatalf("err = %v, want ErrNoAdminRole", err)
	}
}

// TestAdminListReadsTheWholeTenant reads the page a tenant manager reads, with
// the person behind each account.
func TestAdminListReadsTheWholeTenant(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows: []User{
			{ID: testUserID, TenantID: testTenantID, OrgID: testOrgID, Username: "ada",
				UserType: TypeHuman, State: StateActive, CreatedAt: testCreated,
				DisplayName: "Ada Lovelace", Email: "ada@example.com", IsEmailVerified: true,
				MFAEnabled: true},
			{ID: lockedUserID, TenantID: testTenantID, OrgID: otherOrgID, Username: "grace",
				UserType: TypeHuman, State: StateLocked, CreatedAt: testCreated},
		},
	})

	views, total, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(views) != 2 {
		t.Fatalf("the page holds %d of %d rows, want 2 of 2", len(views), total)
	}
	if views[0].Username != "ada" || views[0].OrgID != testOrgID || !views[0].MFAEnabled {
		t.Errorf("the first view reads %+v, want the seeded person of %s", views[0], testOrgID)
	}
	if views[0].Human == nil || views[0].Human.Email != "ada@example.com" {
		t.Fatalf("the first view carries %+v, want the person behind the account", views[0].Human)
	}
	if views[1].State != StateLocked {
		t.Errorf("the second view reads state %d, want the locked account", views[1].State)
	}
}

// TestAdminListReadsEveryStateAndNeverTheHash proves two rules at once. The
// console filters by state itself, so every state comes back, and the stored
// bcrypt hash never leaves this package.
func TestAdminListReadsEveryStateAndNeverTheHash(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMAdmin},
		rows: []User{{ID: testUserID, TenantID: testTenantID, OrgID: testOrgID, Username: "ada",
			UserType: TypeHuman, State: StateInactive, PasswordHash: "a-bcrypt-hash"}},
	})

	views, _, err := svc.List(context.Background(), admin, Query{Limit: 20})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(views) != 1 || views[0].State != StateInactive {
		t.Fatalf("the page reads %+v, want the inactive account", views)
	}
	if strings.Contains(fmt.Sprintf("%+v", views), "a-bcrypt-hash") {
		t.Fatalf("the page reads %+v, want no stored hash in it", views)
	}
}

// TestAdminFindReportsAMiss answers ErrNoSuchUser for an id nobody holds. It is
// not ErrNotFound: that sentinel answers 401 for the caller's own identity, and
// this one answers 404 for a row an administrator named.
func TestAdminFindReportsAMiss(t *testing.T) {
	svc := adminService(t, adminDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	_, err := svc.Find(context.Background(), admin, deletedUserID)
	if !errors.Is(err, ErrNoSuchUser) {
		t.Fatalf("err = %v, want ErrNoSuchUser", err)
	}
}

// TestAuthorizeReadAdmitsAnAdministratorOfAnotherOrganization proves the two
// exported gates are apart.
//
// A person who holds ORG_USER_MANAGER in one organization reads the account
// record of somebody in another organization today, so the read gate admits
// them. The console Passkey list runs this gate for that reason.
func TestAuthorizeReadAdmitsAnAdministratorOfAnotherOrganization(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows: []User{{ID: testUserID, TenantID: testTenantID, OrgID: testOrgID,
			Username: "ada", UserType: TypeHuman, State: StateActive}},
	})

	if err := svc.AuthorizeRead(context.Background(), admin); err != nil {
		t.Fatalf("the read gate answered %v, want the administrator admitted", err)
	}
}

// TestAuthorizeWriteRefusesAnAdministratorOfAnotherOrganization is the other
// half. The same person the read gate admitted is refused the write, because the
// write gate narrows to the organization of the account.
func TestAuthorizeWriteRefusesAnAdministratorOfAnotherOrganization(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows: []User{{ID: testUserID, TenantID: testTenantID, OrgID: testOrgID,
			Username: "ada", UserType: TypeHuman, State: StateActive}},
	})

	err := svc.AuthorizeWrite(context.Background(), admin, testUserID, "revoke a passkey of a user")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("the write gate answered %v, want ErrForbidden", err)
	}
}

// TestAuthorizeReadRefusesAPersonWithoutAdminRole proves the read gate is a gate.
// A person who administers nothing is refused the list as well as the revoke.
func TestAuthorizeReadRefusesAPersonWithoutAdminRole(t *testing.T) {
	svc := adminService(t, adminDeps{})

	if err := svc.AuthorizeRead(context.Background(), admin); !errors.Is(err, ErrNoAdminRole) {
		t.Fatalf("the read gate answered %v, want ErrNoAdminRole", err)
	}
}

// createBody is the body a create carries in the tests below.
func createBody() CreateBody {
	return CreateBody{
		OrgID:       testOrgID,
		Username:    "ada",
		Email:       "ada@example.com",
		FirstName:   "Ada",
		LastName:    "Lovelace",
		DisplayName: "Ada Lovelace",
		Lang:        "en",
		Password:    "a-strong-password",
	}
}

// TestCreateRefusesAPasswordThePolicyRefuses proves that the policy an
// administrator sets in the console governs the administrative create too. The
// refusal is the one a person reads when they change their own password, and it
// names no rule.
//
// The check runs before anything is written, so a refused create leaves no
// account, no person, no membership, and no event.
func TestCreateRefusesAPasswordThePolicyRefuses(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships:  []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		weakPassword: true,
	})

	_, err := svc.Create(context.Background(), admin, createBody())
	if !errors.Is(err, policyRefusal) {
		t.Fatalf("err = %v, want the refusal of the check", err)
	}
	if len(writtenUsers) != 0 || len(writtenHumans) != 0 || len(writtenMembers) != 0 {
		t.Errorf("the refused create wrote %d accounts, %d people and %d memberships, want none",
			len(writtenUsers), len(writtenHumans), len(writtenMembers))
	}
	if len(events) != 0 {
		t.Errorf("the refused create recorded %d events, want none", len(events))
	}
}

// TestCreateWritesTheAccountAndItsMembership is the whole create rule. The
// account, the person, the membership, and the audit event land on one
// transaction, because a person with no membership belongs nowhere.
func TestCreateWritesTheAccountAndItsMembership(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
	})

	view, err := svc.Create(context.Background(), admin, createBody())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.ID == "" || view.State != StateActive || view.OrgID != testOrgID {
		t.Errorf("the view reads %+v, want a new active account of %s", view, testOrgID)
	}
	if view.Human == nil || view.Human.DisplayName != "Ada Lovelace" {
		t.Fatalf("the view carries %+v, want the person of the body", view.Human)
	}
	if len(writtenUsers) != 1 || writtenUsers[0].Username != "ada" || writtenUsers[0].TenantID != testTenantID {
		t.Fatalf("the write wrote %+v, want one account", writtenUsers)
	}
	if len(writtenHumans) != 1 || writtenHumans[0].Email != "ada@example.com" {
		t.Fatalf("the write wrote %+v, want one person", writtenHumans)
	}
	if len(writtenMembers) != 1 || writtenMembers[0].OrgID != testOrgID ||
		writtenMembers[0].UserID != writtenUsers[0].ID {
		t.Fatalf("the write wrote %+v, want one membership of the new account", writtenMembers)
	}
	wantOneEvent(t, audit.ActionUserCreated, view.ID)
}

// TestCreateHashesThePasswordAndNeverLogsIt is the credential rule. The row
// holds a bcrypt hash, the answer holds nothing, and no log line holds either.
func TestCreateHashesThePasswordAndNeverLogsIt(t *testing.T) {
	svc := adminService(t, adminDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	body := createBody()
	view, err := svc.Create(context.Background(), admin, body)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	stored := writtenHumans[0].PasswordHash
	if stored == "" || stored == body.Password {
		t.Fatalf("the row holds %q, want a bcrypt hash of the password", stored)
	}
	if err := crypto.VerifyPassword(stored, body.Password); err != nil {
		t.Fatalf("the stored hash does not verify the password: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", view), body.Password) {
		t.Errorf("the view reads %+v, want no password in it", view)
	}
	wantNothingLogged(t, body.Password)
	wantNothingLogged(t, stored)
}

// TestCreateRefusesAnotherOrganization refuses a manager who names an
// organization it does not administer.
func TestCreateRefusesAnotherOrganization(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgUserManager}}},
	})

	_, err := svc.Create(context.Background(), admin, createBody())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(writtenUsers) != 0 || len(writtenMembers) != 0 {
		t.Errorf("a refused create wrote %+v and %+v", writtenUsers, writtenMembers)
	}
}

// TestCreateRefusesAnOrganizationNobodyHolds covers a body that names an
// organization the tenant does not hold. A tenant manager passes the role gate
// for any organization, so the organization is read as well.
func TestCreateRefusesAnOrganizationNobodyHolds(t *testing.T) {
	svc := adminService(t, adminDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	body := createBody()
	body.OrgID = "no-such-org"
	if _, err := svc.Create(context.Background(), admin, body); !errors.Is(err, organization.ErrNotFound) {
		t.Fatalf("err = %v, want organization.ErrNotFound", err)
	}
	if len(writtenUsers) != 0 {
		t.Errorf("a refused create wrote %+v", writtenUsers)
	}
}

// TestUpdateWritesTheProfile writes the five profile fields and records one
// event. Nothing that credentials a sign-in is written.
func TestUpdateWritesTheProfile(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	view, err := svc.Update(context.Background(), admin, testUserID, UpdateBody{
		FirstName: "Ada", LastName: "King", DisplayName: "Ada King", Lang: "th", Phone: "+66123456789",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if view.Human == nil || view.Human.DisplayName != "Ada King" || view.Human.Lang != "th" {
		t.Errorf("the view reads %+v, want the new profile", view.Human)
	}
	if len(updatedHumans) != 1 || updatedHumans[0].DisplayName != "Ada King" {
		t.Fatalf("the write wrote %+v, want one profile update", updatedHumans)
	}
	if updatedHumans[0].PasswordHash != "" || updatedHumans[0].Email != "" {
		t.Errorf("the write wrote %+v, want no credential in it", updatedHumans[0])
	}
	wantOneEvent(t, audit.ActionUserUpdated, testUserID)
}

// TestUpdateRefusesAnotherOrganization gates the write on the organization of
// the account, so the account is read before the gate.
func TestUpdateRefusesAnotherOrganization(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgOwner}}},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	_, err := svc.Update(context.Background(), admin, testUserID, UpdateBody{DisplayName: "Taken"})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(updatedHumans) != 0 {
		t.Errorf("a refused update wrote %+v", updatedHumans)
	}
}

// TestDeactivateAndActivateWriteTheState covers the two state writes the console
// offers, each with its own action on the trail.
func TestDeactivateAndActivateWriteTheState(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMAdmin},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	if err := svc.Deactivate(context.Background(), admin, testUserID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if len(states) != 1 || states[0] != StateInactive {
		t.Fatalf("the write wrote %v, want the inactive state", states)
	}
	wantOneEvent(t, audit.ActionUserDeactivated, testUserID)

	svc = adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMAdmin},
		rows:        []User{seededPerson(testOrgID, StateInactive)},
	})
	if err := svc.Activate(context.Background(), admin, testUserID); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if len(states) != 1 || states[0] != StateActive {
		t.Fatalf("the write wrote %v, want the active state", states)
	}
	wantOneEvent(t, audit.ActionUserActivated, testUserID)
}

// TestDeactivateRefusesTheLastOwner covers the softer half of the same lockout.
// A deactivate is reversible, but nobody is left who can reverse it: activating
// an account is a write only an administrator of the tenant performs.
func TestDeactivateRefusesTheLastOwner(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		owners:      1,
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	err := svc.Deactivate(context.Background(), admin, testUserID)
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("Deactivate answered %v, want ErrLastOwner", err)
	}
	if len(states) != 0 {
		t.Fatalf("the write wrote %v, want nothing", states)
	}
}

// TestActivateNeverReadsTheOwnerGuard proves the guard sits on the deactivate
// and not on the shared state write. Activating the last owner is the recovery,
// so it must never be refused.
func TestActivateNeverReadsTheOwnerGuard(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		owners:      1,
		rows:        []User{seededPerson(testOrgID, StateInactive)},
	})

	if err := svc.Activate(context.Background(), admin, testUserID); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if len(states) != 1 || states[0] != StateActive {
		t.Fatalf("the write wrote %v, want the active state", states)
	}
}

// TestUnlockClearsTheLockout covers the button the console shows on a locked
// account.
func TestUnlockClearsTheLockout(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []User{seededPerson(testOrgID, StateLocked)},
	})

	if err := svc.Unlock(context.Background(), admin, testUserID); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if len(unlocked) != 1 || unlocked[0] != testUserID {
		t.Fatalf("the write unlocked %v, want %s", unlocked, testUserID)
	}
	wantOneEvent(t, audit.ActionUserUnlocked, testUserID)
}

// TestDeleteSoftDeletesTheAccount covers the delete. The row stays in the
// database, and the console never shows it again.
func TestDeleteSoftDeletesTheAccount(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	if err := svc.Delete(context.Background(), admin, testUserID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(deletedUsers) != 1 || deletedUsers[0] != testUserID {
		t.Fatalf("the write deleted %v, want %s", deletedUsers, testUserID)
	}
	wantOneEvent(t, audit.ActionUserDeleted, testUserID)
}

// TestDeleteRefusesTheLastOwner covers the lockout the membership guard already
// refuses, one endpoint further out. Deleting the account of the last sitting
// IAM_OWNER leaves the membership row in place and nobody able to sign in, so
// the tenant can never grant the role again.
func TestDeleteRefusesTheLastOwner(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		owners:      1,
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	err := svc.Delete(context.Background(), admin, testUserID)
	if !errors.Is(err, ErrLastOwner) {
		t.Fatalf("Delete answered %v, want ErrLastOwner", err)
	}
	if len(deletedUsers) != 0 {
		t.Fatalf("the write deleted %v, want nothing", deletedUsers)
	}
}

// TestDeleteAllowsAnOwnerWhileAnotherSits proves the guard refuses the last one
// only. A tenant with two owners loses one and keeps administering itself.
func TestDeleteAllowsAnOwnerWhileAnotherSits(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		owners:      2,
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	if err := svc.Delete(context.Background(), admin, testUserID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(deletedUsers) != 1 || deletedUsers[0] != testUserID {
		t.Fatalf("the write deleted %v, want %s", deletedUsers, testUserID)
	}
}

// TestDeleteRollsBackAFailedAuditWrite proves the change and the trail land
// together. A change nobody can audit is not allowed to stand.
func TestDeleteRollsBackAFailedAuditWrite(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		owners:      2,
		rows:        []User{seededPerson(testOrgID, StateActive)},
		auditFails:  true,
	})

	if err := svc.Delete(context.Background(), admin, testUserID); err == nil {
		t.Fatal("Delete answered no error, want the failed audit write")
	}
	if !rolledBack {
		t.Error("the transaction must roll the delete back")
	}
}

// TestResetPasswordAnswersTheTokenOnceAndStoresADigest is the whole reset rule.
// The answer carries the token, the row carries a SHA-256 digest of it, and no
// log line carries either.
func TestResetPasswordAnswersTheTokenOnceAndStoresADigest(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	got, err := svc.ResetPassword(context.Background(), admin, testUserID)
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if got.UserID != testUserID || got.Token == "" {
		t.Fatalf("the answer reads %+v, want the account and one new token", got)
	}
	if !got.Expires.After(time.Now().UTC()) {
		t.Errorf("the token expires at %s, want a time still ahead", got.Expires)
	}
	if len(writtenTokens) != 1 {
		t.Fatalf("the write wrote %+v, want one token", writtenTokens)
	}
	row := writtenTokens[0]
	if row.TokenHash == got.Token {
		t.Fatal("the row stores the token itself, want a digest of it")
	}
	if row.TokenHash != crypto.Digest(got.Token) {
		t.Errorf("the row stores %q, want the digest of the answered token", row.TokenHash)
	}
	if row.Purpose != PurposePasswordReset || row.UserID != testUserID {
		t.Errorf("the row reads %+v, want a password reset of %s", row, testUserID)
	}
	wantNothingLogged(t, got.Token)
	wantOneEvent(t, audit.ActionUserPasswordReset, testUserID)
}

// TestResetMFAClearsEverySecondFactor covers the TOTP secret, the recovery codes
// behind it, and every registered passkey. The console offers one button, so one
// call clears all three.
func TestResetMFAClearsEverySecondFactor(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	if err := svc.ResetMFA(context.Background(), admin, testUserID); err != nil {
		t.Fatalf("ResetMFA: %v", err)
	}
	if len(clearedMFA) != 1 || clearedMFA[0] != testUserID {
		t.Fatalf("the write cleared %v, want %s", clearedMFA, testUserID)
	}
	wantOneEvent(t, audit.ActionUserMFAReset, testUserID)
}

// TestResetMFARefusesAnotherOrganization gates the reset the same way every
// other write is gated.
func TestResetMFARefusesAnotherOrganization(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgUserManager}}},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	if err := svc.ResetMFA(context.Background(), admin, testUserID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(clearedMFA) != 0 {
		t.Errorf("a refused reset cleared %v", clearedMFA)
	}
}

// TestMembershipsReadsBothHalvesWhole covers the read that answers every scope
// one person holds a membership in. It is not paged: one person's memberships
// are bounded.
func TestMembershipsReadsBothHalvesWhole(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []User{seededPerson(testOrgID, StateActive)},
		tenantMember: tenant.Member{TenantID: testTenantID, UserID: testUserID,
			Roles: []string{tenant.RoleIAMAdmin}, CreatedAt: testCreated},
		memberships: []organization.Membership{
			{TenantID: testTenantID, OrgID: testOrgID, UserID: testUserID,
				Roles: []string{organization.RoleOrgOwner}, CreatedAt: testCreated},
		},
	})

	got, err := svc.Memberships(context.Background(), admin, testUserID)
	if err != nil {
		t.Fatalf("Memberships: %v", err)
	}
	if len(got.TenantMemberships) != 1 || got.TenantMemberships[0].Roles[0] != tenant.RoleIAMAdmin {
		t.Fatalf("the tenant half reads %+v, want one membership", got.TenantMemberships)
	}
	if got.TenantMemberships[0].UserName != "Ada Lovelace" {
		t.Errorf("the tenant half names %q, want the display name joined", got.TenantMemberships[0].UserName)
	}
	if len(got.OrgMemberships) != 1 || got.OrgMemberships[0].OrgID != testOrgID {
		t.Fatalf("the organization half reads %+v, want one membership", got.OrgMemberships)
	}
	if got.OrgMemberships[0].UserName != "Ada Lovelace" {
		t.Errorf("the organization half names %q, want the display name joined", got.OrgMemberships[0].UserName)
	}
}

// TestMembershipsAnswersEmptyHalves covers a person who holds no membership at
// all. The console iterates both lists without a guard, so each answers an empty
// array and never null.
func TestMembershipsAnswersEmptyHalves(t *testing.T) {
	svc := adminService(t, adminDeps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []User{seededPerson(testOrgID, StateActive)},
	})

	got, err := svc.Memberships(context.Background(), admin, testUserID)
	if err != nil {
		t.Fatalf("Memberships: %v", err)
	}
	if got.TenantMemberships == nil || len(got.TenantMemberships) != 0 {
		t.Errorf("the tenant half reads %+v, want an empty array", got.TenantMemberships)
	}
	if got.OrgMemberships == nil || len(got.OrgMemberships) != 0 {
		t.Errorf("the organization half reads %+v, want an empty array", got.OrgMemberships)
	}
}

// seededPerson is one account of an organization, as the reads answer it.
// inviteBody is the body an invitation carries in the tests below.
func inviteBody() InviteBody {
	return InviteBody{
		Email:       "grace@example.com",
		OrgID:       testOrgID,
		Roles:       []string{organization.RoleOrgUserManager},
		DisplayName: "Grace Hopper",
	}
}

// TestInviteWritesTheAccountTheMembershipAndTheToken is the whole invitation
// rule. An invitation is a membership grant for somebody who has no account
// yet, so the account, the person, the membership, the token, and the audit
// event land on one transaction.
func TestInviteWritesTheAccountTheMembershipAndTheToken(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
	})

	view, err := svc.Invite(context.Background(), admin, inviteBody())
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}

	if len(writtenUsers) != 1 {
		t.Fatalf("the invitation wrote %+v, want one account", writtenUsers)
	}
	row := writtenUsers[0]
	if row.State != StateInitial {
		t.Errorf("the account reads state %d, want %d: nobody signed in as it yet", row.State, StateInitial)
	}
	if row.Username != "grace@example.com" {
		t.Errorf("the account is named %q, want the email address the body carries", row.Username)
	}
	if len(writtenHumans) != 1 || writtenHumans[0].Email != "grace@example.com" {
		t.Fatalf("the invitation wrote %+v, want one person", writtenHumans)
	}
	if writtenHumans[0].PasswordHash != "" {
		t.Error("the invited person carries a password, and only they may set one")
	}
	if len(writtenMembers) != 1 || writtenMembers[0].OrgID != testOrgID ||
		writtenMembers[0].UserID != row.ID {
		t.Fatalf("the invitation wrote %+v, want one membership of the new account", writtenMembers)
	}
	if len(writtenMembers[0].Roles) != 1 || writtenMembers[0].Roles[0] != organization.RoleOrgUserManager {
		t.Errorf("the membership holds %v, want the roles the body names", writtenMembers[0].Roles)
	}
	if view.UserID != row.ID || view.Email != "grace@example.com" {
		t.Errorf("the view reads %+v, want the account it wrote", view)
	}
	wantOneEvent(t, audit.ActionUserInvited, row.ID)
}

// TestInviteAnswersTheTokenOnceAndStoresADigest is the credential rule of the
// invitation. The row holds a digest, the answer holds the token, and no log
// line holds either.
func TestInviteAnswersTheTokenOnceAndStoresADigest(t *testing.T) {
	svc := adminService(t, adminDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	view, err := svc.Invite(context.Background(), admin, inviteBody())
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	if view.Token == "" {
		t.Fatal("the answer carries no token, and it is disclosed nowhere else")
	}
	if len(writtenTokens) != 1 {
		t.Fatalf("the invitation wrote %+v, want one token row", writtenTokens)
	}
	stored := writtenTokens[0]
	if stored.Purpose != PurposeInvitation {
		t.Errorf("the token reads purpose %d, want %d", stored.Purpose, PurposeInvitation)
	}
	if stored.TokenHash == view.Token {
		t.Fatal("the row holds the token itself, want a digest of it")
	}
	if stored.TokenHash != crypto.Digest(view.Token) {
		t.Errorf("the row holds %q, want the digest of the answered token", stored.TokenHash)
	}
	if !view.Expires.After(time.Now().UTC()) {
		t.Errorf("the token expires at %v, which is already past", view.Expires)
	}
	wantNothingLogged(t, view.Token)
}

// TestInviteRefusesAnotherOrganization refuses a manager who names an
// organization it does not administer. An invitation is a membership grant, so
// it passes the same gate a grant passes.
func TestInviteRefusesAnotherOrganization(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	_, err := svc.Invite(context.Background(), admin, inviteBody())
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(writtenUsers) != 0 || len(writtenTokens) != 0 {
		t.Error("a refused invitation wrote an account or a token")
	}
}

// TestInviteCannotConferOwner is the escalation rule, on the endpoint that
// creates the person as well as the membership. An ORG_USER_MANAGER that could
// invite an owner would outrank itself with one request.
func TestInviteCannotConferOwner(t *testing.T) {
	svc := adminService(t, adminDeps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgUserManager}}},
	})

	body := inviteBody()
	body.Roles = []string{organization.RoleOrgOwner}

	_, err := svc.Invite(context.Background(), admin, body)
	if !errors.Is(err, organization.ErrOwnerGrant) {
		t.Fatalf("err = %v, want organization.ErrOwnerGrant", err)
	}
	if len(writtenUsers) != 0 {
		t.Error("a refused invitation wrote an account")
	}
}

// TestInviteRefusesAnOrganizationNobodyHolds refuses an invitation into an
// organization that does not exist. A tenant manager passes the role gate for
// every organization, so the organization is read as well.
func TestInviteRefusesAnOrganizationNobodyHolds(t *testing.T) {
	svc := adminService(t, adminDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	body := inviteBody()
	body.OrgID = "no-such-organization"

	if _, err := svc.Invite(context.Background(), admin, body); !errors.Is(err, organization.ErrNotFound) {
		t.Fatalf("err = %v, want organization.ErrNotFound", err)
	}
}

func seededPerson(orgID string, state int) User {
	return User{
		ID: testUserID, TenantID: testTenantID, OrgID: orgID, Username: "ada",
		UserType: TypeHuman, State: state, CreatedAt: testCreated,
		DisplayName: "Ada Lovelace", Email: "ada@example.com", IsEmailVerified: true,
	}
}

// wantNothingLogged reads every line the service logged, at every level, and
// fails if the value reached one of them.
func wantNothingLogged(t *testing.T, value string) {
	t.Helper()

	for _, entry := range logs.All() {
		line := entry.Message + fmt.Sprint(entry.ContextMap())
		if strings.Contains(line, value) {
			t.Fatalf("the log line %q carries a credential", line)
		}
	}
}

// wantOneEvent reads the audit trail of one test: exactly one event, of the
// action and the entity the write names.
func wantOneEvent(t *testing.T, action audit.Action, entityID string) {
	t.Helper()

	if len(events) != 1 {
		t.Fatalf("the write recorded %d events, want 1: %+v", len(events), events)
	}
	got := events[0]
	if got.Action != string(action) {
		t.Errorf("the event reads %q, want %q", got.Action, action)
	}
	if got.EntityType != audit.EntityUser || got.EntityID != entityID {
		t.Errorf("the event names %s %s, want %s %s",
			got.EntityType, got.EntityID, audit.EntityUser, entityID)
	}
	if got.TenantID != testTenantID || got.ActorID != testUserID {
		t.Errorf("the event reads tenant %s actor %s, want %s %s",
			got.TenantID, got.ActorID, testTenantID, testUserID)
	}
	if got.IP != admin.IP || got.UserAgent != admin.UserAgent {
		t.Errorf("the event reads %s %s, want the request of the actor", got.IP, got.UserAgent)
	}
}

// adminDeps names what one admin service test varies. Everything else takes a
// default below.
type adminDeps struct {
	tenantRoles  []string
	memberships  []organization.Membership
	tenantMember tenant.Member
	rows         []User
	// How many people sit as IAM_OWNER of the tenant. Only the writes that can
	// take an owner out of service read it.
	owners     int64
	auditFails bool
	// weakPassword refuses the password of a create, as the policy of the
	// organization does when the password fails one of its rules.
	weakPassword bool
	// digitalIdentity turns the Scan Verifier on, as the deployment setting does.
	// With it false the service holds no enroller, and nothing calls out.
	digitalIdentity bool
	// enrolFails answers a failure from the Scan Verifier, as an outage there
	// does.
	enrolFails bool
}

// What the writes of one admin test did. adminService clears them, and the
// tests of one package run one after another, so each test reads its own writes.
var (
	writtenUsers   []User
	writtenHumans  []Human
	writtenMembers []organization.Membership
	updatedHumans  []Human
	states         []int
	unlocked       []string
	deletedUsers   []string
	writtenTokens  []AccountToken
	clearedMFA     []string
	events         []audit.Event
	enrolled       []di.EnrolUser
	storedDI       []string
	rolledBack     bool
	logs           *observer.ObservedLogs
)

func adminService(t *testing.T, d adminDeps) *Service {
	t.Helper()
	var log logger.Logger
	log, logs = logger.NewObserved()
	writtenUsers, writtenHumans, writtenMembers, updatedHumans = nil, nil, nil, nil
	states, unlocked, deletedUsers, writtenTokens = nil, nil, nil, nil
	clearedMFA, events, rolledBack = nil, nil, false
	enrolled, storedDI = nil, nil

	record := func(_ context.Context, e audit.Event) error {
		if d.auditFails {
			return errors.New("the audit write failed")
		}
		events = append(events, e)
		return nil
	}
	countWrites := func() int {
		return len(writtenUsers) + len(writtenHumans) + len(writtenMembers) +
			len(updatedHumans) + len(states) + len(unlocked) + len(deletedUsers) +
			len(writtenTokens) + len(clearedMFA)
	}

	return NewService(Deps{
		List: func(context.Context, string, Query) ([]User, int64, error) {
			return d.rows, int64(len(d.rows)), nil
		},
		Read: func(_ context.Context, _, userID string) (User, error) {
			for _, row := range d.rows {
				if row.ID == userID {
					return row, nil
				}
			}
			return User{}, fmt.Errorf("%w: %s", ErrNoSuchUser, userID)
		},
		Org: func(_ context.Context, _, orgID string) (organization.Organization, error) {
			if orgID == testOrgID || orgID == otherOrgID {
				return organization.Organization{ID: orgID, TenantID: testTenantID, Name: "Acme"}, nil
			}
			return organization.Organization{}, organization.ErrNotFound
		},
		Insert: func(_ context.Context, row User) error {
			writtenUsers = append(writtenUsers, row)
			return nil
		},
		InsertHuman: func(_ context.Context, row Human) error {
			writtenHumans = append(writtenHumans, row)
			return nil
		},
		InsertMember: func(_ context.Context, row organization.Membership) error {
			writtenMembers = append(writtenMembers, row)
			return nil
		},
		UpdateHuman: func(_ context.Context, row Human) error {
			updatedHumans = append(updatedHumans, row)
			return nil
		},
		SetState: func(_ context.Context, _, _ string, state int) error {
			states = append(states, state)
			return nil
		},
		Unlock: func(_ context.Context, _, userID string) error {
			unlocked = append(unlocked, userID)
			return nil
		},
		SoftDelete: func(_ context.Context, _, userID string) error {
			deletedUsers = append(deletedUsers, userID)
			return nil
		},
		InsertToken: func(_ context.Context, row AccountToken) error {
			writtenTokens = append(writtenTokens, row)
			return nil
		},
		ClearMFA: func(_ context.Context, _, userID string) error {
			clearedMFA = append(clearedMFA, userID)
			return nil
		},
		TenantMember: func(context.Context, string, string) (tenant.Member, error) {
			return d.tenantMember, nil
		},
		// The unit of work either commits whole or leaves nothing behind, so a
		// failed step clears what the earlier steps wrote.
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			before := countWrites()
			err := fn(ctx)
			if err != nil && countWrites() != before {
				writtenUsers, writtenHumans, writtenMembers, updatedHumans = nil, nil, nil, nil
				states, unlocked, deletedUsers, writtenTokens = nil, nil, nil, nil
				clearedMFA, rolledBack = nil, true
			}
			return err
		},
		Audit: audit.NewRecorder(record, log),
		TenantRoles: func(context.Context, string, string) ([]string, error) {
			return d.tenantRoles, nil
		},
		CheckPassword: func(context.Context, string, string, string) error {
			if d.weakPassword {
				return policyRefusal
			}
			return nil
		},

		CountTenantOwners: func(context.Context, string) (int64, error) {
			return d.owners, nil
		},
		Enrol: enroller(d),
		SetDI: func(_ context.Context, _, userID, uuid string) error {
			storedDI = append(storedDI, userID+"="+uuid)
			return nil
		},
		OrgMemberships: func(context.Context, string, string) ([]organization.Membership, error) {
			return d.memberships, nil
		},
		Log: log,
	})
}

// enroller is the Scan Verifier of one admin test. It answers nil when the
// deployment runs none, which is the switch the service reads.
func enroller(d adminDeps) DIEnroller {
	if !d.digitalIdentity {
		return nil
	}
	return func(_ context.Context, u di.EnrolUser) (string, error) {
		enrolled = append(enrolled, u)
		if d.enrolFails {
			return "", errors.New("the scan verifier is down")
		}
		return "verifier-" + u.IDNumber, nil
	}
}

// meService builds the service over a fixed tenant, two organizations, and one
// person. Only the roles differ between the tests, so each test passes its own
// tenant roles and its own organization memberships.
func meService(tenantRoles []string, memberships []organization.Membership) *Service {
	log, _ := logger.NewObserved()

	return NewService(Deps{
		Find: func(_ context.Context, _, _ string) (User, error) {
			return User{
				ID:          testUserID,
				TenantID:    testTenantID,
				Username:    "ada",
				DisplayName: "Ada Lovelace",
				Email:       "ada@example.com",
			}, nil
		},
		Tenant: func(_ context.Context, _ string) (tenant.Tenant, error) {
			return tenant.Tenant{
				ID:           testTenantID,
				Name:         "Acme",
				State:        1,
				DefaultOrgID: "org-1",
				CreatedAt:    testCreated,
			}, nil
		},
		Domains: func(_ context.Context, _ string) ([]tenant.Domain, error) {
			return []tenant.Domain{
				{Domain: "acme.example.com", IsPrimary: true, IsVerified: true, State: 1},
			}, nil
		},
		TenantRoles: func(_ context.Context, _, _ string) ([]string, error) {
			return tenantRoles, nil
		},
		Orgs: func(_ context.Context, _ string) ([]organization.Organization, error) {
			return []organization.Organization{
				{ID: "org-1", TenantID: testTenantID, Name: "Acme"},
				{ID: "org-2", TenantID: testTenantID, Name: "Beta"},
			}, nil
		},
		OrgMemberships: func(_ context.Context, _, _ string) ([]organization.Membership, error) {
			return memberships, nil
		},
		Log: log,
	})
}

// TestMeAdmitsTenantManager reads the answer of a person who administers the
// whole tenant.
func TestMeAdmitsTenantManager(t *testing.T) {
	svc := meService([]string{tenant.RoleIAMOwner}, nil)

	me, err := svc.Me(context.Background(), testTenantID, testUserID)
	if err != nil {
		t.Fatalf("Me: %v", err)
	}

	if !me.IsTenantManager {
		t.Error("a tenant role must make the person a tenant manager")
	}
	if me.UserID != testUserID || me.Email != "ada@example.com" {
		t.Errorf("person = %s %s, want %s ada@example.com", me.UserID, me.Email, testUserID)
	}
	if me.Tenant.ID != testTenantID || me.Tenant.Name != "Acme" {
		t.Errorf("tenant = %s %s, want %s Acme", me.Tenant.ID, me.Tenant.Name, testTenantID)
	}
	if len(me.Tenant.Domains) != 1 || me.Tenant.Domains[0].Domain != "acme.example.com" {
		t.Errorf("domains = %v, want one acme.example.com", me.Tenant.Domains)
	}
	if len(me.AccessibleOrgs) != 2 {
		t.Errorf("accessible orgs = %d, want 2", len(me.AccessibleOrgs))
	}
	if len(me.OrgMemberships) != 0 {
		t.Errorf("org memberships = %d, want 0", len(me.OrgMemberships))
	}
}

// TestMeAdmitsOrganizationAdmin reads the answer of a person who administers one
// organization and holds no tenant role.
func TestMeAdmitsOrganizationAdmin(t *testing.T) {
	memberships := []organization.Membership{{
		TenantID:  testTenantID,
		OrgID:     "org-2",
		UserID:    testUserID,
		Roles:     []string{organization.RoleOrgUserManager},
		CreatedAt: testCreated,
	}}
	svc := meService(nil, memberships)

	me, err := svc.Me(context.Background(), testTenantID, testUserID)
	if err != nil {
		t.Fatalf("Me: %v", err)
	}

	if me.IsTenantManager {
		t.Error("an organization role must not make the person a tenant manager")
	}
	if len(me.TenantRoles) != 0 {
		t.Errorf("tenant roles = %v, want none", me.TenantRoles)
	}
	if len(me.OrgMemberships) != 1 || me.OrgMemberships[0].OrgID != "org-2" {
		t.Fatalf("org memberships = %v, want one of org-2", me.OrgMemberships)
	}
	if len(me.OrgMemberships[0].Roles) != 1 ||
		me.OrgMemberships[0].Roles[0] != organization.RoleOrgUserManager {
		t.Errorf("roles = %v, want %s", me.OrgMemberships[0].Roles, organization.RoleOrgUserManager)
	}
	if len(me.AccessibleOrgs) != 2 {
		t.Errorf("accessible orgs = %d, want 2", len(me.AccessibleOrgs))
	}
}

// TestMeRefusesPersonWithoutAdminRole refuses a person who holds a membership,
// but no administrative role in it. The console is for administrators, and this
// person belongs in the portal.
func TestMeRefusesPersonWithoutAdminRole(t *testing.T) {
	memberships := []organization.Membership{{
		TenantID: testTenantID,
		OrgID:    "org-1",
		UserID:   testUserID,
		Roles:    []string{"ORG_MEMBER"},
	}}
	svc := meService(nil, memberships)

	_, err := svc.Me(context.Background(), testTenantID, testUserID)
	if !errors.Is(err, ErrNoAdminRole) {
		t.Fatalf("err = %v, want ErrNoAdminRole", err)
	}
}

// TestCreateEnrolsThePersonWithTheScanVerifier is the mirroring rule. A person
// the tenant provisions is registered with the Scan Verifier, keyed on the
// username, and the identifier it answers is stored against them.
func TestCreateEnrolsThePersonWithTheScanVerifier(t *testing.T) {
	svc := adminService(t, adminDeps{
		digitalIdentity: true,
		tenantRoles:     []string{tenant.RoleIAMOwner},
	})

	view, err := svc.Create(context.Background(), admin, createBody())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(enrolled) != 1 || enrolled[0].IDNumber != "ada" || enrolled[0].Email != "ada@example.com" {
		t.Fatalf("the enrolment sent %+v, want the username and the email of the person", enrolled)
	}
	if len(storedDI) != 1 || storedDI[0] != view.ID+"=verifier-ada" {
		t.Fatalf("the write stored %v, want the identifier of the verifier", storedDI)
	}
	if view.Human == nil || view.Human.DIEnrolled == nil || !*view.Human.DIEnrolled {
		t.Errorf("the view reads %+v, want an enrolled person", view.Human)
	}
}

// TestInviteEnrolsThePersonWithTheScanVerifier proves that both administrative
// writes mirror. An invitation produces a person with a username too.
func TestInviteEnrolsThePersonWithTheScanVerifier(t *testing.T) {
	svc := adminService(t, adminDeps{
		digitalIdentity: true,
		tenantRoles:     []string{tenant.RoleIAMOwner},
	})

	view, err := svc.Invite(context.Background(), admin, inviteBody())
	if err != nil {
		t.Fatalf("Invite: %v", err)
	}
	// The invitation names no username, so the email address becomes one, and
	// the Scan Verifier keys on that.
	if len(enrolled) != 1 || enrolled[0].IDNumber != "grace@example.com" {
		t.Fatalf("the enrolment sent %+v, want the username of the person", enrolled)
	}
	if len(storedDI) != 1 || storedDI[0] != view.UserID+"=verifier-grace@example.com" {
		t.Fatalf("the write stored %v, want the identifier of the verifier", storedDI)
	}
}

// TestCreateSurvivesAScanVerifierOutage is the ordering rule. The call runs
// after the commit and outside it, so an outage at a third party leaves the
// person created and answers the console normally. The failure is a warning
// naming the person, and it leaves the stored identifier empty.
func TestCreateSurvivesAScanVerifierOutage(t *testing.T) {
	svc := adminService(t, adminDeps{
		digitalIdentity: true,
		enrolFails:      true,
		tenantRoles:     []string{tenant.RoleIAMOwner},
	})

	view, err := svc.Create(context.Background(), admin, createBody())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(writtenUsers) != 1 || rolledBack {
		t.Fatalf("the write wrote %+v and rolled back %v, want the person created", writtenUsers, rolledBack)
	}
	if len(storedDI) != 0 {
		t.Errorf("the write stored %v, want nothing", storedDI)
	}
	if view.Human == nil || view.Human.DIEnrolled == nil || *view.Human.DIEnrolled {
		t.Errorf("the view reads %+v, want a person who is not enrolled", view.Human)
	}
	warnings := logs.FilterLevelExact(zapcore.WarnLevel).FilterField(zap.String("user_id", view.ID))
	if warnings.Len() == 0 {
		t.Errorf("the log holds %v, want a warning naming the person", logs.All())
	}
	if got := logs.FilterLevelExact(zapcore.ErrorLevel).Len(); got != 0 {
		t.Errorf("the log holds %d error lines, want none: an outage is not this deployment failing", got)
	}
}

// TestCreateSkipsAPersonWithNoUsername proves the skip. The Scan Verifier keys
// on the username, so a person without one cannot be mirrored, and the skip is
// logged rather than sent.
func TestCreateSkipsAPersonWithNoUsername(t *testing.T) {
	svc := adminService(t, adminDeps{
		digitalIdentity: true,
		tenantRoles:     []string{tenant.RoleIAMOwner},
	})

	body := createBody()
	body.Username = ""
	view, err := svc.Create(context.Background(), admin, body)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(enrolled) != 0 {
		t.Fatalf("the enrolment sent %+v, want nothing", enrolled)
	}
	warnings := logs.FilterLevelExact(zapcore.WarnLevel).FilterField(zap.String("user_id", view.ID))
	if warnings.Len() == 0 {
		t.Errorf("the log holds %v, want a warning naming the skipped person", logs.All())
	}
}

// TestCreateWithTheIntegrationOffCallsNothing is the switch. With no Scan
// Verifier configured nothing calls out, and the console answer carries no
// enrolment field at all.
func TestCreateWithTheIntegrationOffCallsNothing(t *testing.T) {
	svc := adminService(t, adminDeps{tenantRoles: []string{tenant.RoleIAMOwner}})

	view, err := svc.Create(context.Background(), admin, createBody())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(enrolled) != 0 || len(storedDI) != 0 {
		t.Fatalf("the enrolment sent %+v and stored %v, want nothing", enrolled, storedDI)
	}
	if view.Human == nil || view.Human.DIEnrolled != nil {
		t.Errorf("the view reads %+v, want no enrolment field", view.Human)
	}
}
