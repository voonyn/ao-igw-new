package notification

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

// testRepo opens the scratch schema and seals the SMTP password the way the
// server does, so the test proves the column and the cipher together.
func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "notification")
	cipher, err := crypto.NewCipher("a-test-encryption-key")
	if err != nil {
		t.Fatalf("build the cipher: %v", err)
	}
	return NewRepository(bdb, cipher, logger.New()), context.Background()
}

// TestFindSettingsAnswersNotFoundForATenantThatStoredNothing covers the read of
// a tenant that configured no delivery. It is not a failure: the defaults apply.
func TestFindSettingsAnswersNotFoundForATenantThatStoredNothing(t *testing.T) {
	repo, ctx := testRepo(t)

	if _, err := repo.FindSettings(ctx, noteTenantID); !errors.Is(err, ErrNoSettings) {
		t.Errorf("a tenant that stored nothing reads %v, want ErrNoSettings", err)
	}
}

// TestUpsertSettingsSealsThePasswordAndReplacesTheWholeRow covers the write of
// the delivery settings. The password is sealed in the column and opened on the
// read, and a second write replaces every other field.
func TestUpsertSettingsSealsThePasswordAndReplacesTheWholeRow(t *testing.T) {
	repo, ctx := testRepo(t)

	written := Settings{
		TenantID: noteTenantID, Transport: TransportSMTP, SMTPHost: "smtp.example.com",
		SMTPPort: 587, SMTPUsername: "postmaster", Password: "a-relay-secret",
		FromAddress: "no-reply@example.com", FromName: "Example",
		TLSMode: "starttls", SendTimeoutMS: 10000,
	}
	if err := repo.UpsertSettings(ctx, written); err != nil {
		t.Fatalf("write the delivery settings: %v", err)
	}

	row, err := repo.FindSettings(ctx, noteTenantID)
	if err != nil {
		t.Fatalf("read the delivery settings: %v", err)
	}
	if row.Password != "a-relay-secret" || row.SMTPHost != "smtp.example.com" {
		t.Errorf("the row reads %+v, want the written settings", row)
	}
	if len(row.Sealed) != 0 {
		t.Errorf("the row carries %d ciphertext bytes, want the column left behind", len(row.Sealed))
	}

	// The column holds ciphertext, not the credential.
	var stored []byte
	if err := repo.db.NewSelect().Model((*Settings)(nil)).
		Column("smtp_password").Where("ns.tenant_id = ?", noteTenantID).
		Scan(ctx, &stored); err != nil {
		t.Fatalf("read the stored column: %v", err)
	}
	if bytes.Contains(stored, []byte("a-relay-secret")) {
		t.Errorf("the column holds the password in the clear")
	}

	written.SMTPHost, written.Transport, written.Password = "", TransportLog, ""
	if err := repo.UpsertSettings(ctx, written); err != nil {
		t.Fatalf("replace the delivery settings: %v", err)
	}
	row, err = repo.FindSettings(ctx, noteTenantID)
	if err != nil {
		t.Fatalf("read the delivery settings: %v", err)
	}
	if row.Transport != TransportLog || row.SMTPHost != "" || row.Password != "" {
		t.Errorf("the row reads %+v, want the replaced settings", row)
	}
}

// TestTemplateOverridesAreSeparatePerLevel covers the two levels one key can be
// overridden at. The unique key spans the organization, so a tenant message and
// an organization message live side by side.
func TestTemplateOverridesAreSeparatePerLevel(t *testing.T) {
	repo, ctx := testRepo(t)

	if _, err := repo.FindTemplate(ctx, noteTenantID, "", KeyPasswordReset); !errors.Is(err, ErrNoTemplate) {
		t.Errorf("a level that stores nothing reads %v, want ErrNoTemplate", err)
	}

	tenantRow := Template{TenantID: noteTenantID, OrgID: "", Key: KeyPasswordReset,
		Subject: "Reset your password", BodyText: "text", BodyHTML: "<p>html</p>"}
	orgRow := Template{TenantID: noteTenantID, OrgID: noteOrgID, Key: KeyPasswordReset,
		Subject: "Reset your Contoso password", BodyText: "text", BodyHTML: "<p>html</p>"}
	for _, row := range []Template{tenantRow, orgRow} {
		if err := repo.UpsertTemplate(ctx, row); err != nil {
			t.Fatalf("write the %q override: %v", row.OrgID, err)
		}
	}

	read, err := repo.FindTemplate(ctx, noteTenantID, "", KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the tenant override: %v", err)
	}
	if read.Subject != "Reset your password" {
		t.Errorf("the tenant row reads %+v, want the tenant message", read)
	}

	read, err = repo.FindTemplate(ctx, noteTenantID, noteOrgID, KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the organization override: %v", err)
	}
	if read.Subject != "Reset your Contoso password" || read.UpdatedAt.IsZero() {
		t.Errorf("the organization row reads %+v, want the organization message", read)
	}
}

// TestUpsertTemplateReplacesTheContentOfALiveRow covers the second write of one
// level. The unique key catches it, so the level holds one row and not two.
func TestUpsertTemplateReplacesTheContentOfALiveRow(t *testing.T) {
	repo, ctx := testRepo(t)

	row := Template{TenantID: noteTenantID, Key: KeyMemberInvitation,
		Subject: "You are invited", BodyText: "text", BodyHTML: "<p>html</p>"}
	if err := repo.UpsertTemplate(ctx, row); err != nil {
		t.Fatalf("write the override: %v", err)
	}

	row.Subject = "Join Contoso"
	if err := repo.UpsertTemplate(ctx, row); err != nil {
		t.Fatalf("replace the override: %v", err)
	}

	read, err := repo.FindTemplate(ctx, noteTenantID, "", KeyMemberInvitation)
	if err != nil {
		t.Fatalf("read the override: %v", err)
	}
	if read.Subject != "Join Contoso" {
		t.Errorf("the row reads %+v, want the replaced message", read)
	}
}

// TestRemoveTemplateSoftDeletesAndLetsTheLevelBeWrittenAgain covers the revert.
// The row is marked deleted, the level reads nothing, and the operator can
// override the key again afterwards.
func TestRemoveTemplateSoftDeletesAndLetsTheLevelBeWrittenAgain(t *testing.T) {
	repo, ctx := testRepo(t)

	row := Template{TenantID: noteTenantID, Key: KeyEmailVerification,
		Subject: "Verify", BodyText: "text", BodyHTML: "<p>html</p>"}
	if err := repo.UpsertTemplate(ctx, row); err != nil {
		t.Fatalf("write the override: %v", err)
	}
	if err := repo.RemoveTemplate(ctx, noteTenantID, "", KeyEmailVerification); err != nil {
		t.Fatalf("remove the override: %v", err)
	}
	if _, err := repo.FindTemplate(ctx, noteTenantID, "", KeyEmailVerification); !errors.Is(err, ErrNoTemplate) {
		t.Errorf("a reverted level reads %v, want ErrNoTemplate", err)
	}
	if err := repo.RemoveTemplate(ctx, noteTenantID, "", KeyEmailVerification); !errors.Is(err, ErrNoTemplate) {
		t.Errorf("a second revert reads %v, want ErrNoTemplate", err)
	}

	row.Subject = "Verify your email address"
	if err := repo.UpsertTemplate(ctx, row); err != nil {
		t.Fatalf("write the override again: %v", err)
	}
	read, err := repo.FindTemplate(ctx, noteTenantID, "", KeyEmailVerification)
	if err != nil {
		t.Fatalf("read the override: %v", err)
	}
	if read.Subject != "Verify your email address" {
		t.Errorf("the row reads %+v, want the new message", read)
	}
}
