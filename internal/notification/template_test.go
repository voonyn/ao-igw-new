package notification

import (
	"context"
	"errors"
	"strings"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/tenant"
)

// templateBody is one override, as the console submits one.
func templateBody(subject string) TemplateBody {
	return TemplateBody{
		Subject:  subject,
		BodyText: "Hello {{.DisplayName}}, open {{.Link}}.",
		BodyHTML: "<p>Hello {{.DisplayName}}, open <a href=\"{{.Link}}\">the link</a>.</p>",
	}
}

// TestReadTemplateFallsBackToTheEmbeddedDefault covers a tenant that overrode
// nothing. The embedded message renders, and the answer says so.
func TestReadTemplateFallsBackToTheEmbeddedDefault(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMAdmin}, nil)

	view, err := svc.ReadTemplate(context.Background(), noteOperator, "", KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the template: %v", err)
	}
	if view.Source != SourceEmbedded || view.IsOverride {
		t.Errorf("the answer reads %+v, want the embedded default", view)
	}
	if view.Subject != embedded[KeyPasswordReset].Subject {
		t.Errorf("the answer reads subject %q, want the embedded one", view.Subject)
	}
}

// TestReadTemplateAnswersTheTenantOverride covers the middle level. The tenant
// wrote the message, so the tenant scope reads it as its own override.
func TestReadTemplateAnswersTheTenantOverride(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyPasswordReset,
		templateBody("Reset your password")); err != nil {
		t.Fatalf("write the tenant override: %v", err)
	}

	view, err := svc.ReadTemplate(context.Background(), noteOperator, "", KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the template: %v", err)
	}
	if view.Source != SourceTenant || !view.IsOverride || view.Subject != "Reset your password" {
		t.Errorf("the answer reads %+v, want the tenant override", view)
	}
}

// TestReadOrgTemplateInheritsTheTenantOverride covers the level that stores
// nothing. The organization reads the tenant message, and the answer says the
// organization holds no override of its own.
func TestReadOrgTemplateInheritsTheTenantOverride(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyPasswordReset,
		templateBody("Reset your password")); err != nil {
		t.Fatalf("write the tenant override: %v", err)
	}

	view, err := svc.ReadTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the organization template: %v", err)
	}
	if view.Source != SourceTenant || view.IsOverride {
		t.Errorf("the answer reads %+v, want the inherited tenant message", view)
	}
	if view.Subject != "Reset your password" {
		t.Errorf("the answer reads subject %q, want the tenant one", view.Subject)
	}
}

// TestReadOrgTemplateAnswersTheOrgOverride covers the top level. The
// organization override wins over the tenant one, which wins over the embedded
// default.
func TestReadOrgTemplateAnswersTheOrgOverride(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyPasswordReset,
		templateBody("Reset your password")); err != nil {
		t.Fatalf("write the tenant override: %v", err)
	}
	if _, err := svc.WriteTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset,
		templateBody("Reset your Contoso password")); err != nil {
		t.Fatalf("write the organization override: %v", err)
	}

	view, err := svc.ReadTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the organization template: %v", err)
	}
	if view.Source != SourceOrg || !view.IsOverride || view.Subject != "Reset your Contoso password" {
		t.Errorf("the answer reads %+v, want the organization override", view)
	}

	// The tenant scope is unchanged by an organization write.
	tenantView, err := svc.ReadTemplate(context.Background(), noteOperator, "", KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the tenant template: %v", err)
	}
	if tenantView.Subject != "Reset your password" {
		t.Errorf("the tenant answer reads %+v, want the tenant override", tenantView)
	}
}

// TestListTemplatesNamesEveryKeyAndItsSource covers the list. Every key the
// gateway sends is listed, whether it is overridden or not.
func TestListTemplatesNamesEveryKeyAndItsSource(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyMemberInvitation,
		templateBody("You are invited")); err != nil {
		t.Fatalf("write the tenant override: %v", err)
	}

	rows, err := svc.ListTemplates(context.Background(), noteOperator, "")
	if err != nil {
		t.Fatalf("list the templates: %v", err)
	}
	if len(rows) != len(Keys) {
		t.Fatalf("the list answers %d rows, want %d", len(rows), len(Keys))
	}

	sources := map[string]TemplateInfo{}
	for _, row := range rows {
		sources[row.Key] = row
	}
	if row := sources[KeyMemberInvitation]; row.Source != SourceTenant || !row.IsOverride {
		t.Errorf("the invitation row reads %+v, want the tenant override", row)
	}
	if row := sources[KeyPasswordReset]; row.Source != SourceEmbedded || row.IsOverride {
		t.Errorf("the reset row reads %+v, want the embedded default", row)
	}
}

// TestReadTemplateRefusesAKeyTheGatewayNeverSends covers a typed key. Only the
// keys the gateway renders can be overridden, because a row under any other name
// would never be read.
func TestReadTemplateRefusesAKeyTheGatewayNeverSends(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if _, err := svc.ReadTemplate(context.Background(), noteOperator, "", "not_a_template"); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("an unknown key reads %v, want ErrUnknownTemplate", err)
	}
	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", "not_a_template",
		templateBody("Anything")); !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("an unknown key writes %v, want ErrUnknownTemplate", err)
	}
}

// TestWriteTemplateRecordsOneEvent covers the trail of one override. The entity
// is the key, and the level it was written at is in the metadata.
func TestWriteTemplateRecordsOneEvent(t *testing.T) {
	svc := testService(t, nil, orgOwner(noteOrgID))

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset,
		templateBody("Reset your Contoso password")); err != nil {
		t.Fatalf("write the organization override: %v", err)
	}
	if len(storedTemplates) != 1 || storedTemplates[0].OrgID != noteOrgID {
		t.Fatalf("the write stored %+v, want one organization override", storedTemplates)
	}
	if len(noteEvents) != 1 {
		t.Fatalf("the write recorded %d events, want one", len(noteEvents))
	}
	event := noteEvents[0]
	if event.Action != string(audit.ActionNotificationTemplateUpdated) ||
		event.EntityType != audit.EntityNotificationTemplate || event.EntityID != KeyPasswordReset {
		t.Errorf("the event reads %+v, want the written override", event)
	}
	if !strings.Contains(event.Metadata, noteOrgID) {
		t.Errorf("the event metadata reads %q, want the organization", event.Metadata)
	}
}

// TestWriteTemplateRefusesAMessageThatDoesNotParse covers the one rule the
// backend enforces on the content. A stored template that fails to parse would
// break every send of that key, and the operator would learn it from a bounced
// password reset.
func TestWriteTemplateRefusesAMessageThatDoesNotParse(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	_, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyPasswordReset, TemplateBody{
		Subject: "Reset", BodyText: "Hello {{.DisplayName", BodyHTML: "<p>Hello</p>",
	})
	if !errors.Is(err, ErrTemplateSyntax) {
		t.Errorf("a template that does not parse writes %v, want ErrTemplateSyntax", err)
	}
	if len(storedTemplates) != 0 {
		t.Errorf("the refused write stored %+v, want nothing", storedTemplates)
	}
}

// TestResetTemplateRemovesTheOverride covers the revert. The level goes back to
// the one below, and one event records it.
func TestResetTemplateRemovesTheOverride(t *testing.T) {
	svc := testService(t, nil, orgOwner(noteOrgID))

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset,
		templateBody("Reset your Contoso password")); err != nil {
		t.Fatalf("write the organization override: %v", err)
	}
	if err := svc.ResetTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset); err != nil {
		t.Fatalf("remove the override: %v", err)
	}
	if len(removedKeys) != 1 || removedKeys[0] != KeyPasswordReset {
		t.Errorf("the revert removed %v, want the override of the key", removedKeys)
	}
	if len(noteEvents) != 2 || noteEvents[1].Action != string(audit.ActionNotificationTemplateReset) {
		t.Errorf("the revert recorded %+v, want one template reset event", noteEvents)
	}

	view, err := svc.ReadTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset)
	if err != nil {
		t.Fatalf("read the organization template: %v", err)
	}
	if view.Source != SourceEmbedded {
		t.Errorf("the answer reads %+v, want the embedded default back", view)
	}
}

// TestResetATemplateWithoutAnOverrideChangesNothing covers the revert of a level
// that already inherits. It is the state the revert asks for, so it answers the
// same way and records nothing.
func TestResetATemplateWithoutAnOverrideChangesNothing(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if err := svc.ResetTemplate(context.Background(), noteOperator, "", KeyPasswordReset); err != nil {
		t.Fatalf("remove an override that is not there: %v", err)
	}
	if len(noteEvents) != 0 {
		t.Errorf("the revert recorded %+v, want nothing", noteEvents)
	}
}

// TestTemplateRefusesAPersonWithoutTheRole covers the template gate. An
// ORG_OWNER writes the message of its own organization, and nothing else.
func TestTemplateRefusesAPersonWithoutTheRole(t *testing.T) {
	svc := testService(t, nil, orgOwner(noteOrgID))

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyPasswordReset,
		templateBody("Anything")); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner writes the tenant message %v, want ErrForbidden", err)
	}
	if _, err := svc.WriteTemplate(context.Background(), noteOperator, otherOrgID, KeyPasswordReset,
		templateBody("Anything")); !errors.Is(err, ErrForbidden) {
		t.Errorf("an owner writes another organization %v, want ErrForbidden", err)
	}
	if len(storedTemplates) != 0 {
		t.Errorf("the refused write stored %+v, want nothing", storedTemplates)
	}

	svc = testService(t, nil, []organization.Membership{
		{TenantID: noteTenantID, OrgID: noteOrgID, UserID: noteUserID,
			Roles: []string{organization.RoleOrgUserManager}},
	})
	if _, err := svc.ReadTemplate(context.Background(), noteOperator, noteOrgID, KeyPasswordReset); !errors.Is(err, ErrForbidden) {
		t.Errorf("a user manager reads the message %v, want ErrForbidden", err)
	}
}

// TestTemplateRefusesAnOrganizationNobodyHolds covers an org id that names
// nothing. A tenant manager passes the gate, so without this read a typed id
// would write a message no send would ever reach.
func TestTemplateRefusesAnOrganizationNobodyHolds(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	_, err := svc.ReadTemplate(context.Background(), noteOperator, "o-nothing", KeyPasswordReset)
	if !errors.Is(err, organization.ErrNotFound) {
		t.Errorf("an organization nobody holds reads %v, want organization.ErrNotFound", err)
	}
}

// TestPreviewRendersTheResolvedTemplateWithSampleData covers the preview. It
// renders the message the level actually sends, so an operator checks the
// override and not the embedded default.
func TestPreviewRendersTheResolvedTemplateWithSampleData(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	if _, err := svc.WriteTemplate(context.Background(), noteOperator, "", KeyPasswordReset,
		templateBody("Reset your password")); err != nil {
		t.Fatalf("write the tenant override: %v", err)
	}

	rendered, err := svc.PreviewTemplate(context.Background(), noteOperator, "", KeyPasswordReset)
	if err != nil {
		t.Fatalf("render the preview: %v", err)
	}
	if rendered.Subject != "Reset your password" {
		t.Errorf("the preview reads subject %q, want the override", rendered.Subject)
	}
	if !strings.Contains(rendered.Text, sample.DisplayName) || strings.Contains(rendered.Text, "{{") {
		t.Errorf("the preview reads text %q, want the sample data rendered", rendered.Text)
	}
	if !strings.Contains(rendered.HTML, sample.Link) {
		t.Errorf("the preview reads html %q, want the sample link", rendered.HTML)
	}
}

// TestPreviewRendersEveryEmbeddedDefault covers the messages the gateway ships
// with. A default that does not parse would fail on the first send, and no
// operator wrote it.
func TestPreviewRendersEveryEmbeddedDefault(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	for _, key := range Keys {
		rendered, err := svc.PreviewTemplate(context.Background(), noteOperator, "", key)
		if err != nil {
			t.Fatalf("render the embedded %s: %v", key, err)
		}
		if rendered.Subject == "" || rendered.Text == "" || rendered.HTML == "" {
			t.Errorf("the embedded %s renders %+v, want every part filled", key, rendered)
		}
	}
}
