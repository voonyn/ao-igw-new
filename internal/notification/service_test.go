package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

const (
	noteTenantID = "t-1"
	noteUserID   = "u-1"
	noteOrgID    = "o-1"
	otherOrgID   = "o-2"
)

// noteOperator is the person every test of this package acts as.
var noteOperator = Actor{
	TenantID: noteTenantID, UserID: noteUserID, IP: "203.0.113.7", UserAgent: "a-browser",
}

// What the writes of one test left behind.
var (
	storedSettings  []Settings
	storedTemplates []Template
	removedKeys     []string
	sentMessages    []Message
	noteEvents      []audit.Event
)

// sendFails makes the transport refuse. A test sets it before the call it covers.
var sendFails bool

// testService builds the service over an in-memory store, with the roles the
// caller holds and the organizations they administer.
func testService(t *testing.T, roles []string, memberships []organization.Membership) *Service {
	t.Helper()
	log, _ := logger.NewObserved()
	storedSettings, storedTemplates, removedKeys, sentMessages, noteEvents = nil, nil, nil, nil, nil
	sendFails = false

	settings := map[string]Settings{}
	templates := map[string]Template{}
	key := func(orgID, name string) string { return orgID + "\x00" + name }

	return NewService(Deps{
		FindSettings: func(_ context.Context, tenantID string) (Settings, error) {
			row, ok := settings[tenantID]
			if !ok {
				return Settings{}, ErrNoSettings
			}
			return row, nil
		},
		UpsertSettings: func(_ context.Context, row Settings) error {
			settings[row.TenantID] = row
			storedSettings = append(storedSettings, row)
			return nil
		},
		FindTemplate: func(_ context.Context, _, orgID, name string) (Template, error) {
			row, ok := templates[key(orgID, name)]
			if !ok {
				return Template{}, ErrNoTemplate
			}
			return row, nil
		},
		UpsertTemplate: func(_ context.Context, row Template) error {
			templates[key(row.OrgID, row.Key)] = row
			storedTemplates = append(storedTemplates, row)
			return nil
		},
		RemoveTemplate: func(_ context.Context, _, orgID, name string) error {
			if _, ok := templates[key(orgID, name)]; !ok {
				return ErrNoTemplate
			}
			delete(templates, key(orgID, name))
			removedKeys = append(removedKeys, name)
			return nil
		},
		Send: func(_ context.Context, _ Settings, msg Message) error {
			if sendFails {
				return errors.New("the relay refused the message")
			}
			sentMessages = append(sentMessages, msg)
			return nil
		},
		Org: func(_ context.Context, _, orgID string) (organization.Organization, error) {
			if orgID != noteOrgID && orgID != otherOrgID {
				return organization.Organization{}, organization.ErrNotFound
			}
			return organization.Organization{ID: orgID, TenantID: noteTenantID}, nil
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) { return roles, nil },
		Memberships: func(context.Context, string, string) ([]organization.Membership, error) {
			return memberships, nil
		},
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			err := fn(ctx)
			if err != nil {
				storedSettings, storedTemplates, removedKeys = nil, nil, nil
			}
			return err
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			noteEvents = append(noteEvents, e)
			return nil
		}, log),
		Log: log,
	})
}

// orgOwner is the membership of a person who owns one organization.
func orgOwner(orgID string) []organization.Membership {
	return []organization.Membership{
		{TenantID: noteTenantID, OrgID: orgID, UserID: noteUserID,
			Roles: []string{organization.RoleOrgOwner}},
	}
}

// ptr answers the address of a value, so a test writes the write-only password
// the way the body carries one.
func ptr[T any](v T) *T { return &v }

// settingsBody is a complete delivery configuration, as the console submits one.
func settingsBody() SettingsBody {
	return SettingsBody{
		Transport: "smtp", SMTPHost: "smtp.example.com", SMTPPort: 587,
		SMTPUsername: "postmaster", FromAddress: "no-reply@example.com", FromName: "Example",
		TLSMode: "starttls", SendTimeoutSeconds: 10,
	}
}

// TestReadSettingsFallsBackToTheDefaultsWhenTheTenantStoresNothing covers the
// read of a tenant that never configured delivery. It is not a failure: the log
// transport applies, and it sends nothing.
func TestReadSettingsFallsBackToTheDefaultsWhenTheTenantStoresNothing(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMAdmin}, nil)

	view, err := svc.ReadSettings(context.Background(), noteOperator)
	if err != nil {
		t.Fatalf("read the delivery settings: %v", err)
	}
	if view.Transport != TransportLog || view.SMTPPort != DefaultSMTPPort {
		t.Errorf("the answer reads %+v, want the defaults", view)
	}
	if view.TLSMode != DefaultTLSMode || view.SendTimeoutSeconds != DefaultSendTimeoutSeconds {
		t.Errorf("the answer reads %+v, want the defaults", view)
	}
	if view.PasswordSet {
		t.Errorf("the answer reads %+v, want no stored password", view)
	}
}

// TestReadSettingsFallsBackToTheInstanceConfig covers the read of a tenant that
// stores no row on a deployment that configured a relay through
// AO_NOTIFICATION_*. Those values are what the tenant sends with, so the read
// answers them: the table defaults would report a log transport while real mail
// leaves the deployment.
func TestReadSettingsFallsBackToTheInstanceConfig(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMAdmin}, nil)
	svc.deps.Defaults = Settings{
		Transport: TransportSMTP, SMTPHost: "relay.example.net", SMTPPort: 465,
		SMTPUsername: "instance", Password: "an-instance-secret",
		FromAddress: "mail@example.net", FromName: "Example",
		TLSMode: "tls", SendTimeoutMS: 15000,
	}

	view, err := svc.ReadSettings(context.Background(), noteOperator)
	if err != nil {
		t.Fatalf("read the delivery settings: %v", err)
	}
	if view.Transport != TransportSMTP || view.SMTPHost != "relay.example.net" {
		t.Errorf("the answer reads %+v, want the instance relay", view)
	}
	if view.SMTPPort != 465 || view.TLSMode != "tls" || view.SendTimeoutSeconds != 15 {
		t.Errorf("the answer reads %+v, want the instance connection settings", view)
	}
	if !view.PasswordSet || !view.Configured {
		t.Errorf("the answer reads %+v, want a stored password and a usable transport", view)
	}
}

// TestWriteSettingsKeepsTheInstancePasswordOutOfTheTenantRow covers the base of
// the first write. The instance credential belongs to the deployment, so a write
// that omits a password stores none and the tenant keeps reading the instance
// value until it sets its own.
func TestWriteSettingsKeepsTheInstancePasswordOutOfTheTenantRow(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMAdmin}, nil)
	svc.deps.Defaults = Settings{
		Transport: TransportSMTP, SMTPHost: "relay.example.net", SMTPPort: 465,
		Password: "an-instance-secret", FromAddress: "mail@example.net",
		TLSMode: "tls", SendTimeoutMS: 15000,
	}

	if _, err := svc.WriteSettings(context.Background(), noteOperator, settingsBody()); err != nil {
		t.Fatalf("write the delivery settings: %v", err)
	}
	if len(storedSettings) != 1 {
		t.Fatalf("the write stored %d rows, want one", len(storedSettings))
	}
	if storedSettings[0].Password != "" {
		t.Error("the write copied the instance credential into the tenant row")
	}
}

// TestWriteSettingsStoresTheBodyAndAnswersWithoutThePassword covers one write.
// The password is write only: the answer reports that one is stored and never
// carries the value.
func TestWriteSettingsStoresTheBodyAndAnswersWithoutThePassword(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	body := settingsBody()
	body.SMTPPassword = ptr("a-relay-secret")

	view, err := svc.WriteSettings(context.Background(), noteOperator, body)
	if err != nil {
		t.Fatalf("write the delivery settings: %v", err)
	}
	if len(storedSettings) != 1 {
		t.Fatalf("the write stored %d rows, want one", len(storedSettings))
	}
	if row := storedSettings[0]; row.Password != "a-relay-secret" || row.SendTimeoutMS != 10000 {
		t.Errorf("the row reads timeout %d, want the body in milliseconds", row.SendTimeoutMS)
	}
	if !view.PasswordSet || !view.Configured {
		t.Errorf("the answer reads %+v, want a stored password and a usable transport", view)
	}
	if len(noteEvents) != 1 || noteEvents[0].Action != string(audit.ActionNotificationSettingsUpdated) {
		t.Fatalf("the write recorded %+v, want one settings event", noteEvents)
	}
	if noteEvents[0].EntityType != audit.EntityNotificationSettings || noteEvents[0].EntityID != noteTenantID {
		t.Errorf("the event reads %+v, want the tenant as the entity", noteEvents[0])
	}
}

// TestWriteSettingsNeverLogsThePassword covers the one field that must not reach
// a log line, at any level.
func TestWriteSettingsNeverLogsThePassword(t *testing.T) {
	log, logs := logger.NewObserved()
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)
	svc.log, svc.deps.Log = log, log

	body := settingsBody()
	body.SMTPPassword = ptr("a-relay-secret")

	if _, err := svc.WriteSettings(context.Background(), noteOperator, body); err != nil {
		t.Fatalf("write the delivery settings: %v", err)
	}
	for _, entry := range logs.All() {
		line := fmt.Sprintf("%s %v", entry.Message, entry.ContextMap())
		if strings.Contains(line, "a-relay-secret") {
			t.Errorf("the log line %q carries the password", line)
		}
	}
}

// TestWriteSettingsKeepsTheStoredPasswordWhenTheBodyOmitsIt covers the omitted
// field. The operator edited the host, not the credential.
func TestWriteSettingsKeepsTheStoredPasswordWhenTheBodyOmitsIt(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	first := settingsBody()
	first.SMTPPassword = ptr("a-relay-secret")
	if _, err := svc.WriteSettings(context.Background(), noteOperator, first); err != nil {
		t.Fatalf("write the delivery settings: %v", err)
	}

	second := settingsBody()
	second.SMTPHost = "relay.example.com"
	view, err := svc.WriteSettings(context.Background(), noteOperator, second)
	if err != nil {
		t.Fatalf("write the delivery settings again: %v", err)
	}
	if row := storedSettings[1]; row.Password != "a-relay-secret" {
		t.Errorf("the row reads password %q, want the stored one kept", row.Password)
	}
	if !view.PasswordSet || view.SMTPHost != "relay.example.com" {
		t.Errorf("the answer reads %+v, want the new host and the stored password", view)
	}
}

// TestWriteSettingsClearsThePasswordOnAnEmptyString covers the other half of the
// write-only rule. An empty string is the only way to remove the credential.
func TestWriteSettingsClearsThePasswordOnAnEmptyString(t *testing.T) {
	svc := testService(t, []string{tenant.RoleIAMOwner}, nil)

	first := settingsBody()
	first.SMTPPassword = ptr("a-relay-secret")
	if _, err := svc.WriteSettings(context.Background(), noteOperator, first); err != nil {
		t.Fatalf("write the delivery settings: %v", err)
	}

	second := settingsBody()
	second.SMTPPassword = ptr("")
	view, err := svc.WriteSettings(context.Background(), noteOperator, second)
	if err != nil {
		t.Fatalf("clear the password: %v", err)
	}
	if row := storedSettings[1]; row.Password != "" {
		t.Errorf("the row reads password %q, want it cleared", row.Password)
	}
	if view.PasswordSet {
		t.Errorf("the answer reads %+v, want no stored password", view)
	}
}

// TestSettingsRefuseAPersonWhoDoesNotManageTheTenant covers the settings gate.
// Delivery is tenant-wide, so an organization owner does not administer it.
func TestSettingsRefuseAPersonWhoDoesNotManageTheTenant(t *testing.T) {
	svc := testService(t, nil, orgOwner(noteOrgID))

	if _, err := svc.ReadSettings(context.Background(), noteOperator); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner reads the settings %v, want ErrForbidden", err)
	}
	if _, err := svc.WriteSettings(context.Background(), noteOperator, settingsBody()); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner writes the settings %v, want ErrForbidden", err)
	}
	if len(storedSettings) != 0 {
		t.Errorf("the refused write stored %+v, want nothing", storedSettings)
	}
}
