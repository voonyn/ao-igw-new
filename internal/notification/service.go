package notification

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// ErrForbidden reports a person who does not administer the level they named. A
// person who administers nothing and a person who administers another
// organization read the same refusal, so no answer reports what somebody else
// administers.
var ErrForbidden = errors.New("cannot administer these notifications")

// ErrSendFailed reports that the transport refused the message. The operator
// reads it as a configuration problem, because that is what it almost always is.
var ErrSendFailed = errors.New("the transport refused the message")

// Actor is the person behind one administrative request. The IP and the user
// agent reach the audit trail, and nothing else here reads them.
type Actor struct {
	TenantID  string
	UserID    string
	IP        string
	UserAgent string
}

// Message is one outbound mail, rendered and ready for a transport.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// The reads, writes, and sends the service composes its answers from. Each one
// is a function value, so the logic is testable without a database and without a
// relay.
type (
	// SettingsFinder reads the delivery settings of one tenant. A tenant that
	// stored nothing answers ErrNoSettings, which the service reads as "the
	// defaults apply".
	SettingsFinder func(ctx context.Context, tenantID string) (Settings, error)

	// SettingsUpserter writes the whole delivery row of one tenant.
	SettingsUpserter func(ctx context.Context, row Settings) error

	// TemplateFinder reads the override of one key at one level. A level that
	// stores nothing answers ErrNoTemplate, which the service reads as
	// "inherit the level below".
	TemplateFinder func(ctx context.Context, tenantID, orgID, key string) (Template, error)

	// TemplateUpserter writes the override of one key at one level.
	TemplateUpserter func(ctx context.Context, row Template) error

	// TemplateRemover marks the override of one key at one level deleted.
	TemplateRemover func(ctx context.Context, tenantID, orgID, key string) error

	// Sender hands one message to the transport the settings name.
	Sender func(ctx context.Context, settings Settings, msg Message) error

	// OrgFinder reads one organization. It returns organization.ErrNotFound on
	// a miss, so no org id can name a template for an organization the tenant
	// does not hold.
	OrgFinder func(ctx context.Context, tenantID, orgID string) (organization.Organization, error)

	// TenantRoleFinder reads the tenant roles of one person. A person with no
	// role gets an empty answer, not an error.
	TenantRoleFinder func(ctx context.Context, tenantID, userID string) ([]string, error)

	// MembershipLister reads the organization memberships of one person.
	MembershipLister func(ctx context.Context, tenantID, userID string) ([]organization.Membership, error)
)

// Deps is the database side and the transport side of the service.
type Deps struct {
	FindSettings   SettingsFinder
	UpsertSettings SettingsUpserter

	FindTemplate   TemplateFinder
	UpsertTemplate TemplateUpserter
	RemoveTemplate TemplateRemover

	Send Sender

	// Defaults is the instance-level delivery of the deployment, from the
	// AO_NOTIFICATION_* configuration. A tenant that stores no row sends with
	// these, so the read and the test send answer them.
	Defaults Settings

	Org         OrgFinder
	TenantRoles TenantRoleFinder
	Memberships MembershipLister

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// Service serves the delivery settings and the message templates of one tenant
// to the console.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// ReadSettings answers how this tenant sends mail. A tenant that configured
// nothing reads the defaults, and the answer never carries the SMTP password.
func (s *Service) ReadSettings(ctx context.Context, a Actor) (SettingsView, error) {
	s.log.Debug("read the delivery settings",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorizeTenant(ctx, a, "read the delivery settings"); err != nil {
		return SettingsView{}, err
	}

	stored, err := s.settings(ctx, a.TenantID)
	if err != nil {
		return SettingsView{}, s.fail(a, "read the delivery settings", err)
	}
	return stored.view(), nil
}

// WriteSettings replaces how this tenant sends mail and answers what then holds.
//
// The SMTP password is write only. A body that omits it keeps the stored
// credential, an empty string clears it, and the answer reports only that one is
// stored.
func (s *Service) WriteSettings(ctx context.Context, a Actor, body SettingsBody) (SettingsView, error) {
	s.log.Debug("write the delivery settings",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))

	if err := s.authorizeTenant(ctx, a, "write the delivery settings"); err != nil {
		return SettingsView{}, err
	}

	var view SettingsView
	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		stored, err := s.base(ctx, a.TenantID)
		if err != nil {
			return err
		}

		written := body.apply(stored)
		if err := s.deps.UpsertSettings(ctx, written); err != nil {
			return err
		}
		if err := s.record(ctx, a, audit.ActionNotificationSettingsUpdated,
			audit.EntityNotificationSettings, a.TenantID, nil); err != nil {
			return err
		}

		view = written.view()
		return nil
	})
	if err != nil {
		return SettingsView{}, s.fail(a, "write the delivery settings", err)
	}

	s.log.Info("wrote the delivery settings",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("transport", view.Transport))
	return view, nil
}

// SendTest delivers one diagnostic message over this tenant's transport.
//
// It renders the template the tenant actually sends, so a message that arrives
// proves the settings and the template together. The recipient never reaches a
// log line and never reaches the audit trail: the address is a person, and the
// event already names the operator who asked for the send.
func (s *Service) SendTest(ctx context.Context, a Actor, body TestBody) error {
	s.log.Debug("send a test message",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("template_key", body.Template))

	if err := s.authorizeTenant(ctx, a, "send a test message"); err != nil {
		return err
	}
	if !known(body.Template) {
		return fmt.Errorf("%w: %s", ErrUnknownTemplate, body.Template)
	}

	settings, err := s.settings(ctx, a.TenantID)
	if err != nil {
		return s.fail(a, "read the delivery settings", err)
	}

	found, err := s.resolve(ctx, a.TenantID, "", body.Template)
	if err != nil {
		return s.fail(a, "read the message template", err)
	}
	rendered, err := found.content.render(sample)
	if err != nil {
		return s.fail(a, "render the message template", err)
	}

	// The send runs outside the transaction. A message the relay accepted cannot
	// be rolled back, so the event is recorded after the send and only then.
	msg := Message{To: body.To, Subject: rendered.Subject, Text: rendered.Text, HTML: rendered.HTML}
	if err := s.deps.Send(ctx, settings, msg); err != nil {
		s.log.Error("the transport refused the test message",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID),
			logger.String("transport", settings.Transport),
			logger.Err(err))
		return fmt.Errorf("%w: tenant %s: %v", ErrSendFailed, a.TenantID, err)
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		return s.record(ctx, a, audit.ActionNotificationTestSent,
			audit.EntityNotificationSettings, a.TenantID,
			map[string]any{"template_key": body.Template})
	})
	if err != nil {
		return s.fail(a, "record the test message", err)
	}

	s.log.Info("sent a test message",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("transport", settings.Transport),
		logger.String("template_key", body.Template))
	return nil
}

// ListTemplates answers every message key the gateway sends, with the level each
// one resolves from at the scope that was read.
//
// An empty orgID reads the tenant scope.
func (s *Service) ListTemplates(ctx context.Context, a Actor, orgID string) ([]TemplateInfo, error) {
	s.log.Debug("list the message templates",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID))

	if err := s.authorize(ctx, a, orgID, "list the message templates"); err != nil {
		return nil, err
	}

	// ponytail: one or two reads per key, and there are three keys. Fold it into
	// one query over the whole scope when the set grows past a screenful.
	rows := make([]TemplateInfo, 0, len(Keys))
	for _, key := range Keys {
		found, err := s.resolve(ctx, a.TenantID, orgID, key)
		if err != nil {
			return nil, s.fail(a, "list the message templates", err)
		}

		info := TemplateInfo{Key: key, Source: found.source, IsOverride: found.own != nil}
		if found.own != nil && !found.own.UpdatedAt.IsZero() {
			at := found.own.UpdatedAt
			info.UpdatedAt = &at
		}
		rows = append(rows, info)
	}
	return rows, nil
}

// ReadTemplate answers the message one level sends, and names the level it comes
// from.
func (s *Service) ReadTemplate(ctx context.Context, a Actor, orgID, key string) (TemplateView, error) {
	s.log.Debug("read a message template",
		logger.String("tenant_id", a.TenantID),
		logger.String("org_id", orgID),
		logger.String("template_key", key))

	found, err := s.readable(ctx, a, orgID, key, "read a message template")
	if err != nil {
		return TemplateView{}, err
	}

	return TemplateView{
		Key:        key,
		IsOverride: found.own != nil,
		Source:     found.source,
		Subject:    found.content.Subject,
		BodyText:   found.content.BodyText,
		BodyHTML:   found.content.BodyHTML,
	}, nil
}

// PreviewTemplate renders the message one level sends, with sample data. It
// renders what resolves at that level, so an operator checks the override they
// are editing and not the message underneath it.
func (s *Service) PreviewTemplate(ctx context.Context, a Actor, orgID, key string) (RenderedView, error) {
	s.log.Debug("render a message template",
		logger.String("tenant_id", a.TenantID),
		logger.String("org_id", orgID),
		logger.String("template_key", key))

	found, err := s.readable(ctx, a, orgID, key, "render a message template")
	if err != nil {
		return RenderedView{}, err
	}

	rendered, err := found.content.render(sample)
	if err != nil {
		return RenderedView{}, s.fail(a, "render a message template", err)
	}
	return rendered, nil
}

// WriteTemplate replaces the override of one key at one level and answers the
// message that then sends.
//
// A message that does not parse is refused before it is stored: every send of
// the key would fail on it, and the operator would learn that from a reset mail
// that never arrives.
func (s *Service) WriteTemplate(ctx context.Context, a Actor, orgID, key string, body TemplateBody) (TemplateView, error) {
	s.log.Debug("write a message template",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("template_key", key))

	if !known(key) {
		return TemplateView{}, fmt.Errorf("%w: %s", ErrUnknownTemplate, key)
	}
	if err := s.authorize(ctx, a, orgID, "write a message template"); err != nil {
		return TemplateView{}, err
	}

	row := body.row(a.TenantID, orgID, key)
	if err := row.content().parse(); err != nil {
		return TemplateView{}, err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.UpsertTemplate(ctx, row); err != nil {
			return err
		}
		return s.record(ctx, a, audit.ActionNotificationTemplateUpdated,
			audit.EntityNotificationTemplate, key,
			map[string]any{"org_id": orgID, "template_key": key})
	})
	if err != nil {
		return TemplateView{}, s.fail(a, "write a message template", err)
	}

	s.log.Info("wrote a message template",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("template_key", key))

	source := SourceTenant
	if orgID != "" {
		source = SourceOrg
	}
	return TemplateView{
		Key: key, IsOverride: true, Source: source,
		Subject: body.Subject, BodyText: body.BodyText, BodyHTML: body.BodyHTML,
	}, nil
}

// ResetTemplate removes the override of one key at one level, so the message
// goes back to the level below: the tenant message for an organization, and the
// embedded default for the tenant.
//
// A level that holds no override is already in the state the revert asks for, so
// the answer is the same and nothing is recorded.
func (s *Service) ResetTemplate(ctx context.Context, a Actor, orgID, key string) error {
	s.log.Debug("remove a message template override",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("template_key", key))

	if !known(key) {
		return fmt.Errorf("%w: %s", ErrUnknownTemplate, key)
	}
	if err := s.authorize(ctx, a, orgID, "remove a message template override"); err != nil {
		return err
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.RemoveTemplate(ctx, a.TenantID, orgID, key); err != nil {
			if errors.Is(err, ErrNoTemplate) {
				return nil
			}
			return err
		}
		return s.record(ctx, a, audit.ActionNotificationTemplateReset,
			audit.EntityNotificationTemplate, key,
			map[string]any{"org_id": orgID, "template_key": key})
	})
	if err != nil {
		return s.fail(a, "remove a message template override", err)
	}

	s.log.Info("removed a message template override",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("template_key", key))
	return nil
}

// readable is the shared front of the two template reads: the key is one the
// gateway sends, the caller administers the level, and the message resolves.
func (s *Service) readable(ctx context.Context, a Actor, orgID, key, what string) (resolution, error) {
	if !known(key) {
		return resolution{}, fmt.Errorf("%w: %s", ErrUnknownTemplate, key)
	}
	if err := s.authorize(ctx, a, orgID, what); err != nil {
		return resolution{}, err
	}

	found, err := s.resolve(ctx, a.TenantID, orgID, key)
	if err != nil {
		return resolution{}, s.fail(a, what, err)
	}
	return found, nil
}

// resolution is where one message came from. own is the row of the level that
// was read, and it is nil when that level stores none: the console reverts what
// the level holds, and it can only revert a row that is there.
type resolution struct {
	content Content
	source  string
	own     *Template
}

// resolve answers the message one level sends. The organization override wins
// over the tenant one, which wins over the message the gateway ships.
func (s *Service) resolve(ctx context.Context, tenantID, orgID, key string) (resolution, error) {
	if orgID != "" {
		row, err := s.override(ctx, tenantID, orgID, key)
		if err != nil {
			return resolution{}, err
		}
		if row != nil {
			return resolution{content: row.content(), source: SourceOrg, own: row}, nil
		}
	}

	row, err := s.override(ctx, tenantID, "", key)
	if err != nil {
		return resolution{}, err
	}
	if row != nil {
		found := resolution{content: row.content(), source: SourceTenant}
		if orgID == "" {
			found.own = row
		}
		return found, nil
	}

	return resolution{content: embedded[key], source: SourceEmbedded}, nil
}

// override reads the row of one level, and answers nil when the level stores
// none. A level that stores nothing is not a failure: it inherits the one below.
func (s *Service) override(ctx context.Context, tenantID, orgID, key string) (*Template, error) {
	row, err := s.deps.FindTemplate(ctx, tenantID, orgID, key)
	switch {
	case errors.Is(err, ErrNoTemplate):
		return nil, nil
	case err != nil:
		return nil, err
	default:
		return &row, nil
	}
}

// settings answers how this tenant sends today: the row it stores, or the
// instance-level configuration of the deployment when it stores none.
//
// The read and the test send both go through here, so the console reports the
// relay that mail actually leaves by.
func (s *Service) settings(ctx context.Context, tenantID string) (Settings, error) {
	return s.find(ctx, tenantID, s.instance(tenantID))
}

// base answers the row one write starts from. A tenant that stores none starts
// from the table defaults and not from the instance configuration: the
// instance credential belongs to the deployment, and a write that omits a
// password must not copy it into a tenant row.
func (s *Service) base(ctx context.Context, tenantID string) (Settings, error) {
	return s.find(ctx, tenantID, defaultSettings(tenantID))
}

// find reads the stored row, and answers the fallback when the tenant stores
// none. Storing nothing is not a failure.
func (s *Service) find(ctx context.Context, tenantID string, fallback Settings) (Settings, error) {
	row, err := s.deps.FindSettings(ctx, tenantID)
	switch {
	case errors.Is(err, ErrNoSettings):
		return fallback, nil
	case err != nil:
		return Settings{}, err
	default:
		return row, nil
	}
}

// instance is the delivery the deployment configured, named for this tenant. A
// deployment that configured nothing carries the table defaults, which the
// configuration layer already fills in.
func (s *Service) instance(tenantID string) Settings {
	row := s.deps.Defaults
	if row.Transport == "" {
		row = defaultSettings(tenantID)
	}
	row.TenantID = tenantID
	return row
}

// record writes one audit event on the caller's transaction.
func (s *Service) record(ctx context.Context, a Actor, action audit.Action,
	entityType, entityID string, metadata map[string]any) error {
	return s.deps.Audit.Record(ctx, audit.Entry{
		TenantID:   a.TenantID,
		ActorID:    a.UserID,
		Action:     action,
		EntityType: entityType,
		EntityID:   entityID,
		IP:         a.IP,
		UserAgent:  a.UserAgent,
		Metadata:   metadata,
	})
}

// authorizeTenant is the gate of the delivery settings and the test send. One
// relay serves the whole tenant, so only a tenant manager administers it: an
// organization owner who could change the host would change how every other
// organization sends.
func (s *Service) authorizeTenant(ctx context.Context, a Actor, what string) error {
	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}
	if slices.Contains(roles, tenant.RoleIAMOwner) || slices.Contains(roles, tenant.RoleIAMAdmin) {
		return nil
	}

	s.log.Warn("refused a person who does not hold the role",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// authorize is the gate of the message templates.
//
// A tenant manager administers the tenant-wide message and every organization's
// own. An ORG_OWNER administers the override of its own organization and nothing
// else: the message carries the name a person of that organization reads, so an
// ORG_USER_MANAGER who administers the people is not enough.
//
// An organization the tenant does not hold is refused before the gate answers,
// so a typed id cannot write a message nobody can reach.
func (s *Service) authorize(ctx context.Context, a Actor, orgID, what string) error {
	if orgID == "" {
		return s.authorizeTenant(ctx, a, what)
	}

	if _, err := s.deps.Org(ctx, a.TenantID, orgID); err != nil {
		if errors.Is(err, organization.ErrNotFound) {
			return err
		}
		return s.fail(a, "read the organization", err)
	}

	roles, err := s.deps.TenantRoles(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read tenant roles", err)
	}
	if slices.Contains(roles, tenant.RoleIAMOwner) || slices.Contains(roles, tenant.RoleIAMAdmin) {
		return nil
	}

	memberships, err := s.deps.Memberships(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.fail(a, "read organization memberships", err)
	}
	for _, m := range memberships {
		if m.OrgID == orgID && slices.Contains(m.Roles, organization.RoleOrgOwner) {
			return nil
		}
	}

	s.log.Warn("refused a person who does not hold the role",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("org_id", orgID),
		logger.String("what", what))
	return fmt.Errorf("%w: %s, tenant %s, user %s", ErrForbidden, what, a.TenantID, a.UserID)
}

// fail logs one failed step and returns it. The error stops bubbling as a 500,
// so it is logged exactly once, here.
func (s *Service) fail(a Actor, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.Err(err))
	return err
}
