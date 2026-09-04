package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/utils"
)

// Action is what happened. Only a defined action can be recorded, so a report
// can rely on the set of names it reads.
type Action string

const (
	ActionLoginSucceeded     Action = "login.succeeded"
	ActionLoginFailed        Action = "login.failed"
	ActionConsentGranted     Action = "consent.granted"
	ActionConsentDenied      Action = "consent.denied"
	ActionConsentRevoked     Action = "consent.revoked"
	ActionTokenIssued        Action = "token.issued"
	ActionTokenRefreshReused Action = "token.refresh_reused"
	ActionTokenRevoked       Action = "token.revoked"
	ActionLogoutSucceeded    Action = "logout.succeeded"

	ActionOrgCreated Action = "organization.created"
	ActionOrgUpdated Action = "organization.updated"
	ActionOrgDeleted Action = "organization.deleted"

	ActionProjectCreated Action = "project.created"
	ActionProjectUpdated Action = "project.updated"
	ActionProjectDeleted Action = "project.deleted"

	ActionAppCreated       Action = "application.created"
	ActionAppUpdated       Action = "application.updated"
	ActionAppDeleted       Action = "application.deleted"
	ActionAppSecretRotated Action = "application.secret_rotated"

	ActionUserCreated       Action = "user.created"
	ActionUserUpdated       Action = "user.updated"
	ActionUserDeleted       Action = "user.deleted"
	ActionUserActivated     Action = "user.activated"
	ActionUserDeactivated   Action = "user.deactivated"
	ActionUserUnlocked      Action = "user.unlocked"
	ActionUserPasswordReset Action = "user.password_reset"
	ActionUserMFAReset      Action = "user.mfa_reset"
	ActionUserInvited       Action = "user.invited"

	// ActionUserPasskeyRevoked records an operator revoking one Passkey of
	// somebody else, from the console. ActionMFAPasskeyRemoved is the same act by
	// the person who holds the device.
	//
	// The two never share a name. A support call about a lost laptop ends here,
	// and a trail that could not say who pressed the button is not the record of
	// it. ActionUserMFAReset is the wider act: it clears every Factor at once.
	ActionUserPasskeyRevoked Action = "user.passkey_revoked"

	// ActionPasswordChanged records a person changing their own password. The
	// administrative reset is ActionUserPasswordReset: an operator mints a token,
	// and the person here chose the new secret themselves.
	ActionPasswordChanged Action = "password.changed"

	// The four second-factor actions a person takes on their own account. The
	// administrative reset is ActionUserMFAReset: an operator clears somebody
	// else's factor, and the person here changed their own.
	//
	// The names are the ones the portal activity feed already renders. See
	// web/portal-ui/src/lib/activity.ts. A name that drifts from that map reads
	// as an unknown event in the feed.
	//
	// A successful challenge records none of these when the person answered with
	// their Authenticator. ActionLoginSucceeded already carries the factor it was
	// proved with. A redeemed Recovery Code records the same factor, so
	// ActionMFARecoveryCodeUsed is what tells the two apart.
	ActionMFAEnrolled                 Action = "mfa.enrolled"
	ActionMFARemoved                  Action = "mfa.removed"
	ActionMFARecoveryCodeUsed         Action = "mfa.recovery_code_used"
	ActionMFARecoveryCodesRegenerated Action = "mfa.recovery_codes_regenerated"

	// The Passkey actions. They never reuse the names above, because the trail
	// is the only record that a Factor existed, and a trail that cannot say
	// which credential was added is not that record.
	ActionMFAPasskeyRegistered Action = "mfa.passkey_registered"
	ActionMFAPasskeyRemoved    Action = "mfa.passkey_removed"

	ActionMemberAdded   Action = "member.added"
	ActionMemberUpdated Action = "member.updated"
	ActionMemberRemoved Action = "member.removed"

	ActionSessionRevoked Action = "session.revoked"

	ActionDomainAdded   Action = "tenant.domain_added"
	ActionDomainRemoved Action = "tenant.domain_removed"

	ActionProviderUpdated Action = "provider.updated"

	ActionScopeCreated Action = "scope.created"
	ActionScopeUpdated Action = "scope.updated"
	ActionScopeDeleted Action = "scope.deleted"

	ActionMapperCreated Action = "claim_mapper.created"
	ActionMapperUpdated Action = "claim_mapper.updated"
	ActionMapperDeleted Action = "claim_mapper.deleted"

	ActionAuthPolicyUpdated Action = "auth_policy.updated"
	ActionAuthPolicyReset   Action = "auth_policy.reset"

	ActionNotificationSettingsUpdated Action = "notification.settings_updated"
	ActionNotificationTestSent        Action = "notification.test_sent"
	ActionNotificationTemplateUpdated Action = "notification.template_updated"
	ActionNotificationTemplateReset   Action = "notification.template_reset"

	ActionFederationCreated  Action = "federation.created"
	ActionFederationUpdated  Action = "federation.updated"
	ActionFederationDeleted  Action = "federation.deleted"
	ActionFederationLinked   Action = "federation.linked"
	ActionFederationUnlinked Action = "federation.unlinked"
	ActionFederationTested   Action = "federation.tested"
)

// EntityOrganization names an organization in the entity_type column.
const EntityOrganization = "organization"

// EntityProject names a project in the entity_type column.
const EntityProject = "project"

// EntityApplication names an application in the entity_type column. A client
// secret rotation is recorded against the application, because the application
// is the thing an administrator names.
const EntityApplication = "application"

// EntityUser names one person in the entity_type column. Every administrative
// change to an account is recorded against the account, never against the
// administrator who made it: the actor column already names them.
const EntityUser = "user"

// EntityMember names one membership in the entity_type column. The entity id is
// the person the membership puts somewhere, because that is the handle an
// operator searches the trail by. The organization is in the metadata.
const EntityMember = "member"

// EntitySession names one login session in the entity_type column. A sign-in, a
// sign-out, and an administrative revoke all record against the session, so the
// three steps of one session read as one entity.
const EntitySession = "login_session"

// EntityTenantDomain names one hostname of a tenant in the entity_type column.
// The entity id is the host itself, because the host is what an operator names
// and it is globally unique.
const EntityTenantDomain = "tenant_domain"

// EntityProviderConfig names the protocol settings of a tenant in the
// entity_type column. The entity id is the tenant, because one tenant holds one
// provider config.
const EntityProviderConfig = "provider_config"

// EntityScope names one scope of a tenant in the entity_type column. The entity
// id is the row id, because a scope can be renamed and the trail still has to
// read as one entity.
const EntityScope = "oidc_scope"

// EntityClaimMapper names one claim mapper in the entity_type column. The entity
// id is the row id, and the scope it belongs to is in the metadata.
const EntityClaimMapper = "claim_mapper"

// EntityAuthPolicy names the lockout, password, and recovery rules of one level
// in the entity_type column. The entity id is the organization an override
// belongs to, and the tenant itself for the tenant default, because one level
// holds one policy.
const EntityAuthPolicy = "auth_policy"

// EntityNotificationSettings names the outbound-mail delivery of one tenant in
// the entity_type column. The entity id is the tenant, because one tenant holds
// one relay. A test send records against it too: it proves the same settings.
const EntityNotificationSettings = "notification_settings"

// EntityNotificationTemplate names one message template in the entity_type
// column. The entity id is the template key, because the key is what an operator
// names and it does not change. The level the override belongs to is in the
// metadata.
const EntityNotificationTemplate = "notification_template"

// EntityFederation names one User Federation in the entity_type column. The
// entity id is the federation row, and an unlink is recorded against the
// federation too: the link is hard deleted, so the trail is the only record that
// the person was ever tied to that directory. The person is in the metadata.
const EntityFederation = "federation"

// The two values the result column holds.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// ErrUnknownAction reports an action outside the defined set.
var ErrUnknownAction = errors.New("unknown audit action")

// ErrIncompleteEntry reports an entry without a tenant or without an entity
// type. Both columns are required, and a row without them answers no question.
var ErrIncompleteEntry = errors.New("incomplete audit entry")

// actionResults is the result of each action. The recorder derives the result,
// so a call site cannot record a denied consent or a replayed refresh token as
// a success.
var actionResults = map[Action]string{
	ActionLoginSucceeded:     ResultSuccess,
	ActionLoginFailed:        ResultFailure,
	ActionConsentGranted:     ResultSuccess,
	ActionConsentDenied:      ResultFailure,
	ActionConsentRevoked:     ResultSuccess,
	ActionTokenIssued:        ResultSuccess,
	ActionTokenRefreshReused: ResultFailure,
	ActionTokenRevoked:       ResultSuccess,
	ActionLogoutSucceeded:    ResultSuccess,
	ActionOrgCreated:         ResultSuccess,
	ActionOrgUpdated:         ResultSuccess,
	ActionOrgDeleted:         ResultSuccess,
	ActionProjectCreated:     ResultSuccess,
	ActionProjectUpdated:     ResultSuccess,
	ActionProjectDeleted:     ResultSuccess,
	ActionAppCreated:         ResultSuccess,
	ActionAppUpdated:         ResultSuccess,
	ActionAppDeleted:         ResultSuccess,
	ActionAppSecretRotated:   ResultSuccess,
	ActionUserCreated:        ResultSuccess,
	ActionUserUpdated:        ResultSuccess,
	ActionUserDeleted:        ResultSuccess,
	ActionUserActivated:      ResultSuccess,
	ActionUserDeactivated:    ResultSuccess,
	ActionUserUnlocked:       ResultSuccess,
	ActionUserPasswordReset:  ResultSuccess,
	ActionUserMFAReset:       ResultSuccess,
	ActionUserInvited:        ResultSuccess,
	ActionUserPasskeyRevoked: ResultSuccess,
	ActionPasswordChanged:    ResultSuccess,
	ActionMemberAdded:        ResultSuccess,
	ActionMemberUpdated:      ResultSuccess,
	ActionMemberRemoved:      ResultSuccess,
	ActionSessionRevoked:     ResultSuccess,
	ActionDomainAdded:        ResultSuccess,
	ActionDomainRemoved:      ResultSuccess,
	ActionProviderUpdated:    ResultSuccess,
	ActionScopeCreated:       ResultSuccess,
	ActionScopeUpdated:       ResultSuccess,
	ActionScopeDeleted:       ResultSuccess,
	ActionMapperCreated:      ResultSuccess,
	ActionMapperUpdated:      ResultSuccess,
	ActionMapperDeleted:      ResultSuccess,
	ActionAuthPolicyUpdated:  ResultSuccess,
	ActionAuthPolicyReset:    ResultSuccess,

	ActionNotificationSettingsUpdated: ResultSuccess,
	ActionNotificationTestSent:        ResultSuccess,
	ActionNotificationTemplateUpdated: ResultSuccess,
	ActionNotificationTemplateReset:   ResultSuccess,

	ActionFederationCreated:  ResultSuccess,
	ActionFederationUpdated:  ResultSuccess,
	ActionFederationDeleted:  ResultSuccess,
	ActionFederationUnlinked: ResultSuccess,

	// The link a first bind wrote. It is the only record that the sign-in
	// created the person, because the link itself is hard deleted.
	ActionFederationLinked: ResultSuccess,

	// The test ran. Which stage of it failed is a metadata key, because the
	// result column of one action is fixed and a failed dial is still a test
	// an administrator drove.
	ActionFederationTested: ResultSuccess,

	// A recovery code redeemed is a success: the person signed in with a factor
	// they hold. The failure it is often read beside is ActionLoginFailed.
	ActionMFAEnrolled:                 ResultSuccess,
	ActionMFARemoved:                  ResultSuccess,
	ActionMFARecoveryCodeUsed:         ResultSuccess,
	ActionMFARecoveryCodesRegenerated: ResultSuccess,
	ActionMFAPasskeyRegistered:        ResultSuccess,
	ActionMFAPasskeyRemoved:           ResultSuccess,
}

// allowedMetadata names every key the metadata bag can hold. It is an
// allow-list, not a deny-list: a credential cannot reach the trail under a name
// nobody thought of, because a name nobody listed is dropped.
var allowedMetadata = map[string]bool{
	"client_id":  true,
	"grant_id":   true,
	"org_id":     true,
	"user_id":    true,
	"sessions":   true,
	"grants":     true,
	"scopes":     true,
	"reason":     true,
	"error_code": true,
	// The factor a sign-in was proved with, such as "pwd" or "vc". It names a
	// method, never the secret behind it.
	"factor":     true,
	"scope_id":   true,
	"scope_name": true,
	"claim_name": true,
	// The name of a message template. It is a key of a fixed set, never a
	// recipient address and never a rendered message.
	"template_key": true,
	// The id of one Passkey, in the base64url spelling the browser uses. It is
	// a public handle that every assertion sends in the clear, and it is never
	// the public key blob beside it.
	"credential_id": true,
	// The stage of one connection test: the dial, the TLS handshake, the service
	// bind, or the search. It names a step of the exchange, never a value the
	// step carried.
	"stage": true,
	// The User Federation one event names. A failed sign-in records it, so an
	// operator reads which directory refused the password. It is the id of a row
	// the tenant registered, and never a credential of any kind.
	"federation_id": true,
	// The servers one connection test dialled. A test of a configuration nobody
	// saved yet names no stored row, so without this key the trail records that
	// somebody drove an outbound call and never records where it went. It holds
	// the host list an administrator typed, and never a credential.
	"servers": true,
}

// Entry is what a caller knows about the action it just took. Metadata holds
// non-secret context only. See allowedMetadata.
type Entry struct {
	TenantID   string
	ActorID    string
	Action     Action
	EntityType string
	EntityID   string
	IP         string
	UserAgent  string
	Metadata   map[string]any
}

// EventWriter writes one event. The recorder holds the writer as a function
// value, so the write runs on whatever connection the context carries: inside
// the caller's transaction, the row and the change land together.
type EventWriter func(ctx context.Context, event Event) error

// Recorder records what happened. It is the only way an audit row is written.
type Recorder struct {
	write EventWriter
	log   logger.Logger
}

func NewRecorder(write EventWriter, log logger.Logger) *Recorder {
	return &Recorder{write: write, log: log}
}

// Record writes one event on the caller's transaction. It returns the error of
// a failed write, so the caller rolls the change back with it: a change nobody
// can audit is not allowed to stand.
func (r *Recorder) Record(ctx context.Context, entry Entry) error {
	r.log.Debug("record audit event",
		logger.String("tenant_id", entry.TenantID),
		logger.String("action", string(entry.Action)), logger.RequestID(ctx))

	event, err := newEvent(entry, r.log)
	if err != nil {
		r.log.Error("build audit event",
			logger.String("tenant_id", entry.TenantID),
			logger.String("action", string(entry.Action)),
			logger.Err(err))
		return err
	}

	if err := r.write(ctx, event); err != nil {
		r.log.Error("write audit event",
			logger.String("tenant_id", entry.TenantID),
			logger.String("action", string(entry.Action)),
			logger.Err(err))
		return err
	}

	r.log.Debug("recorded audit event",
		logger.String("tenant_id", entry.TenantID),
		logger.String("action", string(entry.Action)),
		logger.String("event_id", event.ID), logger.RequestID(ctx))
	return nil
}

// newEvent maps one entry into the row that holds it.
func newEvent(entry Entry, log logger.Logger) (Event, error) {
	if entry.TenantID == "" || entry.EntityType == "" {
		return Event{}, fmt.Errorf("%w: action %s", ErrIncompleteEntry, entry.Action)
	}

	result, ok := actionResults[entry.Action]
	if !ok {
		return Event{}, fmt.Errorf("%w: %s", ErrUnknownAction, entry.Action)
	}

	metadata, err := marshalMetadata(entry, log)
	if err != nil {
		return Event{}, err
	}

	return Event{
		ID:         utils.NewUUIDv7(),
		TenantID:   entry.TenantID,
		ActorID:    entry.ActorID,
		Action:     string(entry.Action),
		EntityType: entry.EntityType,
		EntityID:   entry.EntityID,
		Result:     result,
		IP:         entry.IP,
		UserAgent:  entry.UserAgent,
		Metadata:   metadata,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// marshalMetadata turns the bag into the JSON the column holds. A key outside
// the allow-list is dropped and logged by name. The value is never logged,
// because the value is what a credential hides in.
func marshalMetadata(entry Entry, log logger.Logger) (string, error) {
	if len(entry.Metadata) == 0 {
		return "", nil
	}

	kept := make(map[string]any, len(entry.Metadata))
	for key, value := range entry.Metadata {
		if !allowedMetadata[key] {
			log.Warn("drop audit metadata key",
				logger.String("tenant_id", entry.TenantID),
				logger.String("action", string(entry.Action)),
				logger.String("key", key))
			continue
		}
		kept[key] = value
	}
	if len(kept) == 0 {
		return "", nil
	}

	data, err := json.Marshal(kept)
	if err != nil {
		return "", fmt.Errorf("marshal metadata of action %s: %w", entry.Action, err)
	}
	return string(data), nil
}
