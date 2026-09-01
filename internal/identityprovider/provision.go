package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrNoOrganization reports a provider that names no organization to create
// people in. users.org_id is mandatory, so a tenant-wide row with an empty
// default_org_id creates nobody.
//
// The service refuses to save such a row and the console marks the field
// required, so a row that trips this was written around both.
var ErrNoOrganization = errors.New("the identity provider names no organization")

// ErrNoUsername reports a directory entry that carries no username. The person
// would hold no identifier to sign in with, so the first bind creates nobody.
var ErrNoUsername = errors.New("the directory entry carries no username")

// Person is the local person one first bind writes. It is not a user model: this
// package imports no user domain, and the composition root turns it into the
// rows it writes.
//
// It carries five of the six mapped attributes. The sixth is the stable external
// id, which the Identity Link holds and no column of the person does.
//
// There is no password hash. A person the directory owns holds none, ever.
type Person struct {
	TenantID    string
	OrgID       string
	Username    string
	Email       string
	FirstName   string
	LastName    string
	DisplayName string
}

// PersonOf answers the person one proved directory account signs in as.
//
// The Identity Link is read first, by the stable external id the bind read from
// the entry. It is the only key that holds. A provider maps the username and the
// email, and the person can type a third form that is neither, such as a User
// Principal Name, so the identifier step finds nobody. A sign-in that read "first
// bind" from that miss alone created the same person twice, and the second write
// failed on the username the first one took.
//
// The person the session already names answers next. That is the local account a
// domain claim routed to a directory: the identifier step found them, they hold
// no Identity Link, and no bind writes one.
//
// Provision runs last, and only when neither read named anybody. That is the
// first bind of somebody this gateway does not hold.
func (s *Service) PersonOf(
	ctx context.Context, tenantID, idpID, userID string, identity Identity,
) (string, error) {
	s.log.Debug("name the person the directory proved",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	linked, err := s.deps.FindLink(ctx, tenantID, idpID, identity.ExternalID)
	if err != nil && !errors.Is(err, ErrLinkNotFound) {
		s.log.Error("read the identity link of a proved directory account",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.Err(err))
		return "", err
	}
	if linked != "" {
		// The identifier step reads active people alone, so a person it named
		// can sign in. A person the link names is read by no such filter, and an
		// administrator who deactivates or deletes somebody whose directory
		// account still lives must not see them sign in again. The refusal says
		// that the gateway cannot carry on, and never which people it holds.
		live, err := s.deps.CanSignIn(ctx, tenantID, linked)
		if err != nil {
			s.log.Error("read whether the person of an identity link can sign in",
				logger.String("tenant_id", tenantID), logger.String("idp_id", idpID),
				logger.String("user_id", linked), logger.Err(err))
			return "", err
		}
		if !live {
			s.log.Warn("refused a directory sign-in of a person who cannot sign in",
				logger.String("tenant_id", tenantID), logger.String("idp_id", idpID),
				logger.String("user_id", linked))
			return "", fmt.Errorf("%w: tenant %s, user %s", ErrDirectory, tenantID, linked)
		}

		s.log.Debug("the identity link names the person of this sign-in",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID),
			logger.String("user_id", linked), logger.RequestID(ctx))
		return linked, nil
	}
	if userID != "" {
		return userID, nil
	}
	return s.Provision(ctx, tenantID, idpID, identity)
}

// Provision creates the person one directory account names, and writes the
// Identity Link that ties the two together. It answers the id of the person it
// created.
//
// It runs on the first successful bind of somebody this gateway does not hold,
// and on no other bind. A later sign-in of the same person names them already,
// so nothing here runs again: the create is the only write, and a rename in the
// directory never arrives. That ceiling is stated in
// docs/specs/0002-directory-sign-in.md, and refresh-on-bind is the upgrade.
//
// The person, the link, and the audit event land on one transaction. A person
// with no link would sign in against a local password hash that does not exist,
// and a change nobody can audit is not allowed to stand, so all three commit
// together or none do.
//
// The row is written active, with a NULL password hash, in the organization the
// provider names, and it holds no role. Not state 5: Invite writes state 5 with a
// NULL hash and SetPassword requires an active account, so an invited person can
// never set a first password, and this path must not ride on that defect.
//
// It is always a human account. Nothing here writes a machine account, and no
// caller can ask for one.
func (s *Service) Provision(ctx context.Context, tenantID, idpID string, identity Identity) (string, error) {
	s.log.Debug("create the person the directory proved",
		logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.RequestID(ctx))

	// The provider is read again, and not carried over from the bind, because
	// the row holds the bind credential in the clear and no layer above this
	// package handles it. The state is re-read with it, so a provider switched
	// off between the bind and this write creates nobody.
	row, err := s.deps.Find(ctx, tenantID, idpID)
	if errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrDisabled, tenantID, idpID)
	}
	if err != nil {
		s.log.Error("read the identity provider of the first bind",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.Err(err))
		return "", err
	}
	if row.State != StateActive {
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrDisabled, tenantID, idpID)
	}

	orgID := row.OrgID
	if orgID == "" {
		orgID = row.DefaultOrgID
	}
	if orgID == "" {
		s.log.Error("the identity provider names no organization to create people in",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID))
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrNoOrganization, tenantID, idpID)
	}
	if identity.Username == "" {
		s.log.Error("the directory entry carries no username",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID))
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrNoUsername, tenantID, idpID)
	}

	var userID string
	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		created, err := s.deps.CreatePerson(ctx, Person{
			TenantID:    tenantID,
			OrgID:       orgID,
			Username:    identity.Username,
			Email:       identity.Email,
			FirstName:   identity.FirstName,
			LastName:    identity.LastName,
			DisplayName: identity.DisplayName,
		})
		if err != nil {
			return err
		}
		userID = created

		if err := s.deps.WriteLink(ctx, Link{
			TenantID:   tenantID,
			IdpID:      idpID,
			ExternalID: identity.ExternalID,
			UserID:     userID,
			CreatedAt:  time.Now().UTC(),
		}); err != nil {
			return err
		}
		// The person is the actor of their own sign-in. The link is hard
		// deleted, so this row is the only record that the bind created them.
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    userID,
			Action:     audit.ActionIdpLinked,
			EntityType: audit.EntityIdentityProvider,
			EntityID:   idpID,
			Metadata:   map[string]any{"user_id": userID, "org_id": orgID},
		})
	})
	if err != nil {
		// A username another person of the tenant already holds lands here, and
		// the transaction rolled back, so the refused sign-in leaves no half
		// person behind. The identifier is personal data, so it is not logged.
		s.log.Error("create the person the directory proved",
			logger.String("tenant_id", tenantID), logger.String("idp_id", idpID), logger.Err(err))
		return "", err
	}

	s.log.Info("created the person the directory proved",
		logger.String("tenant_id", tenantID),
		logger.String("idp_id", idpID),
		logger.String("org_id", orgID),
		logger.String("user_id", userID))
	return userID, nil
}
