package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
// no Identity Link, and no bind writes one. A person who holds a link with this
// provider is refused there instead, because the link names an entry the bind
// did not prove.
//
// Provision runs last, and only when neither read named anybody. That is the
// first bind of somebody this gateway does not hold.
//
// a.Identifier is what the person typed. It reaches Provision, and nothing else
// here reads it: the guard of the first bind asks whether the tenant already
// holds an account for it, and the identifier step could not have found one.
func (s *Service) PersonOf(ctx context.Context, a Attempt, identity Identity) (string, error) {
	s.log.Debug("name the person the directory proved",
		logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID), logger.RequestID(ctx))

	linked, err := s.deps.FindLink(ctx, a.TenantID, a.IdpID, identity.ExternalID)
	if err != nil && !errors.Is(err, ErrLinkNotFound) {
		s.log.Error("read the identity link of a proved directory account",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID), logger.Err(err))
		return "", err
	}
	if linked != "" {
		// The identifier step reads active people alone, so a person it named
		// can sign in. A person the link names is read by no such filter, and an
		// administrator who deactivates or deletes somebody whose directory
		// account still lives must not see them sign in again. The refusal says
		// that the gateway cannot carry on, and never which people it holds.
		live, err := s.deps.CanSignIn(ctx, a.TenantID, linked)
		if err != nil {
			s.log.Error("read whether the person of an identity link can sign in",
				logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID),
				logger.String("user_id", linked), logger.Err(err))
			return "", err
		}
		if !live {
			s.log.Warn("refused a directory sign-in of a person who cannot sign in",
				logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID),
				logger.String("user_id", linked))
			return "", fmt.Errorf("%w: tenant %s, user %s", ErrDirectory, a.TenantID, linked)
		}

		s.log.Debug("the identity link names the person of this sign-in",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID),
			logger.String("user_id", linked), logger.RequestID(ctx))
		return linked, nil
	}
	if a.UserID != "" {
		// The link read missed, and that means one of two things. The person
		// holds no link with this provider, which is the local account a domain
		// claim routed to a directory, and the fallback below is right. Or the
		// person holds one and it names another entry of the same directory,
		// which is a directory that gave one identifier to a second entry: a
		// rename frees the old address, the directory hands it on, and the bind
		// proves somebody else. The sign-in never carries on as somebody the
		// proof did not name.
		//
		// The refusal says that the gateway cannot carry on, and never that the
		// password was wrong: it was proved. A slug of its own would say which
		// people the tenant holds.
		holds, err := s.deps.Linked(ctx, a.TenantID, a.UserID)
		if err != nil {
			s.log.Error("read the identity links of the person the session names",
				logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID),
				logger.String("user_id", a.UserID), logger.Err(err))
			return "", err
		}
		if slices.Contains(holds, a.IdpID) {
			s.log.Warn("refused a directory sign-in whose entry another identity link names",
				logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID),
				logger.String("user_id", a.UserID))
			return "", fmt.Errorf("%w: tenant %s, provider %s", ErrDirectory, a.TenantID, a.IdpID)
		}
		s.log.Debug("the login session names the person of this sign-in",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID),
			logger.String("user_id", a.UserID), logger.RequestID(ctx))
		return a.UserID, nil
	}

	created, err := s.Provision(ctx, a, identity)
	if err != nil {
		return "", err
	}
	s.log.Debug("the first bind created the person of this sign-in",
		logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID),
		logger.String("user_id", created), logger.RequestID(ctx))
	return created, nil
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
func (s *Service) Provision(ctx context.Context, a Attempt, identity Identity) (string, error) {
	s.log.Debug("create the person the directory proved",
		logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID), logger.RequestID(ctx))

	// The provider is read again, and not carried over from the bind, because
	// the row holds the bind credential in the clear and no layer above this
	// package handles it. The state is re-read with it, so a provider switched
	// off between the bind and this write creates nobody.
	row, err := s.deps.Find(ctx, a.TenantID, a.IdpID)
	if errors.Is(err, ErrNotFound) {
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrDisabled, a.TenantID, a.IdpID)
	}
	if err != nil {
		s.log.Error("read the identity provider of the first bind",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID), logger.Err(err))
		return "", err
	}
	if row.State != StateActive {
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrDisabled, a.TenantID, a.IdpID)
	}

	orgID := row.OrgID
	if orgID == "" {
		orgID = row.DefaultOrgID
	}
	if orgID == "" {
		s.log.Error("the identity provider names no organization to create people in",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID))
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrNoOrganization, a.TenantID, a.IdpID)
	}
	if identity.Username == "" {
		s.log.Error("the directory entry carries no username",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID))
		return "", fmt.Errorf("%w: tenant %s, provider %s", ErrNoUsername, a.TenantID, a.IdpID)
	}
	if err := s.heldAlready(ctx, a, identity); err != nil {
		return "", err
	}

	var userID string
	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		created, err := s.deps.CreatePerson(ctx, Person{
			TenantID:    a.TenantID,
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
			TenantID:   a.TenantID,
			IdpID:      a.IdpID,
			ExternalID: identity.ExternalID,
			UserID:     userID,
			CreatedAt:  time.Now().UTC(),
		}); err != nil {
			return err
		}
		// The person is the actor of their own sign-in. The link is hard
		// deleted, so this row is the only record that the bind created them.
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   a.TenantID,
			ActorID:    userID,
			Action:     audit.ActionIdpLinked,
			EntityType: audit.EntityIdentityProvider,
			EntityID:   a.IdpID,
			Metadata:   map[string]any{"user_id": userID, "org_id": orgID},
		})
	})
	if err != nil {
		// A username another person of the tenant already holds lands here, and
		// the transaction rolled back, so the refused sign-in leaves no half
		// person behind. The identifier is personal data, so it is not logged.
		s.log.Error("create the person the directory proved",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID), logger.Err(err))
		return "", err
	}

	s.log.Info("created the person the directory proved",
		logger.String("tenant_id", a.TenantID),
		logger.String("idp_id", a.IdpID),
		logger.String("org_id", orgID),
		logger.String("user_id", userID))
	return userID, nil
}

// heldAlready refuses a first bind whose person the tenant already holds, in any
// state.
//
// The identifier step reads active people alone, so a deactivated person and a
// soft-deleted one both name nobody there, and the sign-in reaches this write as
// a first bind. Provider Resolution carries a read that catches them, and case 1
// answers a claimed domain before it runs, so the claim alone routes an
// offboarded person straight here. See docs/specs/0002-directory-sign-in.md.
//
// Without this the create stands: uq_username maps a NULL deleted_at to an
// epoch, so the username of a soft-deleted person is free. The tenant then holds
// two rows for one person, the new one is active and holds a fresh organization
// membership, and the offboarding is undone. A deactivated person trips that key
// instead and answers a 500 after the password was proved. One refusal covers
// both.
//
// Three identifiers are read. What the person typed is the first, and it is the
// read Provider Resolution case 4 would have made: case 1 answers a claimed
// domain and returns before it, so this is where it lands instead. The username
// and the email address of the directory entry follow, because either one names
// a person the identifier step would have found under a form the person did not
// type. A provider that maps no email attribute leaves that one empty, and a
// person can be held under one form and not another, so a single read is not
// enough.
//
// The refusal is ErrDirectory, and never a credential failure. The password was
// proved, the person exists, and the gateway cannot carry on. A slug of its own
// would say that the tenant holds a row for that identifier, which is the
// enumeration answer the password step must not give.
//
// The read runs before the transaction, so two first binds of the same person at
// the same moment both pass it. uq_username then refuses the second insert, and
// the transaction leaves nothing behind, so the race costs a 500 and never a
// second row. An email address two rows share is not covered by that key, and no
// key exists to cover it. Both are the ceiling of this guard, and a unique key on
// the email address is the upgrade.
//
// The identifier is personal data, so neither it nor the answer reaches a log
// line.
func (s *Service) heldAlready(ctx context.Context, a Attempt, identity Identity) error {
	var read []string
	for _, name := range []string{a.Identifier, identity.Username, identity.Email} {
		if name == "" || slices.Contains(read, name) {
			continue
		}
		read = append(read, name)

		held, err := s.deps.Held(ctx, a.TenantID, name)
		if err != nil {
			s.log.Error("read whether the tenant already holds the account of a first bind",
				logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID), logger.Err(err))
			return err
		}
		if !held {
			continue
		}

		s.log.Warn("refused a first bind for a person the tenant already holds",
			logger.String("tenant_id", a.TenantID), logger.String("idp_id", a.IdpID))
		return fmt.Errorf("%w: tenant %s, provider %s", ErrDirectory, a.TenantID, a.IdpID)
	}
	return nil
}
