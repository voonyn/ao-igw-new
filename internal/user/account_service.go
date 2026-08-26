package user

import (
	"context"
	"errors"
	"fmt"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrBadPassword reports a refused current password.
//
// A wrong password and an account the read cannot reach answer this one
// sentinel. The two refusals read alike, so the answer never says which accounts
// a tenant holds, or which of them can still sign in.
var ErrBadPassword = errors.New("current password is wrong")

// The reads and writes the self-service half of this domain composes its answers
// from. Each one is a function value, so the logic is testable without a
// database.
type (
	// ProfileUpdater writes the four identity fields of one person.
	// Repository.UpdateProfile has this shape.
	ProfileUpdater func(ctx context.Context, row Human) error

	// CredentialReader reads the organization and the stored password hash of
	// one live person. It returns ErrNotFound on a miss.
	// Repository.FindCredential has this shape.
	CredentialReader func(ctx context.Context, tenantID, userID string) (User, error)

	// PasswordWriter writes the new password hash of one person.
	// Repository.SetPassword has this shape.
	PasswordWriter func(ctx context.Context, tenantID, userID, hash string) error

	// PasswordChecker refuses a password that the resolved policy of the level
	// does not accept. authpolicy.Service.Enforce has this shape.
	//
	// The refusal names no rule, and the caller cannot classify what comes back:
	// a policy the read failed on and a password the policy refused are one
	// opaque error here. That is the price of the function value, and it is what
	// keeps this domain from importing the policy domain.
	PasswordChecker func(ctx context.Context, tenantID, orgID, plain string) error

	// SessionRevoker ends every login session of one person except the one
	// named, and the grants those sessions fanned out to.
	// session.AccountService.RevokeOthers has this shape, once the router
	// adapts the actor and drops the counts.
	SessionRevoker func(ctx context.Context, a Actor, exceptID string) error
)

// AccountDeps is what the self-service half of this domain reads and writes.
type AccountDeps struct {
	UpdateProfile ProfileUpdater

	Credential    CredentialReader
	SetPassword   PasswordWriter
	CheckPassword PasswordChecker
	RevokeOthers  SessionRevoker

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// AccountService answers the self-service account API.
//
// There is no role gate and no ownership check to write, because there is
// nothing to check: every method acts on the subject of the caller's token, and
// no method takes an account id. The bearer guard verified the subject.
type AccountService struct {
	deps AccountDeps
	log  logger.Logger
}

func NewAccountService(deps AccountDeps) *AccountService {
	return &AccountService{deps: deps, log: deps.Log}
}

// UpdateProfile writes the profile of the person who made the request.
//
// The account is a.UserID and nothing else names it. A body that carried
// another account id would not be read, because ProfileBody holds no such
// field.
func (s *AccountService) UpdateProfile(ctx context.Context, a Actor, body ProfileBody) error {
	s.log.Debug("update own profile",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	person := Human{
		UserID:      a.UserID,
		TenantID:    a.TenantID,
		FirstName:   body.FirstName,
		LastName:    body.LastName,
		DisplayName: body.DisplayName,
		Lang:        body.Locale,
	}

	err := s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.UpdateProfile(ctx, person); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionUserUpdated, a.UserID))
	})
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "update own profile", err)
	}

	s.log.Info("updated own profile",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID))
	return nil
}

// ChangePassword replaces the password of the person who made the request, once
// they prove that they hold the one stored now.
//
// The order is deliberate. The current password is checked first, so a caller
// who cannot prove who they are learns nothing about the policy. The new
// password is then checked against the policy of the level the person belongs
// to. Only then is anything written.
//
// exceptID is the login session the caller is using, as the portal reads it from
// the ID token it holds. Every other session of the person ends, because a person
// changes a password after they believe the old one leaked, and whoever holds it
// must lose access at this moment. With no session named, nothing is spared and
// the caller signs out everywhere too.
//
// The write, the revoke, and the audit event land on one transaction. A password
// that changed with the other devices still signed in would leave the leak open,
// and a change nobody can audit is not allowed to stand.
//
// Neither password reaches a log line, at any level and in any environment.
func (s *AccountService) ChangePassword(
	ctx context.Context, a Actor, body PasswordBody, exceptID string,
) error {
	s.log.Debug("change own password",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID), logger.RequestID(ctx))

	row, err := s.deps.Credential(ctx, a.TenantID, a.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return s.refuse(a, "the token names no account that can sign in")
		}
		return s.fail(a.TenantID, a.UserID, "read the credential", err)
	}

	if err := crypto.VerifyPassword(row.PasswordHash, body.CurrentPassword); err != nil {
		// A stored hash that cannot be parsed is a defect of the credential, not
		// a wrong password. The caller reads the same refusal either way, and
		// the log is where the two are told apart.
		if errors.Is(err, crypto.ErrMalformedHash) {
			s.log.Error("the stored password hash of the account cannot be read",
				logger.String("tenant_id", a.TenantID),
				logger.String("user_id", a.UserID), logger.Err(err))
		}
		return s.refuse(a, "the current password is wrong")
	}

	// A failed policy read is logged in the policy domain, which is the last
	// layer that can name the level the read was for. Nothing is logged again
	// here, and nothing classifies it: a read failure is unregistered in the
	// mapper, so it answers a server error, and only the refusal answers 400.
	if err := s.deps.CheckPassword(ctx, a.TenantID, row.OrgID, body.NewPassword); err != nil {
		return err
	}

	hash, err := crypto.HashPassword(body.NewPassword)
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "hash the new password", err)
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.SetPassword(ctx, a.TenantID, a.UserID, hash); err != nil {
			return err
		}
		if err := s.deps.RevokeOthers(ctx, a, exceptID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, a.entry(audit.ActionPasswordChanged, a.UserID))
	})
	if err != nil {
		return s.fail(a.TenantID, a.UserID, "change own password", err)
	}

	s.log.Info("changed own password",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("except_session_id", exceptID))
	return nil
}

// refuse answers one refused password change. The reason names the log line and
// never the answer, so a caller reads one refusal for every cause.
//
// Neither password reaches this line. why is a fixed string of this file.
func (s *AccountService) refuse(a Actor, why string) error {
	s.log.Warn("refused a password change",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID), logger.String("reason", why))
	return fmt.Errorf("%w: tenant %s, user %s", ErrBadPassword, a.TenantID, a.UserID)
}

// fail logs the error where it stops bubbling up and returns it unchanged, so
// the mapper still reads the sentinel behind it.
func (s *AccountService) fail(tenantID, userID, what string, err error) error {
	s.log.Error(what,
		logger.String("tenant_id", tenantID),
		logger.String("user_id", userID),
		logger.Err(err))
	return err
}
