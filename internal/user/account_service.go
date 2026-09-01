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

// ErrPasswordNotLocal reports a password change on an account the Directory
// owns. Such an account holds no local password hash, and the directory holds
// the rules, so nothing this gateway writes would reach the credential.
//
// The portal reads the same fact from PasswordLocal and hides the control, so a
// person meets this refusal only when the account changed under an open screen.
var ErrPasswordNotLocal = errors.New("the password of the account is not local")

// ErrDirectoryUnavailable reports a directory that could not answer a re-proof.
//
// It is not a wrong password, and it must never read as one. A person whose
// directory is off, unreachable, or over its bind budget is told to try again,
// and never that the password they typed is wrong.
var ErrDirectoryUnavailable = errors.New("the directory did not answer")

// ErrDirectoryNoEntry reports a person whom no single directory entry proves.
//
// Four states reach it: the person holds no live active Identity Link, the
// person holds more than one, the search matched no entry, and the search
// matched two. Each one is an answer, and each one stays until somebody edits
// the links or the directory.
//
// It is not a directory that could not answer, and it must never read as one. A
// person who meets it holds a broken account, nothing they do makes the next try
// work, and only an administrator can mend it. The answer says so.
var ErrDirectoryNoEntry = errors.New("no single directory entry holds the person")

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

	// DirectoryProver proves one password against the Directory that owns a
	// person. identityprovider.Service.ProveOwner has this shape, once the
	// composition root reads the username the bind searches on.
	//
	// It answers nil on a match, ErrDirectoryUnavailable when no directory could
	// answer, ErrDirectoryNoEntry when no single directory entry proves the
	// person, and any other error for a refusal. The password never reaches a log
	// line of this domain.
	DirectoryProver func(ctx context.Context, tenantID, userID, plain string) error

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

	// ProveDirectory is the re-proof of a person the Directory owns. It runs
	// wherever the stored hash is empty, which is what such a person holds.
	ProveDirectory DirectoryProver

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
		return s.readCredential(a, err)
	}
	// The Directory owns the credential and the rules that govern it, so there is
	// no local password to replace and no policy of this gateway that applies.
	// The refusal comes before the proof, because a person who cannot change a
	// password here must not be asked to prove one first.
	if row.PasswordHash == "" {
		s.log.Warn("refused a password change on an account the directory owns",
			logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
		return fmt.Errorf("%w: tenant %s, user %s", ErrPasswordNotLocal, a.TenantID, a.UserID)
	}
	if err := s.checkPassword(ctx, a, row.PasswordHash, body.CurrentPassword); err != nil {
		return err
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

// VerifyPassword proves that plain is the password the person holds now.
//
// The second-factor module takes this as a function value. Its two destructive
// portal addresses demand the same proof this domain's password change demands,
// and a second copy of the read and the check is how the two would come to
// answer a person differently.
//
// The password never reaches a log line.
func (s *AccountService) VerifyPassword(ctx context.Context, a Actor, plain string) error {
	s.log.Debug("verify the current password",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID),
		logger.RequestID(ctx))

	row, err := s.deps.Credential(ctx, a.TenantID, a.UserID)
	if err != nil {
		return s.readCredential(a, err)
	}
	return s.checkPassword(ctx, a, row.PasswordHash, plain)
}

// PasswordLocal reports whether the person who made the request holds a local
// password.
//
// The portal reads it and hides the password change for a person the Directory
// owns, rather than showing a control that always refuses. It answers a boolean
// and never the hash, so no caller of it handles a credential.
func (s *AccountService) PasswordLocal(ctx context.Context, a Actor) (bool, error) {
	s.log.Debug("read whether the password of the account is local",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID),
		logger.RequestID(ctx))

	row, err := s.deps.Credential(ctx, a.TenantID, a.UserID)
	if err != nil {
		return false, s.readCredential(a, err)
	}
	return row.PasswordHash != "", nil
}

// readCredential answers a failed credential read.
//
// An account the read cannot reach is refused the way a wrong password is, so
// the answer never says which accounts a tenant holds. Any other failure travels
// back as it was given, and it answers a server error.
func (s *AccountService) readCredential(a Actor, err error) error {
	if errors.Is(err, ErrNotFound) {
		return s.refuse(a, "the token names no account that can sign in")
	}
	return s.fail(a.TenantID, a.UserID, "read the credential", err)
}

// checkPassword proves plain against the credential the account holds now.
//
// An empty hash is not a broken hash. A person the Directory owns holds no local
// password, so an empty hash is what such a person stores, and the bind proves
// them. Without this branch the empty value reaches bcrypt, trips
// ErrMalformedHash, and writes an error line that says the stored hash cannot be
// read when nothing is wrong with it.
//
// A stored hash that cannot be parsed is a defect of the credential, not a wrong
// password. The caller reads the same refusal either way, and the log is where
// the two are told apart.
//
// The password never reaches a log line.
func (s *AccountService) checkPassword(ctx context.Context, a Actor, hash, plain string) error {
	if hash == "" {
		return s.proveDirectory(ctx, a, plain)
	}
	if err := crypto.VerifyPassword(hash, plain); err != nil {
		if errors.Is(err, crypto.ErrMalformedHash) {
			s.log.Error("the stored password hash of the account cannot be read",
				logger.String("tenant_id", a.TenantID),
				logger.String("user_id", a.UserID), logger.Err(err))
		}
		return s.refuse(a, "the current password is wrong")
	}
	return nil
}

// proveDirectory re-proves a person the Directory owns, with the bind that signs
// them in.
//
// The rule is one rule: prove the credential that signs you in. A person the
// Directory owns holds no local password, so a bcrypt compare here would refuse
// every one of them, and the destructive portal routes would be closed to them
// for ever.
//
// Two states travel back as themselves. A directory that could not answer says
// service unavailable, and a person whom no single directory entry proves says
// that. Neither ever reads as a wrong password. Every other failure reads as a
// refused password, which is what a wrong bind is.
//
// The password never reaches a log line, and the directory layer already logged
// whatever it saw.
func (s *AccountService) proveDirectory(ctx context.Context, a Actor, plain string) error {
	err := s.deps.ProveDirectory(ctx, a.TenantID, a.UserID, plain)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrDirectoryUnavailable), errors.Is(err, ErrDirectoryNoEntry):
		return err
	default:
		return s.refuse(a, "the directory refused the password")
	}
}

// refuse answers one refused password proof. The reason names the log line and
// never the answer, so a caller reads one refusal for every cause.
//
// The line says "proof" and not "change", because two callers reach it: the
// password change, and the second-factor module, which proves the same password
// before it strips an account of its factor.
//
// No password reaches this line. why is a fixed string of this file.
func (s *AccountService) refuse(a Actor, why string) error {
	s.log.Warn("refused a password proof",
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
