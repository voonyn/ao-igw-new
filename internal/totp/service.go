package totp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"alphaomega/identitygateway/internal/audit"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
)

// The sentinels this domain answers with.
var (
	// ErrPasswordNotProved reports a Login Session that has not proved a
	// password. Every second-factor address refuses one.
	//
	// This is the most important guard in the module. A session exists from the
	// identifier step onward and already names a person, so without it anybody
	// who knows an identifier could enrol a factor on that account and then sign
	// in with it.
	ErrPasswordNotProved = errors.New("login session has not proved a password")

	// ErrAlreadyEnrolled reports a start against an active Second Factor. The
	// person removes the factor they hold before they enrol another.
	ErrAlreadyEnrolled = errors.New("an active second factor is already enrolled")

	// ErrNoPendingEnrolment reports an activation with no pending secret to
	// prove. A start that was never made, and an enrolment that is already
	// active, both give it.
	ErrNoPendingEnrolment = errors.New("no pending totp enrolment")

	// ErrNoActiveFactor reports a challenge against an account that holds no
	// active Second Factor. Only the password answer sends a person to the
	// challenge, so a request that reaches it without a factor is a client that
	// went its own way.
	ErrNoActiveFactor = errors.New("no active second factor")

	// ErrBadCode reports a code the secret does not prove.
	//
	// A wrong code from the Authenticator, a code the account already spent, and
	// a Recovery Code no row still holds all give it. The answer never says
	// which of them happened, and it never says which kind of value was sent.
	ErrBadCode = errors.New("the code is wrong")

	// ErrSignInEnded reports the wrong code that used up the Login Session. The
	// session is terminated, and the person starts the sign-in again.
	//
	// It is not ErrBadCode. A person told the code is wrong tries another one,
	// and this answer tells them there is nothing left to try on this sign-in.
	ErrSignInEnded = errors.New("too many wrong codes ended the sign-in")

	// ErrTooManyAttempts reports a person who spent the whole guessing budget of
	// the trailing window, across every sign-in they opened.
	ErrTooManyAttempts = errors.New("too many second-factor attempts")

	// ErrBudgetUnavailable reports a guessing budget nobody could read. The
	// submission is refused, the same way a spent budget refuses it.
	//
	// It is not ErrTooManyAttempts. Both refuse, and the two ask the person for
	// different things: a spent budget asks them to wait, and this asks them to
	// try again. A person told to wait out an outage waits for nothing, because
	// no amount of waiting refills a budget that cannot be read.
	ErrBudgetUnavailable = errors.New("the second-factor guessing budget is unavailable")
)

// attemptLimit and attemptWindow cap second-factor guessing per person, across
// every sign-in that person opens.
//
// The per-session cap alone is not enough. Ending a session is free: an attacker
// who already holds the password answers one identifier step and one password
// step, and buys five fresh guesses. This cap is the one budget a restart cannot
// reset, so it is what makes the total bounded.
//
// The limit is three sessions' worth of the per-session cap. A person who
// mistypes their way out of one sign-in still has two more before they wait.
//
// ponytail: two constants. Move them into a tenant policy row when a tenant asks
// for its own numbers.
const (
	attemptLimit  = 15
	attemptWindow = 15 * time.Minute
)

// attemptKey names the guessing budget of one person. The tenant id is part of
// the key, so a person of one tenant never spends the budget of another.
func attemptKey(tenantID, userID string) string {
	return fmt.Sprintf("mfa_attempts:%s:%s", tenantID, userID)
}

// Principal is what the login side knows about the session one token
// credentials: which person it names, and whether a password was proved on it.
//
// It is not the login session type. This module imports neither the login
// session domain nor the user domain, so the router projects the session onto
// this shape.
type Principal struct {
	SessionID      string
	UserID         string
	PasswordProved bool
	IP             string
	UserAgent      string
}

// The reads and writes the service composes its answers from. Each one is a
// function value, so the logic is testable without a database.
type (
	// SessionFinder reads the Login Session one token credentials. The token is
	// a credential, so only the session id it answers reaches a log line.
	SessionFinder func(ctx context.Context, tenantID, token string) (Principal, error)

	// SessionCompleter records the OTP factor on the Login Session and rotates
	// its token. It answers the rotated token, disclosed exactly once.
	//
	// The factor name lives with the login session domain, which owns every AMR
	// name. The router closes over it, so it is spelled in one place.
	SessionCompleter func(ctx context.Context, tenantID, token, userID string) (string, error)

	// Account names one person on the provisioning URI: the email address, and
	// the username when the account holds no email.
	Account func(ctx context.Context, tenantID, userID string) (string, error)

	// EnrolmentFinder reads the TOTP row of one person. It returns
	// ErrNoEnrolment on a miss.
	EnrolmentFinder func(ctx context.Context, tenantID, userID string) (Enrolment, error)

	// PendingSaver writes a fresh pending enrolment over whatever pending row
	// the person held.
	PendingSaver func(ctx context.Context, tenantID, userID string, secret []byte) error

	// Activator turns a pending enrolment into an active factor and spends the
	// time step the code proved. It names the secret that was verified, so only
	// the secret a code proved is ever activated.
	Activator func(ctx context.Context, tenantID, userID string, secret []byte, step int64) error

	// RecoveryCodeWriter voids every Recovery Code of one person and stores the
	// new set of digests.
	RecoveryCodeWriter func(ctx context.Context, tenantID, userID string, digests []string) error

	// RecoveryCodeCounter counts the Recovery Codes one person still holds. It
	// reads no digest, because the number is the whole answer.
	RecoveryCodeCounter func(ctx context.Context, tenantID, userID string) (int, error)

	// FactorClearer destroys the Second Factor of one person: the shared secret
	// and every Recovery Code behind it. Both deletes are hard, so a later
	// enrolment starts clean.
	FactorClearer func(ctx context.Context, tenantID, userID string) error

	// PasswordVerifier proves the current password of one person. It answers nil
	// when the password is the one stored now, and the wrong-password sentinel
	// of the user domain otherwise.
	//
	// The portal owns the two destructive addresses of this module, and an
	// access token alone cannot guard them: the token carries no session
	// identifier and the bearer guard reads no store, so the body is the only
	// place a proof can go.
	//
	// The router points it at the same check the password change runs, so this
	// module imports neither the user domain nor the password hashing, and that
	// one check is the layer that logs a wrong password and a failed read at the
	// level each deserves. Nothing is logged on this side.
	//
	// The password never reaches a log line.
	PasswordVerifier func(ctx context.Context, tenantID, userID, plain string) error

	// StepSpender claims one TOTP time step for one person. It returns
	// ErrCodeSpent for a step at or below the newest spent one.
	StepSpender func(ctx context.Context, tenantID, userID string, step int64) error

	// RecoveryCodeRedeemer spends one Recovery Code of one person, named by the
	// digest of its canonical spelling. It returns ErrCodeSpent when no row
	// holds the digest, which covers both an unknown code and a spent one.
	RecoveryCodeRedeemer func(ctx context.Context, tenantID, userID, digest string) error

	// CodeFailer records one wrong code against the Login Session, and reports
	// whether this code ended it. The cap and the audit row belong to the login
	// session domain, which this module does not import.
	CodeFailer func(ctx context.Context, tenantID, token string) (bool, error)

	// RateLimiter records one hit against key and reports whether the trailing
	// window is still within limit. cache.Client.AllowInWindow satisfies it.
	RateLimiter func(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
)

// Deps is the database side of the service.
type Deps struct {
	FindSession     SessionFinder
	CompleteSession SessionCompleter
	Account         Account

	Find               EnrolmentFinder
	SavePending        PendingSaver
	Activate           Activator
	SaveRecoveryCodes  RecoveryCodeWriter
	CountRecoveryCodes RecoveryCodeCounter
	SpendStep          StepSpender
	RedeemRecoveryCode RecoveryCodeRedeemer
	ClearFactor        FactorClearer

	// VerifyPassword guards the two destructive portal addresses. Nothing on the
	// sign-in path reads it.
	VerifyPassword PasswordVerifier

	// The two caps on code guessing. FailCode counts against one sign-in, and
	// Allow counts against one person across every sign-in they open.
	FailCode CodeFailer
	Allow    RateLimiter

	// Cipher seals the shared secret at rest. A nil cipher matches the
	// development bootstrap, which stores it in the clear, the way the login
	// session and the OIDC storage already do.
	Cipher *aocrypto.Cipher

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// Service runs the two enrolment steps of the sign-in.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// Started is what a start answers: the shared secret in text, and the same
// secret inside a provisioning URI.
//
// Both are disclosed on every start, because an enrolment that was abandoned is
// started again. Neither reaches a log line.
type Started struct {
	Secret     string
	OtpauthURI string
}

// Activated is what an activation answers: the rotated Login Session token, and
// the Recovery Codes.
//
// The codes are disclosed exactly once, here. Neither field reaches a log line.
type Activated struct {
	SessionToken  string
	RecoveryCodes []string
}

// Start mints a pending TOTP Enrolment for the person the Login Session names.
//
// It records no factor and it does not rotate the session token. Nothing about
// the account changes until a code proves the secret.
//
// A start against an active factor is refused. A start against a pending
// enrolment mints a fresh secret and replaces it, so a person who abandoned a
// setup can begin again. A pending row has no expiry: it is scratch state, and
// the next start overwrites it.
func (s *Service) Start(ctx context.Context, tenantID, issuer, token string) (Started, error) {
	s.log.Debug("start a totp enrolment",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	who, err := s.principal(ctx, tenantID, token)
	if err != nil {
		return Started{}, err
	}
	return s.start(ctx, tenantID, issuer, who)
}

// start mints the pending enrolment of one person, whichever path asked for it.
//
// The sign-in and the portal share it, so the two produce the same provisioning
// URI: the same tenant label, the same person label, and the same refusal
// against an active factor. A second copy of these rules is how the two would
// drift apart.
func (s *Service) start(
	ctx context.Context, tenantID, issuer string, who Principal,
) (Started, error) {
	row, err := s.deps.Find(ctx, tenantID, who.UserID)
	switch {
	case err == nil && row.Active():
		return Started{}, fmt.Errorf("%w: user %s", ErrAlreadyEnrolled, who.UserID)
	case err != nil && !errors.Is(err, ErrNoEnrolment):
		s.log.Error("read the totp enrolment",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Started{}, err
	}

	secret, uri, err := mint(issuerHost(issuer), s.label(ctx, tenantID, who.UserID))
	if err != nil {
		s.log.Error("mint a totp secret",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Started{}, err
	}

	sealed, err := aocrypto.SealJSON(s.deps.Cipher, secret)
	if err != nil {
		s.log.Error("seal the totp secret",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Started{}, fmt.Errorf("seal the totp secret of user %s: %w", who.UserID, err)
	}
	if err := s.deps.SavePending(ctx, tenantID, who.UserID, sealed); err != nil {
		// A factor that landed between the read above and this write answers the
		// conflict the caller expects, not a failure. Logging it at error would
		// fill the log with a race the person resolves by removing the factor
		// they hold.
		if errors.Is(err, ErrAlreadyEnrolled) {
			return Started{}, err
		}
		s.log.Error("write the pending totp enrolment",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Started{}, err
	}

	s.log.Debug("started a totp enrolment",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID), logger.RequestID(ctx))
	return Started{Secret: secret, OtpauthURI: uri}, nil
}

// Activate proves the pending secret with a code and records the Second Factor.
//
// The row is activated, a set of Recovery Codes is issued, the Login Session
// takes the OTP factor, and its token rotates. All four land on one transaction,
// so a sign-in that reports a factor is a sign-in the database records.
//
// The code and the Recovery Codes never reach a log line.
func (s *Service) Activate(ctx context.Context, tenantID, token, code string) (Activated, error) {
	s.log.Debug("activate a totp enrolment",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	who, err := s.principal(ctx, tenantID, token)
	if err != nil {
		return Activated{}, err
	}

	var rotated string
	shown, err := s.activate(ctx, tenantID, who, code, func(ctx context.Context) error {
		upgraded, err := s.deps.CompleteSession(ctx, tenantID, token, who.UserID)
		rotated = upgraded
		return err
	})
	// A wrong code counts against this sign-in, the way a wrong code at the
	// challenge does. The count lives here and not in the shared body, because
	// the portal path holds an access token and has no session to count against.
	if errors.Is(err, ErrBadCode) {
		return Activated{}, s.wrong(ctx, tenantID, token, who)
	}
	if err != nil {
		return Activated{}, err
	}
	return Activated{SessionToken: rotated, RecoveryCodes: shown}, nil
}

// activate proves the pending enrolment of one person and records the Second
// Factor, whichever path asked for it.
//
// finish runs on the same transaction, after the factor lands. The sign-in path
// rotates the Login Session token there. The portal path passes nil: it holds an
// access token, and no login session waits on this enrolment.
//
// The guessing budget is spent here, before the enrolment is read, the way the
// challenge spends it. This address accepts six digits, so without the budget it
// is the way around the cap: a person who holds the password starts an enrolment
// of their own and guesses the code of the secret they were just given. Both
// entry points run this body, so one spend covers both.
func (s *Service) activate(
	ctx context.Context, tenantID string, who Principal, code string,
	finish func(context.Context) error,
) ([]string, error) {
	if err := s.spendGuess(ctx, tenantID, who); err != nil {
		return nil, err
	}

	row, err := s.deps.Find(ctx, tenantID, who.UserID)
	if errors.Is(err, ErrNoEnrolment) || (err == nil && row.Active()) {
		return nil, fmt.Errorf("%w: user %s", ErrNoPendingEnrolment, who.UserID)
	}
	if err != nil {
		s.log.Error("read the totp enrolment",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, err
	}

	var secret string
	if err := aocrypto.OpenJSON(s.deps.Cipher, row.SecretEncrypted, &secret); err != nil {
		s.log.Error("open the totp secret",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, fmt.Errorf("open the totp secret of user %s: %w", who.UserID, err)
	}

	step, ok := verify(secret, code, time.Now().UTC())
	if !ok {
		s.log.Warn("refused a totp code",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID))
		return nil, fmt.Errorf("%w: user %s", ErrBadCode, who.UserID)
	}

	shown, digests, err := newRecoveryCodes()
	if err != nil {
		s.log.Error("mint the recovery codes",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Activate(ctx, tenantID, who.UserID, row.SecretEncrypted, step); err != nil {
			return err
		}
		if err := s.deps.SaveRecoveryCodes(ctx, tenantID, who.UserID, digests); err != nil {
			return err
		}
		if err := s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    who.UserID,
			Action:     audit.ActionMFAEnrolled,
			EntityType: audit.EntityUser,
			EntityID:   who.UserID,
			IP:         who.IP,
			UserAgent:  who.UserAgent,
		}); err != nil {
			return err
		}

		if finish == nil {
			return nil
		}
		return finish(ctx)
	})
	if err != nil {
		// The pending row was replaced or activated while this request ran, so
		// the guarded update matched nothing. The person starts again, which is
		// what a refused activation asks them to do.
		if errors.Is(err, ErrNoEnrolment) {
			return nil, fmt.Errorf("%w: user %s", ErrNoPendingEnrolment, who.UserID)
		}
		s.log.Error("activate the totp enrolment",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, err
	}

	s.log.Info("activated a totp enrolment",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID))
	return shown, nil
}

// Verify answers the second-factor challenge of one sign-in, and signs the
// person in.
//
// One field carries both kinds of value. Six digits is a code from the
// Authenticator, and anything else is a Recovery Code. A submission is tried
// against one kind only, so a wrong six-digit value never spends a Recovery
// Code, and a Recovery Code is never read as a time step.
//
// Both kinds record the same Factor on the Login Session, and both rotate its
// token. A redemption also records mfa.recovery_code_used, which is what tells
// the two apart in the audit trail.
//
// The spend and the sign-in land on one transaction, so a code the database
// records as spent is a code the person got a session for.
//
// Neither kind of code reaches a log line.
func (s *Service) Verify(ctx context.Context, tenantID, token, code string) (string, error) {
	s.log.Debug("verify a second factor",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	who, err := s.principal(ctx, tenantID, token)
	if err != nil {
		return "", err
	}
	if err := s.spendGuess(ctx, tenantID, who); err != nil {
		return "", err
	}

	// One place drops the whitespace a person pasted, so the value that is
	// classified is the value that is verified. A Recovery Code loses its spaces
	// again in the canonical spelling, and this changes nothing for it.
	code = strings.TrimSpace(code)

	row, err := s.activeFactor(ctx, tenantID, who)
	if err != nil {
		return "", err
	}

	// The step the code proves, read before the transaction opens. A Recovery
	// Code proves no step, and the redemption below is its whole proof.
	recovery := !authenticatorCode(code)
	var step int64
	if !recovery {
		var secret string
		if err := aocrypto.OpenJSON(s.deps.Cipher, row.SecretEncrypted, &secret); err != nil {
			s.log.Error("open the totp secret",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", who.UserID), logger.Err(err))
			return "", fmt.Errorf("open the totp secret of user %s: %w", who.UserID, err)
		}

		var proved bool
		if step, proved = verify(secret, code, time.Now().UTC()); !proved {
			s.log.Warn("refused a totp code",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", who.SessionID),
				logger.String("user_id", who.UserID))
			return "", s.wrong(ctx, tenantID, token, who)
		}
	}

	var rotated string
	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.spend(ctx, tenantID, who, code, step, recovery); err != nil {
			return err
		}
		upgraded, err := s.deps.CompleteSession(ctx, tenantID, token, who.UserID)
		rotated = upgraded
		return err
	})
	if errors.Is(err, ErrCodeSpent) {
		// The code was correct and the account has already spent it. The person
		// is told the code is wrong, which is what a replayed code is.
		s.log.Warn("refused a spent code",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID),
			logger.Bool("recovery_code", recovery))
		return "", s.wrong(ctx, tenantID, token, who)
	}
	if err != nil {
		s.log.Error("verify a second factor",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return "", err
	}

	s.log.Info("verified a second factor",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID),
		logger.Bool("recovery_code", recovery))
	return rotated, nil
}

// spend consumes the value the person submitted, on the caller's transaction.
//
// A Recovery Code is deleted and audited. A code from the Authenticator claims
// its time step, and the successful sign-in the caller records is the only event
// it needs. Either way ErrCodeSpent means the value cannot be spent again.
func (s *Service) spend(
	ctx context.Context, tenantID string, who Principal, code string, step int64, recovery bool,
) error {
	if !recovery {
		return s.deps.SpendStep(ctx, tenantID, who.UserID, step)
	}

	if err := s.deps.RedeemRecoveryCode(ctx, tenantID, who.UserID, digestCode(code)); err != nil {
		return err
	}
	return s.deps.Audit.Record(ctx, audit.Entry{
		TenantID:   tenantID,
		ActorID:    who.UserID,
		Action:     audit.ActionMFARecoveryCodeUsed,
		EntityType: audit.EntityUser,
		EntityID:   who.UserID,
		IP:         who.IP,
		UserAgent:  who.UserAgent,
	})
}

// spendGuess spends one guess of the person's trailing-window budget, and
// refuses the submission when nothing is left.
//
// It is spent before the code is read, because a cap that counts only wrong
// codes cannot stop the right guess. A submission that signs the person in is
// the last one of that sign-in, so the budget counts every wrong code plus at
// most one right code per sign-in.
//
// A cache failure refuses the submission. Redis is only a cache elsewhere in
// this gateway, and here it is the whole budget: a failure that let the guess
// through would leave the guessing unbounded for as long as Redis is down. The
// per-session count cannot stand in for it, because that count is read, raised
// and written back, so parallel submissions on one token overwrite each other.
//
// ponytail: a refused read costs every person with a Second Factor their
// sign-in while Redis is down. Answer from the database instead when that
// outage is worth the extra table.
func (s *Service) spendGuess(ctx context.Context, tenantID string, who Principal) error {
	allowed, err := s.deps.Allow(ctx, attemptKey(tenantID, who.UserID), attemptLimit, attemptWindow)
	if err != nil {
		s.log.Error("read the second-factor guessing budget",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return fmt.Errorf("%w: user %s", ErrBudgetUnavailable, who.UserID)
	}
	if allowed {
		return nil
	}

	s.log.Warn("refused a second-factor attempt over the budget",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID))
	return fmt.Errorf("%w: user %s", ErrTooManyAttempts, who.UserID)
}

// SpendGuess spends one guess of the shared second-factor budget of one person.
//
// The budget is one budget for every Second Factor, so a passkey ceremony start
// spends it here too. A second copy of the key, the limit and the window is how
// the two Factors would drift into two budgets, and an attacker would then hold
// the sum of both.
//
// It answers ErrTooManyAttempts and ErrBudgetUnavailable, which the mapper
// already knows. The caller names no login session, so no session id reaches the
// log line of a refusal.
func (s *Service) SpendGuess(ctx context.Context, tenantID, userID string) error {
	return s.spendGuess(ctx, tenantID, Principal{UserID: userID})
}

// wrong records one wrong code against the Login Session, and answers what the
// person is told.
//
// The code that reaches the cap ends the sign-in, so the person is told to start
// again instead of to try another code. The login session domain owns the cap,
// the count and the audit row.
//
// A failed count comes back as it was given. That domain logged it, and the
// mapper already knows every sentinel it answers with.
func (s *Service) wrong(ctx context.Context, tenantID, token string, who Principal) error {
	ended, err := s.deps.FailCode(ctx, tenantID, token)
	if err != nil {
		return err
	}
	if ended {
		return fmt.Errorf("%w: session %s", ErrSignInEnded, who.SessionID)
	}
	return fmt.Errorf("%w: user %s", ErrBadCode, who.UserID)
}

// activeFactor reads the active Second Factor of one person, and refuses an
// account that holds none.
//
// Three paths need it: the challenge, which verifies a code against the secret,
// and the two destructive portal addresses, which have nothing to remove and
// nothing to replace without it. A pending enrolment reads as no factor, the way
// it does everywhere else: the next start overwrites it.
func (s *Service) activeFactor(
	ctx context.Context, tenantID string, who Principal,
) (Enrolment, error) {
	row, err := s.deps.Find(ctx, tenantID, who.UserID)
	if errors.Is(err, ErrNoEnrolment) || (err == nil && !row.Active()) {
		return Enrolment{}, fmt.Errorf("%w: user %s", ErrNoActiveFactor, who.UserID)
	}
	if err != nil {
		s.log.Error("read the totp enrolment",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Enrolment{}, err
	}
	return row, nil
}

// principal reads the Login Session one token credentials, and refuses one that
// has not proved a password.
//
// A session that names nobody is refused too. It cannot have proved a password,
// because the password step is what binds the person.
func (s *Service) principal(ctx context.Context, tenantID, token string) (Principal, error) {
	who, err := s.deps.FindSession(ctx, tenantID, token)
	if err != nil {
		return Principal{}, err
	}
	if !who.PasswordProved || who.UserID == "" {
		s.log.Warn("refused a second-factor step on a session that proved no password",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID))
		return Principal{}, fmt.Errorf("%w: session %s", ErrPasswordNotProved, who.SessionID)
	}
	return who, nil
}

// label names the person on the provisioning URI.
//
// A failed read is not a failure of the enrolment. The label is what an
// Authenticator prints beside the code, so the user id stands in and the sign-in
// continues. A blank label is what must never happen: it would print an
// unreadable entry that the person cannot tell from another account.
func (s *Service) label(ctx context.Context, tenantID, userID string) string {
	name, err := s.deps.Account(ctx, tenantID, userID)
	if err != nil {
		s.log.Error("read the account name for the provisioning uri",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", userID), logger.Err(err))
	}
	if name == "" {
		return userID
	}
	return name
}
