package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"alphaomega/identitygateway/internal/audit"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/user"
	"alphaomega/identitygateway/internal/utils"
)

// decoyPasswordHash is a bcrypt hash of a value nobody holds, at the cost the
// gateway hashes with. A session that names no person is compared against it,
// so the password step costs the same whether or not the identifier named
// somebody. Without it, the answer time alone says which people a tenant holds.
const decoyPasswordHash = "$2a$12$W2/bjFPAOoBUDagpusdjV.9VOtRCC2VOjswuaOActMhq.AWsTXntu"

// IdentityFinder reads the person one identifier names. It returns
// user.ErrNotFound on a miss.
type IdentityFinder func(ctx context.Context, tenantID, identifier string) (Identity, error)

// Saver writes one login session under one token digest. prevTokenHash is the
// digest the session answered to before this write, and it is empty on the
// first write. A rotation passes the old digest, so the cache can drop it.
type Saver func(ctx context.Context, s LoginSession, tokenHash, prevTokenHash string) error

// Finder reads the live login session one token digest credentials. It returns
// ErrLoginSessionNotFound on a miss.
type Finder func(ctx context.Context, tenantID, tokenHash string) (LoginSession, error)

// Terminator ends one login session of one tenant. It returns
// ErrLoginSessionNotFound when no live session of the tenant carries the id.
type Terminator func(ctx context.Context, tenantID, sessionID string) error

// CredentialFinder reads the stored password hash of one person. It returns
// user.ErrNotFound when no live account of the tenant carries the id.
type CredentialFinder func(ctx context.Context, tenantID, userID string) (string, error)

// FactorSteps names the factors one person must still verify after the password
// step. It answers an empty list when the sign-in owes nothing.
//
// The router composes it, because it reads the organization of the person, the
// MFA Requirement of that level, and the second factors the person holds, and
// those live in three domains this one must not import.
type FactorSteps func(ctx context.Context, tenantID, userID string) ([]string, error)

// Deps is the database side of the service. Every field is a function value or
// a recorder, so the logic is testable without a database.
type Deps struct {
	Identity   IdentityFinder
	Credential CredentialFinder
	Steps      FactorSteps
	Save       Saver
	Find       Finder
	Terminate  Terminator
	InTx       db.TxRunner
	Audit      *audit.Recorder
	Log        logger.Logger
}

// Service opens, upgrades, and reads login sessions.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// Identify opens a partial login session for one identifier.
//
// A session is opened whether or not the identifier names a person. An unknown
// identifier gets the same answer as a known one, so the response never says
// which people a tenant holds. The password step then fails alike for both.
func (s *Service) Identify(ctx context.Context, tenantID, identifier, ip, userAgent string) (Opened, error) {
	s.log.Debug("open login session", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	person, err := s.deps.Identity(ctx, tenantID, identifier)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		s.log.Error("read user", logger.String("tenant_id", tenantID), logger.Err(err))
		return Opened{}, err
	}
	return s.open(ctx, tenantID, person, ip, userAgent)
}

// Open opens a partial login session that names nobody.
//
// A flow that learns the person later calls it. QR Login is the first: the code
// goes on screen before anybody has said who they are, and the poll binds the
// person the scan resolved to.
func (s *Service) Open(ctx context.Context, tenantID, ip, userAgent string) (Opened, error) {
	s.log.Debug("open login session", logger.String("tenant_id", tenantID), logger.RequestID(ctx))
	return s.open(ctx, tenantID, Identity{}, ip, userAgent)
}

// open writes one partial login session and hands out the token that
// credentials it. person is the zero Identity when the caller names nobody.
func (s *Service) open(
	ctx context.Context, tenantID string, person Identity, ip, userAgent string,
) (Opened, error) {
	now := time.Now().UTC()
	live := LoginSession{
		ID:        utils.NewUUIDv7(),
		TenantID:  tenantID,
		UserID:    person.UserID,
		Email:     person.Email,
		IP:        ip,
		UserAgent: userAgent,
		CreatedAt: now,
		ExpiresAt: now.Add(partialLifetime),
	}

	token, err := mintToken()
	if err != nil {
		s.log.Error("mint session token", logger.String("tenant_id", tenantID), logger.Err(err))
		return Opened{}, err
	}
	if err := s.deps.Save(ctx, live, aocrypto.Digest(token), ""); err != nil {
		s.log.Error("save login session",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.Err(err))
		return Opened{}, err
	}

	s.log.Debug("opened login session",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", live.ID),
		logger.Bool("known_user", person.UserID != ""), logger.RequestID(ctx))
	return Opened{ID: live.ID, Token: token}, nil
}

// VerifyPassword checks a password against the person the login session names,
// and upgrades the session on a match.
//
// The upgraded session carries the pwd factor, lives for fullLifetime, and
// answers to a new token. The old token dies with the rotation, and the new one
// is disclosed exactly once, here. The authn session of an authorization
// request is not touched, because only Complete writes it.
//
// A wrong password, a session that names nobody, and a broken stored hash all
// give ErrBadCredentials. Each of them also pays for one bcrypt comparison, so
// neither the answer nor its timing says which of them happened.
//
// The second return names the factors the person still owes. It is read after
// the password is verified, so a caller who guessed wrong learns nothing about
// the account, and it is read before the session is upgraded, so a policy nobody
// could read refuses the step instead of signing the person in without a factor.
func (s *Service) VerifyPassword(
	ctx context.Context, tenantID, token, password string,
) (Opened, []string, error) {
	s.log.Debug("verify password", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	live, err := s.deps.Find(ctx, tenantID, aocrypto.Digest(token))
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("read login session", logger.String("tenant_id", tenantID), logger.Err(err))
		}
		return Opened{}, nil, err
	}

	hash, err := s.passwordHash(ctx, live)
	if err != nil {
		return Opened{}, nil, err
	}
	if err := aocrypto.VerifyPassword(hash, password); err != nil {
		return Opened{}, nil, s.refuse(ctx, live, err)
	}

	steps, err := s.deps.Steps(ctx, tenantID, live.UserID)
	if err != nil {
		return Opened{}, nil, err
	}

	now := time.Now().UTC()
	if live.Factors == nil {
		live.Factors = make(map[string]time.Time, 1)
	}
	live.Factors[FactorPassword] = now
	live.ExpiresAt = now.Add(fullLifetime)

	rotated, err := mintToken()
	if err != nil {
		s.log.Error("mint session token",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.Err(err))
		return Opened{}, nil, err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Save(ctx, live, aocrypto.Digest(rotated), aocrypto.Digest(token)); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, s.entry(live, audit.ActionLoginSucceeded, nil))
	})
	if err != nil {
		s.log.Error("upgrade login session",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.Err(err))
		return Opened{}, nil, err
	}

	s.log.Debug("verified password",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", live.ID),
		logger.String("user_id", live.UserID), logger.RequestID(ctx))
	return Opened{ID: live.ID, Token: rotated}, steps, nil
}

// passwordHash reads the stored hash of the person the session names. A session
// that names nobody, and a person the tenant no longer holds, both answer with
// the decoy hash, so the comparison still runs.
func (s *Service) passwordHash(ctx context.Context, live LoginSession) (string, error) {
	if live.UserID == "" {
		return decoyPasswordHash, nil
	}

	hash, err := s.deps.Credential(ctx, live.TenantID, live.UserID)
	if errors.Is(err, user.ErrNotFound) {
		return decoyPasswordHash, nil
	}
	if err != nil {
		s.log.Error("read password hash",
			logger.String("tenant_id", live.TenantID),
			logger.String("user_id", live.UserID),
			logger.Err(err))
		return "", err
	}
	if hash == "" {
		return decoyPasswordHash, nil
	}
	return hash, nil
}

// refuse records the refused password and returns what the caller answers with.
// The cause names the defect for the log, and never for the response.
//
// A failed audit write comes back instead, and the recorder has logged it. The
// caller then fails the request, because a refusal nobody can audit is not
// allowed to stand.
func (s *Service) refuse(ctx context.Context, live LoginSession, cause error) error {
	s.log.Warn("refused password",
		logger.String("tenant_id", live.TenantID),
		logger.String("session_id", live.ID),
		logger.Err(cause))

	metadata := map[string]any{"reason": "bad_password"}
	if err := s.deps.Audit.Record(ctx, s.entry(live, audit.ActionLoginFailed, metadata)); err != nil {
		return err
	}
	return fmt.Errorf("%w: session %s", ErrBadCredentials, live.ID)
}

// entry describes one login outcome for the audit trail. The password is never
// part of it, at any level and in any environment.
func (s *Service) entry(live LoginSession, action audit.Action, metadata map[string]any) audit.Entry {
	return audit.Entry{
		TenantID:   live.TenantID,
		ActorID:    live.UserID,
		Action:     action,
		EntityType: audit.EntitySession,
		EntityID:   live.ID,
		IP:         live.IP,
		UserAgent:  live.UserAgent,
		Metadata:   metadata,
	}
}

// Find returns the login session the token credentials, whether or not the
// person verified a factor. A caller that must act on a partial session uses it,
// and every other caller uses Resolve.
//
// The token is a credential. Only the session id reaches a log line.
func (s *Service) Find(ctx context.Context, tenantID, token string) (LoginSession, error) {
	s.log.Debug("read login session", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	live, err := s.deps.Find(ctx, tenantID, aocrypto.Digest(token))
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("read login session", logger.String("tenant_id", tenantID), logger.Err(err))
		}
		return LoginSession{}, err
	}

	s.log.Debug("read login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", live.ID), logger.RequestID(ctx))
	return live, nil
}

// Complete binds a person to a partial login session and records one named
// factor on it.
//
// The upgraded session lives for fullLifetime and answers to a new token. The old
// token dies with the rotation, and the new one is disclosed exactly once, here.
// This is the same rule the password step follows, so one writer holds it.
//
// The factor name is a parameter, and this method knows nothing about how the
// factor was proved. A later factor reuses it unchanged.
//
// A session that already names a different person gives ErrSubjectBound. A
// session that already names this person is bound again, which changes nothing.
func (s *Service) Complete(
	ctx context.Context, tenantID, token, userID, factor string,
) (Opened, error) {
	s.log.Debug("complete login session",
		logger.String("tenant_id", tenantID), logger.String("factor", factor), logger.RequestID(ctx))

	live, err := s.deps.Find(ctx, tenantID, aocrypto.Digest(token))
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("read login session", logger.String("tenant_id", tenantID), logger.Err(err))
		}
		return Opened{}, err
	}
	if live.UserID != "" && live.UserID != userID {
		return Opened{}, fmt.Errorf("%w: session %s", ErrSubjectBound, live.ID)
	}

	now := time.Now().UTC()
	live.UserID = userID
	if live.Factors == nil {
		live.Factors = make(map[string]time.Time, 1)
	}
	live.Factors[factor] = now
	live.ExpiresAt = now.Add(fullLifetime)

	rotated, err := mintToken()
	if err != nil {
		s.log.Error("mint session token",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.Err(err))
		return Opened{}, err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Save(ctx, live, aocrypto.Digest(rotated), aocrypto.Digest(token)); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, s.entry(live, audit.ActionLoginSucceeded,
			map[string]any{"factor": factor}))
	})
	if err != nil {
		s.log.Error("complete login session",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.Err(err))
		return Opened{}, err
	}

	s.log.Info("completed login session",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", live.ID),
		logger.String("user_id", live.UserID),
		logger.String("factor", factor), logger.RequestID(ctx))
	return Opened{ID: live.ID, Token: rotated}, nil
}

// Resolve returns the login session the token credentials, and only when the
// person verified a factor. A partial session gives ErrNotAuthenticated, so an
// unfinished login never counts as a signed-in one.
//
// The token is a credential. Only the session id reaches a log line.
func (s *Service) Resolve(ctx context.Context, tenantID, token string) (LoginSession, error) {
	s.log.Debug("read login session", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	live, err := s.deps.Find(ctx, tenantID, aocrypto.Digest(token))
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("read login session", logger.String("tenant_id", tenantID), logger.Err(err))
		}
		return LoginSession{}, err
	}
	if !live.Authenticated() {
		return LoginSession{}, fmt.Errorf("%w: session %s", ErrNotAuthenticated, live.ID)
	}

	s.log.Debug("read login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", live.ID), logger.RequestID(ctx))
	return live, nil
}

// ResolveForFinalize returns the login session the token credentials, and only
// when the sign-in owes no further factor. The finalize step reads it, and every
// other caller reads Resolve.
//
// The requirement is read through Steps, the one function that also answers the
// step signal of the password step. Two copies of an authentication predicate
// drift, and a drifted predicate is a security defect.
//
// A step the session already proved is met. Steps answers what the account and
// the policy demand, not what this sign-in did, so the session is what says
// whether the demand was answered.
//
// A QR Login is exempt. A Wallet presentation is a possession factor already,
// and the poll answers pending, authenticated, or expired, with no room to name
// a step still owed. See docs/adr/0011-the-mfa-gate-is-at-the-finalize-step.md.
func (s *Service) ResolveForFinalize(ctx context.Context, tenantID, token string) (LoginSession, error) {
	live, err := s.Resolve(ctx, tenantID, token)
	if err != nil {
		return LoginSession{}, err
	}
	if _, scanned := live.Factors[FactorScan]; scanned {
		return live, nil
	}

	steps, err := s.deps.Steps(ctx, tenantID, live.UserID)
	if err != nil {
		return LoginSession{}, err
	}
	for _, step := range steps {
		if _, proved := live.Factors[step]; proved {
			continue
		}
		s.log.Warn("refused the finalize step: the sign-in owes a factor",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.String("user_id", live.UserID),
			logger.String("step", step))
		return LoginSession{}, fmt.Errorf("%w: session %s owes %s", ErrInsufficientFactors, live.ID, step)
	}
	return live, nil
}

// Logout ends the login session one token credentials, from the account side.
//
// A partial session ends too. The person asked to sign out, so whatever session
// the token names is terminated, signed in or not.
//
// The token is a credential. Only the session id reaches a log line.
func (s *Service) Logout(ctx context.Context, tenantID, token string) error {
	s.log.Debug("end login session", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	live, err := s.deps.Find(ctx, tenantID, aocrypto.Digest(token))
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("read login session", logger.String("tenant_id", tenantID), logger.Err(err))
		}
		return err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Terminate(ctx, tenantID, live.ID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, s.entry(live, audit.ActionLogoutSucceeded, nil))
	})
	if err != nil {
		s.log.Error("end login session",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.Err(err))
		return err
	}

	s.log.Debug("ended login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", live.ID), logger.RequestID(ctx))
	return nil
}

// TerminateByID ends one login session by its id, with no audit row. It serves
// the RP-initiated logout, which records logout.succeeded itself, because only
// that side knows the client that asked. See internal/api/oidc/logout.go.
func (s *Service) TerminateByID(ctx context.Context, tenantID, sessionID string) error {
	s.log.Debug("end login session",
		logger.String("tenant_id", tenantID), logger.String("session_id", sessionID), logger.RequestID(ctx))

	if err := s.deps.Terminate(ctx, tenantID, sessionID); err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("end login session",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", sessionID),
				logger.Err(err))
		}
		return err
	}
	return nil
}

// mintToken returns a new session token. The caller stores its digest and hands
// the token out once. Every rotation calls this again, so no token is reused.
func mintToken() (string, error) {
	token, err := aocrypto.SessionToken()
	if err != nil {
		return "", fmt.Errorf("mint login session token: %w", err)
	}
	return token, nil
}
