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

// passwordStepFloor is the least time the password step takes, measured from
// entry and applied to every answer it gives.
//
// The decoy hash gives the local path a constant cost, and a bind does not: an
// entry the directory does not hold answers faster than a wrong password,
// because the second bind never runs. Without the floor, account enumeration
// returns at the password step.
//
// One floor covers both paths. A floor on the directory path alone would leave
// the local path faster, and the difference would say which identifiers a
// directory serves. The number is above the cost of one bcrypt comparison at
// cost 12, which is what the local path pays today.
//
// ponytail: a constant, and it is a floor and not a fixed cost. A directory
// slower than the floor still answers late, so a slow directory is visible in
// the timing even though a missing entry is not.
const passwordStepFloor = 500 * time.Millisecond

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

// FederationResolver names the User Federation that proves one sign-in. It
// answers an empty id when the local password compare proves it, and an error
// when no single federation can.
//
// The router composes it, because it reads the directories a tenant registered,
// the domains they claim, and the Federation Links of the person, and those live in
// a domain this one must not import.
//
// userID and email are the person the identifier named, and both are empty when
// the identifier named nobody. A domain claim is read from both forms of the
// person, the identifier they typed and the email address the tenant holds for
// them, so a claim a person steps around by typing their username is no guard
// rail.
type FederationResolver func(
	ctx context.Context, tenantID, userID, identifier, email string,
) (string, error)

// Prover proves one password against the directory a login session names, and
// answers the person the sign-in carries on as. It answers one of five sentinels
// of this package when the directory refused: ErrBadCredentials,
// ErrFederationDisabled, ErrFederationUnavailable, ErrFederationMisconfigured, or
// ErrTooManyProofs.
//
// userID is the person the login session already names, and it is empty when the
// identifier named nobody. The answer names that same person when the session
// named one, and the person the first bind created when it did not. A bind that
// proved the password of somebody the gateway did not hold therefore creates
// them, and every later bind of that person creates nothing.
//
// The answer carries the email address of the directory entry beside the person
// id. A first bind names nobody at the identifier step, so the session learns
// the email here or nowhere. No credential travels with it: the answer holds the
// person and the email alone.
//
// The router composes it, because it reads the provider row, spends the bind
// budget, dials the directory, and writes the person the first bind creates, and
// those live in a domain this one must not import. It maps that domain's
// sentinels onto these five, so the password step reads one vocabulary.
type Prover func(
	ctx context.Context, tenantID, federationID, userID, identifier, password string,
) (Identity, error)

// PendingSteps names the Pending Steps one person still owes after the password
// step. It answers an empty list when the sign-in owes nothing.
//
// The router composes it, because it reads the organization of the person, the
// MFA Requirement of that level, and the second factors the person holds, and
// those live in three domains this one must not import.
type PendingSteps func(ctx context.Context, tenantID, userID string) ([]string, error)

// Deps is the database side of the service. Every field is a function value or
// a recorder, so the logic is testable without a database.
type Deps struct {
	Identity   IdentityFinder
	Federation FederationResolver
	Prove      Prover
	Credential CredentialFinder
	Steps      PendingSteps
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
	// A resolution that broke stops the request, the way a broken read of the
	// person above it does. The resolver answers an empty id for every case the
	// local password compare proves, so an error here is a read that failed and
	// never a person who is not held: a sign-in that carried on would fall back
	// to a local password hash that a claimed domain took out of service. The
	// resolver has logged it.
	federationID, err := s.deps.Federation(ctx, tenantID, person.UserID, identifier, person.Email)
	if err != nil {
		return Opened{}, err
	}
	return s.open(ctx, tenantID, person, federationID, identifier, ip, userAgent)
}

// Open opens a partial login session that names nobody.
//
// A flow that learns the person later calls it. QR Login is the first: the code
// goes on screen before anybody has said who they are, and the poll binds the
// person the scan resolved to.
func (s *Service) Open(ctx context.Context, tenantID, ip, userAgent string) (Opened, error) {
	s.log.Debug("open login session", logger.String("tenant_id", tenantID), logger.RequestID(ctx))
	return s.open(ctx, tenantID, Identity{}, "", "", ip, userAgent)
}

// open writes one partial login session and hands out the token that
// credentials it. person is the zero Identity when the caller names nobody,
// federationID is empty when the local password compare proves the sign-in, and
// identifier is empty when the caller names nobody at all.
func (s *Service) open(
	ctx context.Context, tenantID string, person Identity, federationID, identifier, ip, userAgent string,
) (Opened, error) {
	now := time.Now().UTC()
	live := LoginSession{
		ID:           utils.NewUUIDv7(),
		TenantID:     tenantID,
		UserID:       person.UserID,
		Email:        person.Email,
		FederationID: federationID,
		Identifier:   identifier,
		IP:           ip,
		UserAgent:    userAgent,
		CreatedAt:    now,
		ExpiresAt:    now.Add(partialLifetime),
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

	// The session id ties the steps of one sign-in together, and the provider id
	// says which credential the password step will prove. Whether the identifier
	// named a person is not logged: this step answers the same thing either way,
	// and a log line that named it would be the enumeration oracle the answer is
	// not.
	s.log.Debug("opened login session",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", live.ID),
		logger.String("federation_id", live.FederationID), logger.RequestID(ctx))
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
// A session that names a directory is proved with a bind, and every other
// session with the bcrypt compare. Nothing below this step learns which of the
// two ran: the factor is pwd either way, and acr is unchanged.
//
// A wrong password, a session that names nobody, and a broken stored hash all
// give ErrBadCredentials. Each of them also pays for one bcrypt comparison, so
// neither the answer nor its timing says which of them happened. The whole step
// carries a floor besides, so a directory that holds no such entry cannot answer
// faster than one that refused the password.
//
// The second return names the factors the person still owes. It is read after
// the password is verified, so a caller who guessed wrong learns nothing about
// the account, and it is read before the session is upgraded, so a policy nobody
// could read refuses the step instead of signing the person in without a factor.
func (s *Service) VerifyPassword(
	ctx context.Context, tenantID, token, password string,
) (Opened, []string, error) {
	defer floorTheStep(time.Now())
	s.log.Debug("verify password", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	live, err := s.deps.Find(ctx, tenantID, aocrypto.Digest(token))
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("read login session", logger.String("tenant_id", tenantID), logger.Err(err))
		}
		return Opened{}, nil, err
	}

	// The password step is the first thing that names the person of a directory
	// sign-in whose identifier the gateway held no row for. Every read below it
	// takes the person the bind answered.
	person, err := s.prove(ctx, live, password)
	if err != nil {
		return Opened{}, nil, err
	}
	// The email travels with the id, because a session that names one person and
	// shows the address of another is what every screen below this step reads.
	//
	// A bind that changed the person writes their email too. The identifier step
	// finds a person by username and writes their email, and the bind then proves
	// a directory entry whose Federation Link names somebody else. A first bind is
	// the same case with nobody on the left: the session carries no email, and the
	// bind is the only step that learns one.
	//
	// A bind that named the person the session already held writes no email. It
	// writes no attribute of the person, so what the directory says now is not
	// what the gateway holds.
	//
	// A directory entry that carries no mail leaves the session with no email at
	// all, and that is the answer. The address the session held belongs to the
	// person the bind replaced, so keeping it is the fault this rule closes. A
	// session that shows no address is the same state a first bind of such an
	// entry already reaches.
	if live.UserID != person.UserID || live.Email == "" {
		live.Email = person.Email
	}
	live.UserID = person.UserID

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

// prove proves the password of one login session, records the refusal when it
// does not hold, and answers the person the sign-in carries on as.
//
// A session that names a User Federation is proved with a bind, and every
// other session with the bcrypt compare. The two answer alike wherever they can:
// a wrong password, an entry the directory does not hold, and a search that
// matched twice all give ErrBadCredentials, which is what a wrong local password
// gives.
//
// The person is the one the session already named, except on the first bind of
// somebody the gateway held no row for: the bind creates them, and answers who
// they are. The local compare creates nobody, so it answers the person the
// session named.
//
// The email address of that person comes back with the id. The bind reads it off
// the directory entry, and the local compare answers the one the identifier step
// already found.
//
// Every outcome runs through refuse, so login.failed is written for every
// failure, a dial that never returned included.
func (s *Service) prove(ctx context.Context, live LoginSession, password string) (Identity, error) {
	if live.FederationID == "" {
		hash, err := s.passwordHash(ctx, live)
		if err != nil {
			return Identity{}, err
		}
		if err := aocrypto.VerifyPassword(hash, password); err != nil {
			return Identity{}, s.refuse(ctx, live, "bad_password", err, ErrBadCredentials)
		}
		return Identity{UserID: live.UserID, Email: live.Email}, nil
	}

	person, err := s.deps.Prove(ctx, live.TenantID, live.FederationID, live.UserID, live.Identifier, password)
	switch {
	case errors.Is(err, ErrFederationDisabled):
		return Identity{}, s.refuse(ctx, live, "federation_disabled", err, ErrFederationDisabled)
	case errors.Is(err, ErrFederationUnavailable):
		return Identity{}, s.refuse(ctx, live, "federation_unavailable", err, ErrFederationUnavailable)
	case errors.Is(err, ErrFederationMisconfigured):
		return Identity{}, s.refuse(ctx, live, "federation_misconfigured", err, ErrFederationMisconfigured)
	case errors.Is(err, ErrTooManyProofs):
		return Identity{}, s.refuse(ctx, live, "too_many_proofs", err, ErrTooManyProofs)
	case err != nil:
		return Identity{}, s.refuse(ctx, live, "bad_password", err, ErrBadCredentials)
	}

	// The bind proved a password and named nobody, so the person the sign-in
	// would carry on as does not exist. It is a defect of the seam and never an
	// answer of a directory, and a sign-in that carried on would upgrade a
	// session that names no person at all.
	if person.UserID == "" {
		return Identity{}, s.refuse(ctx, live, "no_local_person",
			errors.New("the bind proved a password and named no person"),
			ErrBadCredentials)
	}
	return person, nil
}

// floorTheStep holds the answer of the password step until the floor has passed.
// entered is the moment the step began, so one call covers every return the step
// has, the refusals and the sign-in alike.
func floorTheStep(entered time.Time) {
	if rest := passwordStepFloor - time.Since(entered); rest > 0 {
		time.Sleep(rest)
	}
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

// refuse records the refused password step and returns what the caller answers
// with.
//
// reason names the cause for the audit trail, which an operator reads, and
// answer is the sentinel the response is built from. The two are not the same
// thing: a disabled directory and a wrong password answer one slug and record
// two reasons, so the trail stays readable and the response says nothing about
// which people a tenant holds.
//
// The cause names the defect for the log, and never for the response.
//
// A failed audit write comes back instead, and the recorder has logged it. The
// caller then fails the request, because a refusal nobody can audit is not
// allowed to stand.
func (s *Service) refuse(
	ctx context.Context, live LoginSession, reason string, cause, answer error,
) error {
	s.log.Warn("refused password",
		logger.String("tenant_id", live.TenantID),
		logger.String("session_id", live.ID),
		logger.String("reason", reason),
		logger.Err(cause))

	// The federation names the directory that refused, so an operator reading a
	// failed sign-in knows which one to look at. It is the id of a row the tenant
	// registered, and never a credential of any kind.
	metadata := map[string]any{"reason": reason}
	if live.FederationID != "" {
		metadata["federation_id"] = live.FederationID
	}
	if err := s.deps.Audit.Record(ctx, s.entry(live, audit.ActionLoginFailed, metadata)); err != nil {
		return err
	}
	return fmt.Errorf("%w: session %s", answer, live.ID)
}

// FailSecondFactor records one wrong second-factor code against the login
// session, and reports whether this code ended the sign-in.
//
// The count lives in the sealed session, so it needs no column and any instance
// reads the same number. The second-factor module owns the decision to call it,
// and this domain owns the cap and the audit row.
//
// The code that reaches the cap terminates the session and records login.failed.
// The codes before it record nothing: one refused sign-in is one audit row, not
// five.
//
// The token is a credential. Only the session id reaches a log line.
//
// ponytail: the count is read, raised and written back, so submissions that run
// side by side on one token overwrite each other and a sign-in can take a few
// codes over the cap. The trailing-window budget of the TOTP module is atomic
// and bounds the person whatever happens here. Move the count into a column and
// raise it with one UPDATE when the exact number must hold under a flood.
func (s *Service) FailSecondFactor(ctx context.Context, tenantID, token string) (bool, error) {
	s.log.Debug("record a wrong second-factor code",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	digest := aocrypto.Digest(token)
	live, err := s.deps.Find(ctx, tenantID, digest)
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			s.log.Error("read login session", logger.String("tenant_id", tenantID), logger.Err(err))
		}
		return false, err
	}

	live.WrongCodes++
	if live.WrongCodes < maxWrongCodes {
		// The token did not rotate, so the digest before this write is the digest
		// after it, and the cached copy is replaced in place.
		if err := s.deps.Save(ctx, live, digest, digest); err != nil {
			s.log.Error("count a wrong second-factor code",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", live.ID),
				logger.Err(err))
			return false, err
		}

		s.log.Debug("counted a wrong second-factor code",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID), logger.RequestID(ctx))
		return false, nil
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Terminate(ctx, tenantID, live.ID); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, s.entry(live, audit.ActionLoginFailed,
			map[string]any{"reason": "bad_second_factor"}))
	})
	if err != nil {
		s.log.Error("end the login session after too many wrong codes",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", live.ID),
			logger.Err(err))
		return false, err
	}

	s.log.Info("ended a login session after too many wrong second-factor codes",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", live.ID),
		logger.String("user_id", live.UserID))
	return true, nil
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
// A step the session already answered is met. Steps answers what the account and
// the policy demand, not what this sign-in did, so the session is what says
// whether the demand was answered. LoginSession.meets carries that reading: a
// challenge step takes any proved Second Factor, and every other step is refused.
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
		if live.meets(step) {
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
