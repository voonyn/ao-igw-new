package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/cache"
	"alphaomega/identitygateway/internal/platform/db"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/utils"
)

// The sentinels this domain answers with.
var (
	// ErrOriginRefused reports a ceremony asked for from an origin the derived
	// RP ID does not cover, or from an origin this deployment does not serve.
	//
	// The registration is refused before a key pair exists. A Passkey binds to
	// one domain, so a credential created under an origin the sign-in host does
	// not cover is a Factor no sign-in can ever answer.
	ErrOriginRefused = errors.New("the relying party does not cover this origin")

	// ErrCeremonyUnavailable reports a ceremony the gateway could not run: a
	// challenge store nobody could read or write, or a host this deployment
	// derives no RP ID for.
	//
	// The ceremony is refused, because a ceremony that proceeds without a stored
	// challenge is not a ceremony. It asks the person to try again, and the log
	// line names which of the two happened.
	ErrCeremonyUnavailable = errors.New("the passkey ceremony is unavailable")

	// ErrChallengeExpired reports a finish with no challenge behind it. A
	// challenge that ran out its TTL, one that was already answered, and one
	// that a later start replaced all give it.
	//
	// The person starts the registration again, which is what a refused finish
	// asks them to do.
	ErrChallengeExpired = errors.New("the passkey challenge expired")

	// ErrRejected reports an answer the challenge does not prove. A malformed
	// answer, a wrong signature, and an answer to another challenge all give it.
	//
	// The answer never says which of them happened.
	ErrRejected = errors.New("the passkey answer is wrong")

	// ErrTooManyPasskeys reports a registration over the cap. The person removes
	// a device they no longer hold and registers again.
	ErrTooManyPasskeys = errors.New("the person holds the most passkeys allowed")

	// ErrTooManyEnrolments reports a person who started more registrations than
	// the trailing window allows. They wait, and then they register again.
	//
	// It is not ErrTooManyPasskeys. That cap counts the devices an account
	// holds, and this one counts the starts one person asked for.
	ErrTooManyEnrolments = errors.New("too many passkey registration starts")

	// ErrTooManyChallenges reports a person who started more sign-in challenges
	// than the trailing window allows. They wait, and then they start again.
	//
	// It is not ErrTooManyEnrolments. That budget counts the registration starts
	// of one person, and this one counts the challenge starts. The two are
	// separate counters, so a person who cancels a prompt on one path keeps the
	// other whole.
	ErrTooManyChallenges = errors.New("too many passkey challenge starts")

	// ErrDuplicateDevice reports a registration of a credential id that a live
	// row already holds.
	//
	// The exclude list stops the common case in the browser, and it names the
	// devices of one person alone. This is the case it cannot name: the same
	// device already registered against another account of the same tenant, and
	// the primary key is (tenant_id, credential_id).
	ErrDuplicateDevice = errors.New("the device already holds a passkey")

	// ErrNotFound reports a rename or a removal that names no live Passkey of
	// the person who asked. An id nobody registered, a device somebody already
	// removed, and a device of another account all give it.
	ErrNotFound = errors.New("passkey not found")

	// ErrPasswordNotProved reports a Login Session that has not proved a
	// password. Every sign-in ceremony address refuses one.
	//
	// This is the account takeover guard. A session names a person from the
	// identifier step onward, so without it anybody who knows an identifier
	// could ask for the challenge of that account.
	ErrPasswordNotProved = errors.New("login session has not proved a password")

	// ErrNoPasskey reports a challenge against a person who holds no live
	// Passkey. Only the password answer routes a person to the challenge, so a
	// request that reaches it without one is a client that went its own way.
	ErrNoPasskey = errors.New("the person holds no passkey")

	// ErrFactorAlreadyHeld reports a sign-in enrolment for a person who already
	// holds a Second Factor, of either kind. That person is challenged, never
	// enrolled. The finalize gate re-reads the account, so a Factor added in the
	// middle of a sign-in would meet the challenge step the account already
	// owes, and a person who holds the password alone would reach a token.
	//
	// It is not ErrTooManyPasskeys. That cap counts the devices an account may
	// hold, and it governs the portal too. This one governs the sign-in alone.
	ErrFactorAlreadyHeld = errors.New("the account already holds a second factor")

	// ErrCredentialUnknown reports an assertion signed by a credential the
	// person does not own.
	//
	// It is not ErrRejected. A wrong signature is a device that failed, and this
	// is a device that belongs to somebody else, so the person is told to use a
	// device of their own instead of to try again.
	ErrCredentialUnknown = errors.New("the passkey belongs to another person")
)

// maxPasskeys caps how many Passkeys one person holds. The list is answered
// whole and carries no pager, the exclude list of a ceremony carries every one
// of them, and a person who runs out removes a device they no longer hold.
const maxPasskeys = 10

// ceremonyTTL bounds one ceremony. It matches the timeout a browser gives the
// person to touch the device, so a prompt that is still open never meets an
// expired challenge.
const ceremonyTTL = 5 * time.Minute

// defaultName is what a Passkey is called when the person named none. The column
// is nullable and names are not unique, so a person with two unnamed devices
// reads this word twice and renames the one they mean.
const defaultName = "Passkey"

// ceremonyKey names the one live ceremony of one holder. A Portal registration
// keys on the subject of the access token, and a sign-in ceremony keys on the
// Login Session id, so no identifier is minted for either.
//
// The two holders never collide. A session id and a user id are both UUIDs of
// the same shape, and a sign-in mints a fresh session id that no user row
// carries.
//
// The tenant id is part of the key, so a ceremony of one tenant is never read
// under another.
func ceremonyKey(tenantID, holder string) string {
	return fmt.Sprintf("passkey_ceremony:%s:%s", tenantID, holder)
}

// enrolLimit and enrolWindow cap how many registration starts one person asks
// for, across every sign-in and every portal tab they open.
//
// It is a budget of its own, and it is deliberately not the shared second-factor
// guessing budget. A start proves nothing and verifies nothing, so it is not a
// guess. A browser prompt is easy to cancel by accident, and a person who
// cancelled fifteen of them must still be able to answer a code.
//
// The number is larger than the guessing budget for the same reason: a cancelled
// prompt is an accident, and a wrong code is an attempt. It still bounds the
// work, which is what the cap is for.
//
// ponytail: two constants. Move them into a tenant policy row when a tenant asks
// for its own numbers.
const (
	enrolLimit  = 30
	enrolWindow = 15 * time.Minute
)

// enrolKey names the registration-start budget of one person. The tenant id is
// part of the key, so a person of one tenant never spends the budget of another.
//
// It keys on the person and not on the holder, because a person who opens a
// second sign-in must not buy a second budget with it.
func enrolKey(tenantID, userID string) string {
	return fmt.Sprintf("passkey_enrolments:%s:%s", tenantID, userID)
}

// challengeLimit and challengeWindow cap how many sign-in challenges one person
// starts, across every sign-in they open.
//
// It is a budget of its own, for the reason the enrolment budget above is one. A
// challenge start mints options and stores a challenge. It proves nothing, and a
// person who presses Escape on the browser sheet guessed nothing, so that cancel
// must not cost them the code sign-in beside it.
//
// The numbers mirror the enrolment budget. The two paths have the same shape: a
// browser prompt that is easy to cancel by accident, and a start that costs the
// gateway work. Only the password answer reaches this start, and the cap bounds
// the work either way.
//
// ponytail: two constants. Move them into a tenant policy row when a tenant asks
// for its own numbers.
const (
	challengeLimit  = 30
	challengeWindow = 15 * time.Minute
)

// challengeKey names the challenge-start budget of one person. The tenant id is
// part of the key, so a person of one tenant never spends the budget of another.
//
// It keys on the person and not on the Login Session, because a person who opens
// a second sign-in must not buy a second budget with it.
func challengeKey(tenantID, userID string) string {
	return fmt.Sprintf("passkey_challenges:%s:%s", tenantID, userID)
}

// Principal is what the caller knows about the person one ceremony runs for.
//
// It is not the login session type and it is not the user type. This module
// imports neither domain, so the router projects each of them onto this shape.
type Principal struct {
	UserID    string
	IP        string
	UserAgent string

	// SessionID names the Login Session one sign-in ceremony belongs to, and it
	// keys the challenge of that ceremony. The portal leaves it empty: no
	// sign-in is in flight there, and the person themselves is the holder.
	//
	// A session id is not a credential. The opaque token credentials the
	// session, and the id is disclosed to the client, so it reaches a log line.
	SessionID string

	// PasswordProved is whether the Login Session already answered the password
	// step. The portal leaves it false and never reads it: an access token is
	// what guards that path.
	PasswordProved bool
}

// holder names the ceremony this principal runs, the way ceremonyKey reads it.
// A sign-in keys on the Login Session id, so a person who opens a second sign-in
// never answers the ceremony of the first. The portal leaves the session empty
// and keys on the person themselves.
func (p Principal) holder() string {
	if p.SessionID != "" {
		return p.SessionID
	}
	return p.UserID
}

// The reads, writes, and sends the service composes its answers from. Each one
// is a function value, so the logic is testable without a database.
type (
	// Account names one person on the ceremony. The email address is what a
	// person recognises, and the username stands in for an account that holds
	// no email. Neither reaches an authenticator screen in this deployment,
	// because a Passkey here is a Second Factor and the person already typed an
	// identifier.
	Account func(ctx context.Context, tenantID, userID string) (string, error)

	// CredentialLister reads the live Passkeys of one person.
	CredentialLister func(ctx context.Context, tenantID, userID string) ([]Credential, error)

	// CredentialInserter writes one registered Passkey on the caller's
	// transaction.
	CredentialInserter func(ctx context.Context, row Credential) error

	// OriginLister reads every origin one tenant runs a ceremony from: the hosts
	// that tenant serves, and the Portal and Console origins of the deployment.
	//
	// The library refuses to start with an empty list, so a tenant that serves
	// no verified host cannot run a ceremony at all.
	OriginLister func(ctx context.Context, tenantID string) ([]string, error)

	// CredentialFinder reads one row by its credential id, removed rows
	// included. The primary key is (tenant_id, credential_id), so a removed row
	// blocks an insert of the same id as firmly as a live one does.
	CredentialFinder func(ctx context.Context, tenantID string, credID []byte) (Credential, error)

	// CredentialReviver rewrites a removed row as a fresh registration and
	// clears the delete mark. It runs on the caller's transaction.
	CredentialReviver func(ctx context.Context, row Credential) error

	// CredentialRenamer writes the new name of one live Passkey of one person.
	CredentialRenamer func(ctx context.Context, tenantID, userID string, credID []byte, name string) error

	// CredentialRemover marks one live Passkey of one person as removed. It runs
	// on the caller's transaction.
	CredentialRemover func(ctx context.Context, tenantID, userID string, credID []byte) error

	// PasswordVerifier checks the password stored now against what the person
	// typed. It answers the refusal sentinel of the user domain, which owns the
	// hash, so one refusal is read wherever the portal asks for a password.
	PasswordVerifier func(ctx context.Context, tenantID, userID, plain string) error

	// SessionFinder reads the Login Session one token credentials. The token is
	// a credential, so only the session id it answers reaches a log line.
	SessionFinder func(ctx context.Context, tenantID, token string) (Principal, error)

	// SessionCompleter records the Passkey factor on the Login Session and
	// rotates its token. It answers the rotated token, disclosed exactly once.
	//
	// The factor name lives with the login session domain, which owns every AMR
	// name. The router closes over it, so it is spelled in one place.
	SessionCompleter func(ctx context.Context, tenantID, token, userID string) (string, error)

	// CredentialToucher writes back what one successful assertion changed: the
	// stored blob, which carries the new sign counter and the new backup state,
	// and the moment the Passkey was last used. It runs on the caller's
	// transaction.
	CredentialToucher func(ctx context.Context, tenantID, userID string, credID []byte, record string) error

	// FactorHolder reports whether one person holds any Second Factor: a live
	// Passkey, or an active TOTP Enrolment. The router builds it once, over the
	// pending steps of the account and never the two Factor tables, so this
	// module reads the Factor it does not own without importing the module that
	// owns it. ADR 0011 says why one function answers this for every reader.
	FactorHolder func(ctx context.Context, tenantID, userID string) (bool, error)

	// Notifier tells one person that a Passkey was registered on their account.
	// A send that fails is logged and never refuses the registration: the key
	// pair is already stored, and the audit trail is the record of it.
	Notifier func(ctx context.Context, tenantID, userID, deviceName string) error
)

// Deps is the database side, the cache side, and the transport side of the
// service.
type Deps struct {
	Account Account
	List    CredentialLister
	Insert  CredentialInserter
	Find    CredentialFinder
	Revive  CredentialReviver
	Rename  CredentialRenamer
	Delete  CredentialRemover
	Touch   CredentialToucher
	Origins OriginLister

	// The two crossings into the login session domain. The sign-in ceremony
	// reads the session one token credentials, and records the Factor on it.
	// The portal path uses neither.
	FindSession     SessionFinder
	CompleteSession SessionCompleter

	// VerifyPassword guards the removal. The access token carries no session
	// identifier and the bearer guard reads no store, so the password in the
	// body is the only proof the request can hold. Without it, a leaked access
	// token strips the account of a Factor in one request.
	VerifyPassword PasswordVerifier

	// HoldsFactor guards the two sign-in enrolment steps. Nothing on the portal
	// path reads it: the portal is where a person adds a second kind of Factor
	// beside the one they already hold.
	HoldsFactor FactorHolder

	// Notify tells the person a Passkey was registered. A nil value sends
	// nothing, which is what a deployment with no transport does.
	Notify Notifier

	// RPIDOverride replaces the RP ID derived from the request host. It is set
	// for a development host alone, where the registrable domain is empty and no
	// ceremony could otherwise run.
	RPIDOverride string

	// Ceremony holds the challenge of one ceremony in flight, the
	// registration-start budget of one person, and the challenge-start budget of
	// one person. It is Redis and nothing else: no table holds any of them. See
	// docs/adr/0002-session-storage.md, which names all three as exceptions to
	// the stateless rule.
	Ceremony cache.Client

	InTx  db.TxRunner
	Audit *audit.Recorder
	Log   logger.Logger
}

// account is what the library reads about the person a ceremony runs for.
//
// The user handle is the user id. It is a UUID, it is stable, it carries no
// personal data, and it fits the 64-byte cap the specification sets. No column
// stores it, because it is derived.
//
// The two display names never reach an authenticator screen in this deployment:
// a Passkey here is a Second Factor, and the person already typed an identifier.
// They are answered anyway, because the library demands them.
//
// The credentials are the Passkeys the person already holds. Registration sends
// them as the exclude list, so a device that already registered says so instead
// of creating a second key pair.
type account struct {
	id          string
	name        string
	credentials []webauthn.Credential
	held        int
}

func (a account) WebAuthnID() []byte                         { return []byte(a.id) }
func (a account) WebAuthnName() string                       { return a.name }
func (a account) WebAuthnDisplayName() string                { return a.name }
func (a account) WebAuthnCredentials() []webauthn.Credential { return a.credentials }

// Service runs the WebAuthn ceremonies.
type Service struct {
	deps Deps
	log  logger.Logger
}

func NewService(deps Deps) *Service {
	return &Service{deps: deps, log: deps.Log}
}

// registerStart mints the registration options of one person and stores the
// challenge behind them.
//
// The enrolment budget is spent first, before anything is read. A start is what
// costs the gateway work, and a person who holds a valid token could otherwise
// ask for options without end.
//
// That budget is the one spendEnrolment owns, and it is not the shared
// second-factor guessing budget a TOTP submission spends. A registration start
// proves nothing, so a person who cancels browser prompts must never spend the
// budget their next code sign-in reads. LoginStart holds a third counter for the
// same reason. See spendChallenge.
//
// The origin is checked before the options are minted. A key pair created under
// an origin the RP ID does not cover is a Factor no sign-in can answer, so it
// must never be created. The check reads the origin the caller names, and the
// portal BFF names its own, so a deployment that covers no portal origin is
// refused here rather than at the finish. relying names the caller that sends
// none, and says why an empty value still runs.
//
// The exclude list names every Passkey the person already holds, so a device
// that already registered tells the person so instead of creating a second key
// pair for the same account.
//
// The cap is checked here and not at the finish. A start refused costs the
// person nothing, and a browser prompt that ends in a refusal costs them a touch
// of the device for a Factor the gateway was never going to keep.
func (s *Service) registerStart(
	ctx context.Context, tenantID, host, origin string, who Principal,
) (*protocol.CredentialCreation, error) {
	if err := s.spendEnrolment(ctx, tenantID, who.UserID); err != nil {
		return nil, err
	}

	party, rpID, err := s.relying(ctx, tenantID, host, origin)
	if err != nil {
		return nil, err
	}

	person, err := s.account(ctx, tenantID, who.UserID)
	if err != nil {
		return nil, err
	}

	if person.held >= maxPasskeys {
		s.log.Warn("refused a passkey registration over the cap",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Int("held", person.held))
		return nil, fmt.Errorf("%w: user %s holds %d", ErrTooManyPasskeys, who.UserID, person.held)
	}

	exclude := make([]protocol.CredentialDescriptor, 0, len(person.credentials))
	for i := range person.credentials {
		exclude = append(exclude, person.credentials[i].Descriptor())
	}

	creation, ceremony, err := party.BeginRegistration(person, webauthn.WithExclusions(exclude))
	if err != nil {
		s.log.Error("begin a passkey registration",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID),
			logger.String("rp_id", rpID), logger.Err(err))
		return nil, fmt.Errorf("%w: user %s", ErrCeremonyUnavailable, who.UserID)
	}

	if err := s.store(ctx, tenantID, who.holder(), ceremony); err != nil {
		return nil, err
	}

	s.log.Debug("started a passkey registration",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("rp_id", rpID),
		logger.Int("excluded", len(exclude)), logger.RequestID(ctx))
	return creation, nil
}

// registerFinish verifies the answer of one registration and stores the Passkey.
//
// The challenge is deleted before the answer is verified, so a captured answer
// cannot be replayed against it. A verification that then fails costs the person
// one restart, which is the price of a challenge that is consumed exactly once.
//
// The row and the audit event land on one transaction, and finish runs on it
// too, after the row lands. The sign-in path completes the Login Session there,
// so an enrolment that reports a Factor is an enrolment the database records.
// The portal path passes nil: it holds an access token, and no login session
// waits on this registration.
//
// The notification is sent after the transaction, because a message a relay
// accepted cannot be rolled back.
//
// A credential id a live row already holds is refused. A credential id a removed
// row holds takes that row back. See claim, which decides between the two.
//
// No private key exists here. The stored blob is a public key and its metadata.
func (s *Service) registerFinish(
	ctx context.Context, tenantID, host, origin, name string, who Principal, answer []byte,
	finish func(context.Context) error,
) (Credential, error) {
	party, rpID, err := s.relying(ctx, tenantID, host, origin)
	if err != nil {
		return Credential{}, err
	}

	ceremony, err := s.consume(ctx, tenantID, who.holder(), who)
	if err != nil {
		return Credential{}, err
	}

	person, err := s.account(ctx, tenantID, who.UserID)
	if err != nil {
		return Credential{}, err
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(answer)
	if err != nil {
		s.log.Warn("refused a malformed passkey registration",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.String("rp_id", rpID))
		return Credential{}, fmt.Errorf("%w: user %s", ErrRejected, who.UserID)
	}

	made, err := party.CreateCredential(person, ceremony, parsed)
	if err != nil {
		s.log.Warn("refused a passkey registration",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID),
			logger.String("rp_id", rpID), logger.Err(err))
		return Credential{}, fmt.Errorf("%w: user %s", ErrRejected, who.UserID)
	}

	// The library's own type, marshaled verbatim. No Go type in this package
	// parses it, so a new field of the library lands without a migration.
	blob, err := json.Marshal(made)
	if err != nil {
		s.log.Error("marshal the passkey credential",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Credential{}, fmt.Errorf("marshal the passkey of user %s: %w", who.UserID, err)
	}

	if name = strings.TrimSpace(name); name == "" {
		name = defaultName
	}

	row := Credential{
		TenantID:     tenantID,
		CredentialID: made.ID,
		UserID:       who.UserID,
		RPID:         rpID,
		Record:       string(blob),
		Name:         name,
		CreatedAt:    time.Now().UTC(),
	}

	write, err := s.claim(ctx, tenantID, who, made.ID)
	if err != nil {
		return Credential{}, err
	}

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := write(ctx, row); err != nil {
			return err
		}
		if err := s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    who.UserID,
			Action:     audit.ActionMFAPasskeyRegistered,
			EntityType: audit.EntityUser,
			EntityID:   who.UserID,
			IP:         who.IP,
			UserAgent:  who.UserAgent,
			Metadata:   map[string]any{"credential_id": credentialID(made.ID)},
		}); err != nil {
			return err
		}
		if finish == nil {
			return nil
		}
		return finish(ctx)
	})
	if err != nil {
		s.log.Error("register a passkey",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return Credential{}, err
	}

	s.log.Info("registered a passkey",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("rp_id", rpID),
		logger.String("credential_id", credentialID(made.ID)))

	s.notify(ctx, tenantID, who.UserID, name)
	return row, nil
}

// claim decides how one proved credential reaches the table, and refuses the id
// of a device that is already registered.
//
// The primary key is (tenant_id, credential_id), so three states exist for one
// id and each needs its own answer:
//
//   - No row: insert.
//   - A removed row: revive it. The device registered here before, somebody
//     removed it, and the person is registering it again. A plain insert would
//     fail on the primary key, and the person could never use that device again.
//   - A live row: refuse. The exclude list already stops one person registering
//     their own device twice, and this is the case it cannot see, where the row
//     belongs to another account of the same tenant.
//
// It reads before the transaction opens and answers the write to run inside it.
// Two registrations of one id that race still cannot both land: the insert meets
// the primary key, and the revive demands a row that still carries the delete
// mark.
func (s *Service) claim(
	ctx context.Context, tenantID string, who Principal, credID []byte,
) (func(context.Context, Credential) error, error) {
	held, err := s.deps.Find(ctx, tenantID, credID)
	if errors.Is(err, ErrNotFound) {
		return s.deps.Insert, nil
	}
	if err != nil {
		s.log.Error("find the passkey by its credential id",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return nil, err
	}

	if held.DeletedAt.IsZero() {
		s.log.Warn("refused a passkey registration of a device already registered",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID),
			logger.String("credential_id", credentialID(credID)))
		return nil, fmt.Errorf("%w: credential %s", ErrDuplicateDevice, credentialID(credID))
	}

	s.log.Debug("revive a removed passkey",
		logger.String("tenant_id", tenantID),
		logger.String("user_id", who.UserID),
		logger.String("credential_id", credentialID(credID)), logger.RequestID(ctx))
	return s.deps.Revive, nil
}

// relying builds the WebAuthn Relying Party of one request, and refuses an
// origin it does not cover.
//
// The RP ID is the registrable domain of the same verified host that already
// resolved the tenant, so a deployment configures nothing per tenant. The
// override replaces it for a development host, where the registrable domain is
// empty and no ceremony could otherwise run.
//
// The origins are the hosts the tenant serves, plus the Portal and Console
// origins of the deployment. The library refuses to start without them.
//
// Only the origins the RP ID covers are kept. A device binds its key pair to the
// RP ID, so a Passkey created from any other origin is a Factor no sign-in can
// answer. Dropping those origins is what stops one being created: the library
// then refuses the finish, and the check below refuses the start.
//
// The caller's own origin is checked when the request names one. Both BFFs call
// server to server, so no browser header arrives, and each one decides what to
// name. The portal BFF names its own origin on the registration start, which is
// the origin the browser will run that ceremony at, so a deployment that covers
// no portal origin is refused before a key pair exists. The login BFF names
// none: it runs at the verified host that resolved this request, and that host
// is already one of the origins above, so the check would only repeat it.
//
// An empty value is therefore not a refusal. The finish still compares the
// origin the device signed against the list kept here, which is where the rule
// is enforced for every caller.
func (s *Service) relying(
	ctx context.Context, tenantID, host, origin string,
) (*webauthn.WebAuthn, string, error) {
	rpID := s.deps.RPIDOverride
	if rpID == "" {
		rpID = utils.RegistrableDomain(host)
	}
	if rpID == "" {
		s.log.Error("the host has no registrable domain and no rp id is configured",
			logger.String("tenant_id", tenantID), logger.String("host", host))
		return nil, "", fmt.Errorf("%w: host %s", ErrCeremonyUnavailable, host)
	}

	origins, err := s.deps.Origins(ctx, tenantID)
	if err != nil {
		s.log.Error("read the passkey origins",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return nil, "", fmt.Errorf("%w: tenant %s", ErrCeremonyUnavailable, tenantID)
	}

	covered := covers(rpID, origins)
	if len(covered) == 0 {
		s.log.Warn("refused a passkey ceremony: the rp id covers no origin this tenant serves",
			logger.String("tenant_id", tenantID),
			logger.String("rp_id", rpID), logger.Int("origins", len(origins)))
		return nil, "", fmt.Errorf("%w: rp id %s covers none of %d origins",
			ErrOriginRefused, rpID, len(origins))
	}

	if origin != "" && !served(origin, covered) {
		s.log.Warn("refused a passkey ceremony from an origin the rp id does not cover",
			logger.String("tenant_id", tenantID),
			logger.String("rp_id", rpID), logger.String("origin", origin))
		return nil, "", fmt.Errorf("%w: origin %s under rp id %s", ErrOriginRefused, origin, rpID)
	}

	party, err := webauthn.New(&webauthn.Config{
		RPID: rpID,
		// The RP ID is what a browser shows beside the prompt, and this
		// deployment holds no other name for the relying party.
		RPDisplayName: rpID,
		RPOrigins:     covered,
		// Attestation asks the device to name its make and model. This
		// deployment runs no metadata service and refuses no model, so asking
		// for it would collect what nothing reads.
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// The password already proved knowledge. Demanding verification
			// here locks out a security key that holds no PIN.
			UserVerification: protocol.VerificationPreferred,
			// A Second Factor is never the first one, so no device needs to
			// discover this account without an identifier.
			ResidentKey: protocol.ResidentKeyRequirementDiscouraged,
		},
	})
	if err != nil {
		s.log.Error("build the passkey relying party",
			logger.String("tenant_id", tenantID),
			logger.String("rp_id", rpID),
			logger.Int("origins", len(covered)), logger.Err(err))
		return nil, "", fmt.Errorf("%w: tenant %s", ErrCeremonyUnavailable, tenantID)
	}
	return party, rpID, nil
}

// account reads the person one ceremony runs for, and the Passkeys they already
// hold.
//
// The user handle is the user id, and no column stores it. The name beside it is
// display only, and the library refuses a person with no name, so an account
// that holds neither an email address nor a username falls back to the id.
//
// A read that fails stops the ceremony, unlike the TOTP label, which carries on
// with the id. Both reads here are plain database reads, and the first of them
// answers the exclude list: a ceremony that ran without it would offer to
// register a device the person already holds.
func (s *Service) account(ctx context.Context, tenantID, userID string) (account, error) {
	held, err := s.deps.List(ctx, tenantID, userID)
	if err != nil {
		s.log.Error("list the passkeys",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", userID), logger.Err(err))
		return account{}, err
	}

	name, err := s.deps.Account(ctx, tenantID, userID)
	if err != nil {
		s.log.Error("read the account name for the passkey ceremony",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", userID), logger.Err(err))
		return account{}, err
	}
	if name == "" {
		name = userID
	}

	person := account{
		id:          userID,
		name:        name,
		credentials: make([]webauthn.Credential, 0, len(held)),
		held:        len(held),
	}
	for _, row := range held {
		var one webauthn.Credential
		if err := json.Unmarshal([]byte(row.Record), &one); err != nil {
			// One unreadable row must not cost the person every other device.
			// The row is named so an operator can find it, and the ceremony runs
			// without it.
			s.log.Error("read a stored passkey",
				logger.String("tenant_id", tenantID),
				logger.String("user_id", userID),
				logger.String("credential_id", credentialID(row.CredentialID)), logger.Err(err))
			continue
		}
		person.credentials = append(person.credentials, one)
	}
	return person, nil
}

// spendEnrolment spends one registration start of the person's trailing-window
// enrolment budget, and refuses the start when nothing is left.
//
// The budget is its own, and it is not the shared second-factor guessing budget
// in totp.Service.spendGuess. The two are apart on purpose. A guess answers a
// challenge, and a registration start answers nothing: it mints options and
// stores a challenge. A person who cancels a browser prompt did not guess, so
// that cancel must never cost them the code sign-in that reads the other budget.
//
// The sign-in challenge start holds a third counter, in spendChallenge, for the
// same reason. Neither start spends the shared budget, and the refusal of each
// one reads as the same rate_limited slug, so an attacker learns nothing about
// which counter refused them.
//
// A cache failure refuses the start. Redis holds the whole counter, the way it
// holds the whole challenge, so a start that ran without it would leave the
// enrolment path unbounded for as long as Redis is down.
//
// The refusal is ErrCeremonyUnavailable and not a budget sentinel of its own.
// The person is told the ceremony could not run, which is what happened, and the
// log line above names the counter.
func (s *Service) spendEnrolment(ctx context.Context, tenantID, userID string) error {
	allowed, err := s.deps.Ceremony.AllowInWindow(
		ctx, enrolKey(tenantID, userID), enrolLimit, enrolWindow)
	if err != nil {
		s.log.Error("read the passkey enrolment budget",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", userID), logger.Err(err))
		return fmt.Errorf("%w: user %s", ErrCeremonyUnavailable, userID)
	}
	if allowed {
		return nil
	}

	s.log.Warn("refused a passkey registration start over the budget",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))
	return fmt.Errorf("%w: user %s", ErrTooManyEnrolments, userID)
}

// spendChallenge spends one challenge start of the person's trailing-window
// challenge budget, and refuses the start when nothing is left.
//
// The budget is its own, and it is not the shared second-factor guessing budget
// in totp.Service.spendGuess. A start answers nothing: it mints options and
// stores a challenge, and the finish beside it is what answers. A person who
// cancels the browser sheet is mid sign-in and holds no token, so that cancel
// must never cost them the code path they have left.
//
// Guessing stays bounded without it. consume deletes the challenge, so a wrong
// answer forces a new start, and the new start spends this budget.
//
// A cache failure refuses the start, the way it refuses a registration start.
// Redis holds the whole counter, so a start that ran without it would leave the
// challenge path unbounded for as long as Redis is down.
func (s *Service) spendChallenge(ctx context.Context, tenantID, userID string) error {
	allowed, err := s.deps.Ceremony.AllowInWindow(
		ctx, challengeKey(tenantID, userID), challengeLimit, challengeWindow)
	if err != nil {
		s.log.Error("read the passkey challenge budget",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", userID), logger.Err(err))
		return fmt.Errorf("%w: user %s", ErrCeremonyUnavailable, userID)
	}
	if allowed {
		return nil
	}

	s.log.Warn("refused a passkey challenge start over the budget",
		logger.String("tenant_id", tenantID), logger.String("user_id", userID))
	return fmt.Errorf("%w: user %s", ErrTooManyChallenges, userID)
}

// store writes the challenge of one ceremony, under a short TTL.
//
// A start replaces whatever the holder had in flight, so a person who cancelled
// a browser prompt starts again at once. At most one challenge of one holder is
// ever live, and the finish below consumes it.
//
// A cache failure refuses the ceremony. Redis is only a cache elsewhere in this
// gateway, and here it is the whole challenge: a ceremony that proceeds without
// a stored challenge proves nothing.
func (s *Service) store(
	ctx context.Context, tenantID, holder string, ceremony *webauthn.SessionData,
) error {
	blob, err := json.Marshal(ceremony)
	if err != nil {
		s.log.Error("marshal the passkey ceremony",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return fmt.Errorf("%w: tenant %s", ErrCeremonyUnavailable, tenantID)
	}

	if err := s.deps.Ceremony.Set(
		ctx, ceremonyKey(tenantID, holder), string(blob), ceremonyTTL,
	); err != nil {
		s.log.Error("write the passkey ceremony",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return fmt.Errorf("%w: tenant %s", ErrCeremonyUnavailable, tenantID)
	}
	return nil
}

// consume reads the challenge of one ceremony and deletes it.
//
// The delete runs before the answer is verified, so one challenge answers one
// ceremony however that ceremony ends. A captured answer replayed against it
// finds nothing.
//
// A delete that fails is logged and does not refuse the ceremony. The read
// already succeeded, the TTL removes the key anyway, and refusing here would
// cost the person a registration that is otherwise sound.
func (s *Service) consume(
	ctx context.Context, tenantID, holder string, who Principal,
) (webauthn.SessionData, error) {
	key := ceremonyKey(tenantID, holder)

	blob, err := s.deps.Ceremony.Get(ctx, key)
	if errors.Is(err, cache.ErrCacheMiss) {
		s.log.Warn("refused a passkey answer with no challenge behind it",
			logger.String("tenant_id", tenantID), logger.String("user_id", who.UserID))
		return webauthn.SessionData{}, fmt.Errorf("%w: user %s", ErrChallengeExpired, who.UserID)
	}
	if err != nil {
		s.log.Error("read the passkey ceremony",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return webauthn.SessionData{}, fmt.Errorf("%w: user %s", ErrCeremonyUnavailable, who.UserID)
	}

	if err := s.deps.Ceremony.Del(ctx, key); err != nil {
		s.log.Error("delete the passkey ceremony",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
	}

	var ceremony webauthn.SessionData
	if err := json.Unmarshal([]byte(blob), &ceremony); err != nil {
		s.log.Error("read the stored passkey ceremony",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return webauthn.SessionData{}, fmt.Errorf("%w: user %s", ErrChallengeExpired, who.UserID)
	}
	return ceremony, nil
}

// notify tells the person that a Passkey was registered on their account.
//
// It runs after the transaction and it refuses nothing. The key pair is already
// stored and the audit trail already records it, so a relay that is down must
// not undo a registration the person completed.
func (s *Service) notify(ctx context.Context, tenantID, userID, deviceName string) {
	if s.deps.Notify == nil {
		return
	}
	if err := s.deps.Notify(ctx, tenantID, userID, deviceName); err != nil {
		s.log.Error("send the passkey registration notice",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", userID), logger.Err(err))
	}
}

// covers keeps the origins the RP ID covers, in the order they were given.
//
// A device binds its key pair to the RP ID and answers under that domain alone,
// so an origin outside it can neither create a Passkey this tenant can use nor
// answer a challenge with one. The deployment names the Portal and the Console,
// and a tenant whose RP ID does not reach them keeps the rest.
//
// The suffix must break on a label. Otherwise notexample.com would pass under the
// RP ID example.com, and a device would bind to a domain somebody else owns.
func covers(rpID string, origins []string) []string {
	kept := make([]string, 0, len(origins))
	for _, one := range origins {
		parsed, err := url.Parse(strings.TrimSuffix(one, "/"))
		if err != nil {
			continue
		}

		host := strings.ToLower(parsed.Hostname())
		if host == rpID || strings.HasSuffix(host, "."+rpID) {
			kept = append(kept, one)
		}
	}
	return kept
}

// served reports whether origin is one of the origins this ceremony may run
// from. The comparison ignores case and a trailing slash, which is what a
// canonical origin comparison is.
func served(origin string, allowed []string) bool {
	origin = strings.TrimSuffix(origin, "/")
	for _, one := range allowed {
		if strings.EqualFold(strings.TrimSuffix(one, "/"), origin) {
			return true
		}
	}
	return false
}

// credentialID spells one credential id for a log line and an audit event. It is
// the same base64url spelling the browser and the list answer use, so an
// operator matches a log line to a row the person can see.
//
// It is not a credential. The id is a public handle: the browser sends it in the
// clear on every assertion.
func credentialID(raw []byte) string {
	return protocol.URLEncodedBase64(raw).String()
}
