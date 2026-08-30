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
)

// ceremonyTTL bounds one ceremony. It matches the timeout a browser gives the
// person to touch the device, so a prompt that is still open never meets an
// expired challenge.
const ceremonyTTL = 5 * time.Minute

// defaultName is what a Passkey is called when the person named none. The column
// is nullable and names are not unique, so a person with two unnamed devices
// reads this word twice and renames the one they mean.
const defaultName = "Passkey"

// ceremonyKey names the one live ceremony of one holder. A Portal registration
// keys on the subject of the access token, so no identifier is minted for it.
//
// The tenant id is part of the key, so a ceremony of one tenant is never read
// under another.
func ceremonyKey(tenantID, holder string) string {
	return fmt.Sprintf("passkey_ceremony:%s:%s", tenantID, holder)
}

// Principal is what the caller knows about the person one ceremony runs for.
//
// It is not the login session type and it is not the user type. This module
// imports neither domain, so the router projects each of them onto this shape.
type Principal struct {
	UserID    string
	IP        string
	UserAgent string
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

	// BudgetSpender spends one guess of the shared second-factor budget of one
	// person. It answers the refusal sentinels of the TOTP module, which owns
	// the budget, so one cap covers both Second Factors.
	BudgetSpender func(ctx context.Context, tenantID, userID string) error

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
	Origins OriginLister

	// Budget is the shared second-factor guessing budget. A ceremony start
	// spends it, because a start is the request that costs work and a valid
	// session can otherwise ask for challenges without end.
	Budget BudgetSpender

	// Notify tells the person a Passkey was registered. A nil value sends
	// nothing, which is what a deployment with no transport does.
	Notify Notifier

	// RPIDOverride replaces the RP ID derived from the request host. It is set
	// for a development host alone, where the registrable domain is empty and no
	// ceremony could otherwise run.
	RPIDOverride string

	// Ceremony holds the challenge of one ceremony in flight. It is Redis and
	// nothing else: no table holds a challenge. See
	// docs/adr/0002-session-storage.md, which names this the second exception to
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
// The budget is spent first, before anything is read. A start is what costs the
// gateway work, and a person who holds a valid token could otherwise ask for
// challenges without end.
//
// The origin is checked before the options are minted. A key pair created under
// an origin the RP ID does not cover is a Factor no sign-in can answer, so it
// must never be created.
//
// The exclude list names every Passkey the person already holds, so a device
// that already registered tells the person so instead of creating a second key
// pair for the same account.
func (s *Service) registerStart(
	ctx context.Context, tenantID, host, origin string, who Principal,
) (*protocol.CredentialCreation, error) {
	if err := s.deps.Budget(ctx, tenantID, who.UserID); err != nil {
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

	if err := s.store(ctx, tenantID, who.UserID, ceremony); err != nil {
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
// The row and the audit event land on one transaction. The notification is sent
// after it, because a message a relay accepted cannot be rolled back.
//
// No private key exists here. The stored blob is a public key and its metadata.
func (s *Service) registerFinish(
	ctx context.Context, tenantID, host, origin, name string, who Principal, answer []byte,
) (Credential, error) {
	party, rpID, err := s.relying(ctx, tenantID, host, origin)
	if err != nil {
		return Credential{}, err
	}

	ceremony, err := s.consume(ctx, tenantID, who)
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

	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Insert(ctx, row); err != nil {
			return err
		}
		return s.deps.Audit.Record(ctx, audit.Entry{
			TenantID:   tenantID,
			ActorID:    who.UserID,
			Action:     audit.ActionMFAPasskeyRegistered,
			EntityType: audit.EntityUser,
			EntityID:   who.UserID,
			IP:         who.IP,
			UserAgent:  who.UserAgent,
			Metadata:   map[string]any{"credential_id": credentialID(made.ID)},
		})
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
// The caller's own origin is checked when the request names one. A browser sends
// it, and the Portal BFF forwards a call that has none, so an empty value is not
// a refusal: the finish still compares the origin the device signed against the
// list kept here.
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

	person := account{id: userID, name: name, credentials: make([]webauthn.Credential, 0, len(held))}
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
	ctx context.Context, tenantID string, who Principal,
) (webauthn.SessionData, error) {
	key := ceremonyKey(tenantID, who.UserID)

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
