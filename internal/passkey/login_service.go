package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"

	"alphaomega/identitygateway/internal/platform/logger"
)

// The sign-in half of the module: the Passkey challenge a person answers after
// the password.
//
// The ceremony keys on the Login Session id, so no identifier is minted for it
// and a person who opens a second sign-in never answers the challenge of the
// first.
//
// A failure here never ends the sign-in. The person retries on the same screen,
// or picks the other Second Factor, and the Login Session is untouched either
// way. See LoginFinish, which states why.

// LoginStart hands the person the assertion options their browser passes to
// navigator.credentials.get().
//
// The budget is spent before the ceremony is built, and after the session is
// read. A start is what costs the gateway work. A request that names no live
// session buys nothing and spends nothing.
//
// The budget is the challenge budget of spendChallenge, and it is not the shared
// second-factor guessing budget. A start answers nothing, so a cancelled browser
// sheet must not cost the person the code sign-in beside it. LoginFinish is what
// answers, and consume deletes the challenge, so every retry pays a new start.
//
// The allow list is every live Passkey of the person. A device that holds none
// of them cannot answer, and the browser says so without a prompt.
//
// A person who holds no Passkey is refused here. Only the password answer routes
// a person to this step, so a request that arrives without one is a client that
// went its own way.
//
// A person whose every stored Passkey is unreadable is refused differently. The
// step signal counts rows and this reads them, so the two would otherwise
// disagree: the password step would name a step this ceremony calls impossible.
// It is the gateway that cannot read its own data, so the answer says so and the
// person is not told they hold nothing.
func (s *Service) LoginStart(
	ctx context.Context, tenantID, host, origin, token string,
) (*protocol.CredentialAssertion, error) {
	s.log.Debug("start a passkey challenge",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	who, err := s.principal(ctx, tenantID, token)
	if err != nil {
		return nil, err
	}

	if err := s.spendChallenge(ctx, tenantID, who.UserID); err != nil {
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
	if len(person.credentials) == 0 {
		if person.held > 0 {
			// account logged each unreadable row with its credential id, which is
			// where an operator starts.
			s.log.Error("refused a passkey challenge: no stored passkey could be read",
				logger.String("tenant_id", tenantID),
				logger.String("session_id", who.SessionID),
				logger.String("user_id", who.UserID), logger.Int("held", person.held))
			return nil, fmt.Errorf("%w: user %s holds %d unreadable passkeys",
				ErrCeremonyUnavailable, who.UserID, person.held)
		}

		s.log.Warn("refused a passkey challenge for a person who holds none",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID))
		return nil, fmt.Errorf("%w: user %s", ErrNoPasskey, who.UserID)
	}

	assertion, ceremony, err := party.BeginLogin(person)
	if err != nil {
		s.log.Error("begin a passkey challenge",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID),
			logger.String("rp_id", rpID), logger.Err(err))
		return nil, fmt.Errorf("%w: user %s", ErrCeremonyUnavailable, who.UserID)
	}

	if err := s.store(ctx, tenantID, who.holder(), ceremony); err != nil {
		return nil, err
	}

	s.log.Debug("started a passkey challenge",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID),
		logger.String("rp_id", rpID),
		logger.Int("allowed", len(person.credentials)), logger.RequestID(ctx))
	return assertion, nil
}

// LoginFinish verifies one assertion and signs the person in.
//
// The challenge is deleted before the answer is verified, so a captured answer
// cannot be replayed against it. A replayed challenge and an expired one both
// find nothing, and both answer ErrChallengeExpired: the key is gone either way,
// and the gateway cannot tell which of them happened.
//
// The write-back, the session completion, and the audit row land on one
// transaction. A sign-in that reports the Factor is a sign-in the database
// records, and a counter the database advanced is a counter the person got a
// session for.
//
// A failed assertion counts against nothing but the challenge budget the start
// already spent. It never counts against the wrong-code cap of the Login
// Session: a signature is not a guessable value, and a hostile page that could
// burn those five failures would hold a free way to end a person's sign-in.
//
// The answer is the object the browser produced, passed through whole. Nothing
// between the device and this call picks a field out of it, because every field
// is part of what the signature covers.
func (s *Service) LoginFinish(
	ctx context.Context, tenantID, host, origin, token string, answer []byte,
) (string, error) {
	s.log.Debug("finish a passkey challenge",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	who, err := s.principal(ctx, tenantID, token)
	if err != nil {
		return "", err
	}

	party, rpID, err := s.relying(ctx, tenantID, host, origin)
	if err != nil {
		return "", err
	}

	ceremony, err := s.consume(ctx, tenantID, who.holder(), who)
	if err != nil {
		return "", err
	}

	person, err := s.account(ctx, tenantID, who.UserID)
	if err != nil {
		return "", err
	}

	parsed, err := protocol.ParseCredentialRequestResponseBytes(answer)
	if err != nil {
		s.log.Warn("refused a malformed passkey assertion",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID), logger.String("rp_id", rpID))
		return "", fmt.Errorf("%w: user %s", ErrRejected, who.UserID)
	}

	proved, err := party.ValidateLogin(person, ceremony, parsed)
	if err != nil {
		return "", s.refuse(ctx, tenantID, rpID, who, parsed.RawID, err)
	}

	// A counter that goes backwards says the device may be a clone. It is logged
	// and it refuses nothing: a synced passkey reports zero on every assertion,
	// so refusing here would shut out every person whose device syncs its keys.
	if proved.Authenticator.CloneWarning {
		s.log.Warn("a passkey reported a sign counter that went backwards",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID),
			logger.String("credential_id", credentialID(proved.ID)))
	}

	// The library's own type, marshaled verbatim, exactly as the registration
	// stored it. The new sign counter and the new backup state ride inside it.
	blob, err := json.Marshal(proved)
	if err != nil {
		s.log.Error("marshal the proved passkey",
			logger.String("tenant_id", tenantID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return "", fmt.Errorf("marshal the passkey of user %s: %w", who.UserID, err)
	}

	var rotated string
	err = s.deps.InTx(ctx, func(ctx context.Context) error {
		if err := s.deps.Touch(
			ctx, tenantID, who.UserID, proved.ID, string(blob),
		); err != nil {
			return err
		}
		upgraded, err := s.deps.CompleteSession(ctx, tenantID, token, who.UserID)
		rotated = upgraded
		return err
	})
	if err != nil {
		s.log.Error("finish a passkey challenge",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID), logger.Err(err))
		return "", err
	}

	s.log.Info("verified a passkey",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID),
		logger.String("credential_id", credentialID(proved.ID)))
	return rotated, nil
}

// refuse says what the person is told when the library rejects an assertion.
//
// A credential the person does not own gets a slug of its own. The library names
// that case, and it is the one refusal a person can act on: they picked the
// wrong device, and a device of their own still works.
//
// Everything else is one answer. A wrong signature, an answer to another
// challenge, and a device that failed its own checks all read the same, and the
// answer never says which of them happened.
func (s *Service) refuse(
	ctx context.Context, tenantID, rpID string, who Principal, credID []byte, err error,
) error {
	var unknown *protocol.ErrorUnknownCredential
	if errors.As(err, &unknown) {
		s.log.Warn("refused a passkey that belongs to another person",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID),
			logger.String("user_id", who.UserID),
			logger.String("credential_id", credentialID(credID)))
		return fmt.Errorf("%w: user %s", ErrCredentialUnknown, who.UserID)
	}

	s.log.Warn("refused a passkey assertion",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID),
		logger.String("rp_id", rpID), logger.Err(err), logger.RequestID(ctx))
	return fmt.Errorf("%w: user %s", ErrRejected, who.UserID)
}

// principal reads the Login Session one token credentials, and refuses one that
// has not proved a password.
//
// A session that names nobody is refused too. It cannot have proved a password,
// because the password step is what binds the person.
//
// A session that names no session id is refused as well. Every address behind
// this guard keys its ceremony on holder(), and a blank session id there falls
// back to the person. The fallback is what the Portal wants and what a sign-in
// must never reach: two sign-ins of one person would share one ceremony.
//
// The TOTP module runs the same guard on its own addresses. Both are needed:
// each module owns what an unfinished session may do at its own routes.
func (s *Service) principal(ctx context.Context, tenantID, token string) (Principal, error) {
	who, err := s.deps.FindSession(ctx, tenantID, token)
	if err != nil {
		return Principal{}, err
	}
	if !who.PasswordProved || who.UserID == "" || who.SessionID == "" {
		s.log.Warn("refused a passkey ceremony on a session that proved no password",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", who.SessionID))
		return Principal{}, fmt.Errorf("%w: session %s", ErrPasswordNotProved, who.SessionID)
	}
	return who, nil
}

// LoginEnrolStart hands the person the registration options their browser
// passes to navigator.credentials.create().
//
// It is the enrolment half of the sign-in: a person the MFA Requirement governs,
// who holds no Second Factor, reaches this instead of a challenge. The password
// answer names the step, and the Authenticator sits beside it on the same
// screen, so a device with no authenticator never dead-ends.
//
// It demands the password, and it demands that the person holds no Second
// Factor. refuseHeldFactor says why the second rule is here.
//
// The guard runs before registerStart, so a refused start spends no enrolment
// budget and mints no ceremony. The finish below runs it again, because a Factor
// the account gains while the browser prompt is open would otherwise be met by
// the Passkey this finish records.
//
// The ceremony keys on the Login Session id, the way the challenge does. A
// person who opens a second sign-in never answers the ceremony of the first.
func (s *Service) LoginEnrolStart(
	ctx context.Context, tenantID, host, origin, token string,
) (*protocol.CredentialCreation, error) {
	s.log.Debug("start a passkey enrolment at sign-in",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	who, err := s.principal(ctx, tenantID, token)
	if err != nil {
		return nil, err
	}
	if err := s.refuseHeldFactor(ctx, tenantID, who); err != nil {
		return nil, err
	}

	return s.registerStart(ctx, tenantID, host, origin, who)
}

// refuseHeldFactor refuses a sign-in enrolment for a person who already holds a
// Second Factor.
//
// It reads the pending steps of the account, through one closure the router
// builds once, and never the two Factor tables. A person the steps name a
// challenge for is a person who holds a Factor. The rule is one sentence: a
// sign-in enrols a Second Factor only for a person who holds none. A person who
// holds one is challenged.
//
// Without it the sign-in has a way around the challenge. The finalize gate
// re-reads the account on purpose, so a Factor this route recorded mid sign-in
// meets the challenge step the account owes, and a person who holds the password
// alone reaches a token without touching the device.
//
// It is not the cap registerStart checks. That cap counts Passkeys and governs
// the portal too. This reads both Factors and governs the sign-in alone: the
// portal is where a person adds a second kind of Factor beside the one they
// already hold.
//
// The TOTP module runs the same guard on its own enrolment addresses, and the
// body there is a copy of this one. Both are needed: each module owns what an
// unfinished session may do at its own routes.
//
// The two copies stay, and they cannot drift into a bypass, because the rule is
// not written here. The predicate is the one closure the router builds, and
// these lines only read the bool it answers, log the refusal, and wrap a
// sentinel. ADR 0011 records that decision.
//
// The refusal is logged here, because this is where it stops. The read behind it
// is not: the router composes that read and logs its own failure.
func (s *Service) refuseHeldFactor(ctx context.Context, tenantID string, who Principal) error {
	held, err := s.deps.HoldsFactor(ctx, tenantID, who.UserID)
	if err != nil {
		// Nothing is logged here. The composed read logs its own failure, and it
		// is the last layer that can say which read of which Factor failed.
		return fmt.Errorf("read the second factors of user %s: %w", who.UserID, err)
	}
	if !held {
		return nil
	}

	s.log.Warn("refused a sign-in enrolment for a person who holds a second factor",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID))
	return fmt.Errorf("%w: user %s", ErrFactorAlreadyHeld, who.UserID)
}

// LoginEnrolFinish stores the proved Passkey and signs the person in.
//
// The Passkey row, the audit row, and the session completion land on one
// transaction. A sign-in that reports the Factor is a sign-in the database
// records, and a Passkey the database kept is a Passkey the person got a session
// for.
//
// The person continues straight to the application. They proved the password and
// they proved possession of the device, so a second challenge would ask for what
// the enrolment already showed.
//
// The device is not named here. The sign-in screen asks for no name, so the
// registration takes the default, and the person renames it in the portal.
//
// The held-Factor guard runs here too, and not on the start alone. The ceremony
// lives for its TTL, so an account that gains a Factor while the prompt is open
// reaches this finish owing a challenge. The Passkey this finish records would
// meet that challenge, which is the bypass the start refuses, one call later and
// one ceremony wide.
//
// A refusal leaves the sign-in alive. The person tries again on the same screen,
// or enrols an Authenticator instead.
func (s *Service) LoginEnrolFinish(
	ctx context.Context, tenantID, host, origin, token string, answer []byte,
) (string, error) {
	s.log.Debug("finish a passkey enrolment at sign-in",
		logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	who, err := s.principal(ctx, tenantID, token)
	if err != nil {
		return "", err
	}
	if err := s.refuseHeldFactor(ctx, tenantID, who); err != nil {
		return "", err
	}

	var rotated string
	if _, err := s.registerFinish(ctx, tenantID, host, origin, "", who, answer,
		func(ctx context.Context) error {
			upgraded, err := s.deps.CompleteSession(ctx, tenantID, token, who.UserID)
			rotated = upgraded
			return err
		},
	); err != nil {
		return "", err
	}

	s.log.Info("enrolled a passkey at sign-in",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", who.SessionID),
		logger.String("user_id", who.UserID))
	return rotated, nil
}
