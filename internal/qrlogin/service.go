package qrlogin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/di"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/user"
	"alphaomega/identitygateway/internal/utils"
)

// Starter opens one transaction with the Scan Verifier and binds it to a nonce.
// It is the one operation this flow calls out with. The Scan Verifier reports the
// result by pushing it to the callback, so nothing here reads back.
type Starter func(ctx context.Context, nonce string) (di.Transaction, error)

// UserFinder reads the person one username names. It returns user.ErrNotFound on
// a miss. There is deliberately no create: a scan never becomes a registration
// nobody approved.
type UserFinder func(ctx context.Context, tenantID, username string) (string, error)

// Deps is everything the service reaches outside itself. Every field is a
// function value or a recorder, so the logic is testable without a database and
// without the Scan Verifier.
type Deps struct {
	Start Starter

	Insert        func(ctx context.Context, row Transaction) error
	ByVerifierRef func(ctx context.Context, sessionID, presentationID string) (Transaction, error)
	ByLoginSess   func(ctx context.Context, tenantID, loginSessionID string) (Transaction, error)
	Consume       func(ctx context.Context, tenantID, id string, now time.Time) error
	SetResult     func(ctx context.Context, tenantID, id string, state int, userID string) error

	OpenSession     func(ctx context.Context, tenantID, ip, userAgent string) (session.Opened, error)
	FindSession     func(ctx context.Context, tenantID, token string) (session.LoginSession, error)
	CompleteSession func(ctx context.Context, tenantID, token, userID, factor string) (session.Opened, error)

	User  UserFinder
	Audit *audit.Recorder
	Log   logger.Logger

	// Now reads the clock. A test sets it, and every other caller leaves it nil.
	Now func() time.Time
}

// Service owns the three steps that turn a scan into a sign-in.
//
// The division of labour between the callback and the poll is not free. Recording
// a factor rotates the login session token, and the browser is polling with that
// token. A callback that recorded the factor would invalidate the token before the
// browser learned that it had succeeded. So the callback writes the result on the
// transaction and never touches the login session, and the poll, the only party
// holding a valid token, binds the person and records the factor.
type Service struct {
	deps Deps
	log  logger.Logger
	now  func() time.Time
}

func NewService(deps Deps) *Service {
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	return &Service{deps: deps, log: deps.Log, now: now}
}

// Started is what the browser gets back from the start step.
type Started struct {
	SessionID    string
	SessionToken string
	// QRCode is the code object of the Scan Verifier, unchanged. A re-encode
	// drops every field the verifier adds, including the fallback link the
	// sign-in page offers as "no app?".
	QRCode json.RawMessage
	// ExpiresIn is how long the code stays scannable, in seconds, so the browser
	// counts down against the window this deployment enforces.
	ExpiresIn int
}

// Meta is the address and the agent of the request, for the audit trail.
type Meta struct {
	IP        string
	UserAgent string
}

// Start opens a login session that names nobody, mints a nonce, asks the Scan
// Verifier for a transaction, and records the pair.
//
// The Scan Verifier is called before the login session is opened. A transaction
// this deployment could not open must leave nothing behind.
func (s *Service) Start(ctx context.Context, tenantID string, meta Meta) (Started, error) {
	s.log.Debug("start qr login", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	// A fresh nonce per transaction. Reusing one would let a presentation
	// captured from any transaction replay into another.
	nonce, err := aocrypto.SessionToken()
	if err != nil {
		s.log.Error("mint qr login nonce", logger.String("tenant_id", tenantID), logger.Err(err))
		return Started{}, fmt.Errorf("mint qr login nonce: %w", err)
	}

	txn, err := s.deps.Start(ctx, nonce)
	if err != nil {
		s.log.Error("start verifier transaction", logger.String("tenant_id", tenantID), logger.Err(err))
		return Started{}, err
	}

	opened, err := s.deps.OpenSession(ctx, tenantID, meta.IP, meta.UserAgent)
	if err != nil {
		return Started{}, err
	}

	now := s.now().UTC()
	row := Transaction{
		ID:                     utils.NewUUIDv7(),
		TenantID:               tenantID,
		LoginSessionID:         opened.ID,
		VerifierSessionID:      txn.SessionID,
		VerifierPresentationID: txn.PresentationID,
		// Only the digest is stored. The plaintext nonce went to the Scan
		// Verifier and reaches nothing else, no log line included.
		NonceHash: aocrypto.Digest(nonce),
		State:     StatePending,
		ExpiresAt: now.Add(TransactionTTL),
	}
	if err := s.deps.Insert(ctx, row); err != nil {
		s.log.Error("write qr login transaction",
			logger.String("tenant_id", tenantID),
			logger.String("session_id", opened.ID),
			logger.Err(err))
		return Started{}, err
	}

	s.log.Info("started qr login",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", opened.ID), logger.RequestID(ctx))
	return Started{
		SessionID:    opened.ID,
		SessionToken: opened.Token,
		QRCode:       txn.QRCode,
		ExpiresIn:    int(TransactionTTL.Seconds()),
	}, nil
}

// Callback takes the push of the Scan Verifier. It claims the transaction,
// checks the nonce, resolves the presented name to a person, and records the
// outcome on the transaction row. It never touches the login session.
//
// Every outcome past a parseable body is a nil error. That includes an unknown
// reference, an already claimed one, which is also what a retry of the push looks
// like, and a push that resolved to nobody. The endpoint must never say which
// transactions exist.
func (s *Service) Callback(ctx context.Context, req CallbackRequest, meta Meta) error {
	s.log.Debug("qr login callback", logger.RequestID(ctx))

	ref, err := parseCallback(req)
	if err != nil {
		s.log.Warn("qr login callback: unusable body",
			logger.Int("body_bytes", len(req.Raw)),
			logger.Any("body_keys", callbackKeys(req.Raw)),
			logger.Err(err))
		return err
	}
	// The key names, never the values. The body is a third party's and carries an
	// asserted username, which is personal data. The key set is what a contract
	// change is diagnosed from.
	s.log.Info("qr login callback: received",
		logger.Int("body_bytes", len(req.Raw)),
		logger.Any("body_keys", callbackKeys(req.Raw)), logger.RequestID(ctx))

	row, err := s.deps.ByVerifierRef(ctx, ref.SessionID, ref.PresentationID)
	if errors.Is(err, ErrNotFound) {
		s.log.Info("qr login callback: no transaction matches the reference", logger.RequestID(ctx))
		return nil
	}
	if err != nil {
		s.log.Error("read qr login transaction", logger.Err(err))
		return err
	}

	// The guarded claim. A second push, a retry, and a concurrent one all stop
	// here, so one transaction resolves exactly once.
	err = s.deps.Consume(ctx, row.TenantID, row.ID, s.now().UTC())
	if errors.Is(err, ErrNotFound) {
		s.log.Info("qr login callback: the transaction is not claimable",
			logger.String("tenant_id", row.TenantID), logger.RequestID(ctx))
		return nil
	}
	if err != nil {
		s.log.Error("claim qr login transaction",
			logger.String("tenant_id", row.TenantID), logger.Err(err))
		return err
	}

	userID, reason := s.resolve(ctx, row, ref)
	if reason != nil {
		s.fail(ctx, row, reason, meta)
		return nil
	}

	if err := s.deps.SetResult(ctx, row.TenantID, row.ID, StateVerified, userID); err != nil {
		s.log.Error("record qr login result",
			logger.String("tenant_id", row.TenantID), logger.Err(err))
		return err
	}

	s.log.Info("qr login callback: presentation accepted",
		logger.String("tenant_id", row.TenantID),
		logger.String("user_id", userID), logger.RequestID(ctx))
	return nil
}

// resolve checks what the push asserted against the claimed transaction and
// turns the presented name into a person of that tenant.
//
// Its error is a reason for the log and for the failed state. A caller of the
// endpoint never sees it.
func (s *Service) resolve(ctx context.Context, row Transaction, ref callbackRef) (string, error) {
	// The Scan Verifier answers a refusal inside a successful push, under a result
	// code of its own. A push it did not accept must never sign anybody in. A push
	// that carries no code at all is judged on the checks below, because an older
	// shape of the vendor sends none.
	if ref.StateWord != "" && ref.StateWord != stateWordAccepted {
		return "", fmt.Errorf("the verifier refused the presentation (state word %s)", ref.StateWord)
	}
	// The nonce binds the presentation to this transaction. A push that carries
	// one must carry the one this transaction was started with, and a push that
	// carries none is bound by the presentation identifier instead, which the
	// Scan Verifier mints and never sends to the browser.
	if ref.Nonce != "" && aocrypto.Digest(ref.Nonce) != row.NonceHash {
		return "", errors.New("the pushed nonce does not match the transaction")
	}
	if ref.Username == "" {
		return "", errors.New("the push carries no presented name")
	}

	userID, err := s.deps.User(ctx, row.TenantID, ref.Username)
	if errors.Is(err, user.ErrNotFound) {
		// Refuse. There is no provisioning here: a scan that created an account
		// would be a registration nobody approved.
		return "", errors.New("the presented name matches no person of this tenant")
	}
	if err != nil {
		return "", fmt.Errorf("resolve the presented name: %w", err)
	}
	return userID, nil
}

// fail marks a claimed transaction failed and records the refused sign-in.
//
// A failure to write either one is logged and not returned. The caller is the
// Scan Verifier, and there is nothing useful it could do with the error.
func (s *Service) fail(ctx context.Context, row Transaction, reason error, meta Meta) {
	s.log.Warn("qr login callback: the presentation was refused",
		logger.String("tenant_id", row.TenantID), logger.Err(reason))

	if err := s.deps.SetResult(ctx, row.TenantID, row.ID, StateFailed, ""); err != nil {
		s.log.Error("record qr login result",
			logger.String("tenant_id", row.TenantID), logger.Err(err))
	}
	err := s.deps.Audit.Record(ctx, audit.Entry{
		TenantID:   row.TenantID,
		Action:     audit.ActionLoginFailed,
		EntityType: audit.EntitySession,
		EntityID:   row.LoginSessionID,
		IP:         meta.IP,
		UserAgent:  meta.UserAgent,
		Metadata:   map[string]any{"factor": session.FactorScan},
	})
	if err != nil {
		s.log.Error("record refused qr login",
			logger.String("tenant_id", row.TenantID), logger.Err(err))
	}
}

// Polled is the answer the browser gets. Status is pending, authenticated, or
// expired, and nothing else.
type Polled struct {
	Status string
	// SessionToken is the rotated token. It is present only on the poll that
	// turns the login session authenticated. A later poll answers it empty: the
	// browser already holds the live token, and rotating again would kill it.
	SessionToken string
	UserID       string
}

// Poll reports the state of the transaction of the caller's login session and,
// on the step to verified, binds the person and records the factor.
//
// The poll is the only party holding a valid login session token, so the binding
// and the factor happen here and not in the callback.
func (s *Service) Poll(ctx context.Context, tenantID, token string, meta Meta) (Polled, error) {
	s.log.Debug("poll qr login", logger.String("tenant_id", tenantID), logger.RequestID(ctx))

	live, err := s.deps.FindSession(ctx, tenantID, token)
	if err != nil {
		return Polled{}, err
	}
	// Already completed. Answer without touching the session again.
	//
	// ponytail: the check is a read, so two polls that overlap can both rotate the
	// token and the browser can be handed a dead one. The browser polls in series,
	// so this needs two tabs on one login session. Make the completion a guarded
	// update the day that happens.
	if _, done := live.Factors[session.FactorScan]; done {
		return Polled{Status: StatusAuthenticated, UserID: live.UserID}, nil
	}

	row, err := s.deps.ByLoginSess(ctx, tenantID, live.ID)
	if errors.Is(err, ErrNotFound) {
		return Polled{Status: StatusExpired}, nil
	}
	if err != nil {
		s.log.Error("read qr login transaction",
			logger.String("tenant_id", tenantID), logger.Err(err))
		return Polled{}, err
	}

	switch row.State {
	case StateVerified:
		return s.complete(ctx, tenantID, token, row, meta)
	case StatePending:
		if row.ExpiresAt.After(s.now().UTC()) {
			return Polled{Status: StatusPending}, nil
		}
		return Polled{Status: StatusExpired}, nil
	default:
		// Failed. It answers expired: the remedy is the same, scan again, and a
		// separate status would say which of the two happened.
		return Polled{Status: StatusExpired}, nil
	}
}

// complete binds the resolved person to the polling login session and records
// the scan factor, which rotates the token. The new token is handed out once.
func (s *Service) complete(
	ctx context.Context, tenantID, token string, row Transaction, meta Meta,
) (Polled, error) {
	if row.UserID == "" {
		s.log.Error("qr login poll: a verified transaction names no person",
			logger.String("tenant_id", tenantID))
		return Polled{Status: StatusExpired}, nil
	}

	opened, err := s.deps.CompleteSession(ctx, tenantID, token, row.UserID, session.FactorScan)
	if errors.Is(err, session.ErrSubjectBound) {
		// The login session already names somebody else. Refuse: this is the
		// shape of an attempt to point a live session at another person.
		s.log.Error("qr login poll: the login session already names another person",
			logger.String("tenant_id", tenantID))
		return Polled{Status: StatusExpired}, nil
	}
	if err != nil {
		return Polled{}, err
	}

	s.log.Info("qr login: the login session is authenticated by a presented credential",
		logger.String("tenant_id", tenantID),
		logger.String("session_id", opened.ID),
		logger.String("user_id", row.UserID), logger.RequestID(ctx))
	return Polled{Status: StatusAuthenticated, SessionToken: opened.Token, UserID: row.UserID}, nil
}

// callbackRef is what one push body names: which transaction, which nonce, and
// who the Scan Verifier says presented.
type callbackRef struct {
	SessionID      string
	PresentationID string
	Nonce          string
	Username       string
	// StateWord is the result code of the Scan Verifier, normalised. "0" is an
	// accepted presentation and every other value is a refusal. It is empty when
	// the push carries none.
	StateWord string
}

// parseCallback is the one function the contract of the push is confined to. When
// the shape of the vendor changes, CallbackRequest, this function, and their
// tests are what change.
//
// The body must name the transaction, by presentationId or by session_id, which
// the wallet also echoes as state. Either can be wrapped in a data envelope, the
// way the other answers of the Scan Verifier are.
//
// What carries the whole flow is two things, and both must hold. The presentation
// identifier is a value the Scan Verifier mints and never sends to the browser,
// and it lives for TransactionTTL. The endpoint sits behind its own credential,
// which is what stops anybody who can reach the address from asserting a scan.
func parseCallback(req CallbackRequest) (callbackRef, error) {
	data := req.Data
	if data == nil {
		data = &CallbackFields{}
	}
	ref := callbackRef{
		SessionID: firstSet(req.SessionID, req.SessionIDCamel, req.State,
			data.SessionID, data.SessionIDCamel, data.State),
		PresentationID: firstSet(req.PresentationID, req.PresentationIDCamel,
			data.PresentationID, data.PresentationIDCamel),
		Nonce:     firstSet(req.CallbackFields.nonce(), data.nonce()),
		Username:  firstSet(req.username(), data.username()),
		StateWord: firstSet(req.CallbackFields.stateWord(), data.stateWord()),
	}
	if ref.SessionID == "" && ref.PresentationID == "" {
		return callbackRef{}, fmt.Errorf("%w: no session_id and no presentation_id", ErrUnusableCallback)
	}
	return ref, nil
}

// maxLoggedKeys caps the key list one unusable body writes into the log. The body
// belongs to a third party, and without a ceiling the length of the line is its
// decision.
const maxLoggedKeys = 50

// callbackKeys reports the key names one push body carries, at the top level and
// one level inside each object. A body that names no transaction still names its
// own shape in the log, so the contract is fixed from evidence.
//
// Only the names are reported, never the values. The body is untrusted and
// carries an asserted username, and the names answer the whole question.
func callbackKeys(body []byte) []string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return nil
	}
	keys := make([]string, 0, len(top))
	for name, value := range top {
		keys = append(keys, name)
		var child map[string]json.RawMessage
		if err := json.Unmarshal(value, &child); err == nil {
			for inner := range child {
				keys = append(keys, name+"."+inner)
			}
		}
	}
	sort.Strings(keys)
	if len(keys) > maxLoggedKeys {
		keys = keys[:maxLoggedKeys]
	}
	return keys
}

// firstSet returns the first value that is not empty.
func firstSet(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
