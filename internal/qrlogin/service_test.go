package qrlogin

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest/observer"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/di"
	aocrypto "alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/session"
	"alphaomega/identitygateway/internal/user"
)

const (
	testTenantID = "tenant-1"
	testUserID   = "user-1"
	testUsername = "person@example.com"
)

// testNow is the moment every test runs at. A fixed clock keeps the expiry
// arithmetic the same on every run.
var testNow = time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

// store is the database seam of the service, held in memory. It records what the
// service wrote, so a test reads the rows the database would have held.
type store struct {
	rows []Transaction

	// nonces is every nonce the service sent to the Scan Verifier, in order.
	nonces []string
	// qrCode is what the Scan Verifier answers with.
	qrCode json.RawMessage
	// startErr fails the call to the Scan Verifier.
	startErr error

	// sessions holds each opened login session by the token that credentials it.
	sessions map[string]session.LoginSession
	// completed counts the login sessions the poll completed.
	completed int

	// users maps a username to a person of the tenant.
	users map[string]string

	events []audit.Event
}

func newStore() *store {
	return &store{
		qrCode:   json.RawMessage(`{"url":"openid4vp://authorize?x=1","fallback_url":"https://verifier.example/app"}`),
		sessions: map[string]session.LoginSession{},
		users:    map[string]string{testUsername: testUserID},
	}
}

func (s *store) Start(_ context.Context, nonce string) (di.Transaction, error) {
	s.nonces = append(s.nonces, nonce)
	if s.startErr != nil {
		return di.Transaction{}, s.startErr
	}
	return di.Transaction{
		PresentationID: "presentation-1",
		SessionID:      "verifier-session-1",
		QRCode:         s.qrCode,
	}, nil
}

func (s *store) Insert(_ context.Context, row Transaction) error {
	for _, held := range s.rows {
		// The unique keys are global. A duplicate identifier of the verifier is
		// what refuses a replay.
		if held.VerifierSessionID == row.VerifierSessionID ||
			held.VerifierPresentationID == row.VerifierPresentationID {
			return errors.New("duplicate verifier identifier")
		}
	}
	s.rows = append(s.rows, row)
	return nil
}

func (s *store) ByVerifierRef(_ context.Context, sessionID, presentationID string) (Transaction, error) {
	if sessionID == "" && presentationID == "" {
		return Transaction{}, ErrNotFound
	}
	for _, row := range s.rows {
		if (sessionID != "" && row.VerifierSessionID == sessionID) ||
			(presentationID != "" && row.VerifierPresentationID == presentationID) {
			return row, nil
		}
	}
	return Transaction{}, ErrNotFound
}

func (s *store) ByLoginSess(_ context.Context, tenantID, loginSessionID string) (Transaction, error) {
	for i := len(s.rows) - 1; i >= 0; i-- {
		if s.rows[i].TenantID == tenantID && s.rows[i].LoginSessionID == loginSessionID {
			return s.rows[i], nil
		}
	}
	return Transaction{}, ErrNotFound
}

// Consume is the guarded claim. It matches the one guarded update the repository
// runs: pending, unconsumed, and unexpired.
func (s *store) Consume(_ context.Context, tenantID, id string, now time.Time) error {
	for i, row := range s.rows {
		if row.TenantID != tenantID || row.ID != id {
			continue
		}
		if !row.ConsumedAt.IsZero() || row.State != StatePending || !row.ExpiresAt.After(now) {
			return ErrNotFound
		}
		s.rows[i].ConsumedAt = now
		return nil
	}
	return ErrNotFound
}

func (s *store) SetResult(_ context.Context, tenantID, id string, state int, userID string) error {
	for i, row := range s.rows {
		if row.TenantID == tenantID && row.ID == id {
			s.rows[i].State = state
			if userID != "" {
				s.rows[i].UserID = userID
			}
			return nil
		}
	}
	return ErrNotFound
}

func (s *store) OpenSession(_ context.Context, tenantID, ip, userAgent string) (session.Opened, error) {
	id := "login-session-" + string(rune('a'+len(s.sessions)))
	token := "token-" + id
	s.sessions[token] = session.LoginSession{
		ID: id, TenantID: tenantID, IP: ip, UserAgent: userAgent,
	}
	return session.Opened{ID: id, Token: token}, nil
}

func (s *store) FindSession(_ context.Context, tenantID, token string) (session.LoginSession, error) {
	live, ok := s.sessions[token]
	if !ok || live.TenantID != tenantID {
		return session.LoginSession{}, session.ErrLoginSessionNotFound
	}
	return live, nil
}

// CompleteSession binds the person and records the factor, and it rotates the
// token exactly as the session domain does.
func (s *store) CompleteSession(
	_ context.Context, tenantID, token, userID, factor string,
) (session.Opened, error) {
	live, ok := s.sessions[token]
	if !ok || live.TenantID != tenantID {
		return session.Opened{}, session.ErrLoginSessionNotFound
	}
	if live.UserID != "" && live.UserID != userID {
		return session.Opened{}, session.ErrSubjectBound
	}
	delete(s.sessions, token)

	live.UserID = userID
	if live.Factors == nil {
		live.Factors = map[string]time.Time{}
	}
	live.Factors[factor] = testNow

	rotated := token + "-rotated"
	s.sessions[rotated] = live
	s.completed++
	return session.Opened{ID: live.ID, Token: rotated}, nil
}

func (s *store) User(_ context.Context, _, username string) (string, error) {
	id, ok := s.users[username]
	if !ok {
		return "", user.ErrNotFound
	}
	return id, nil
}

func (s *store) Write(_ context.Context, event audit.Event) error {
	s.events = append(s.events, event)
	return nil
}

// actions names every action the store recorded, in order.
func (s *store) actions() []string {
	names := make([]string, 0, len(s.events))
	for _, event := range s.events {
		names = append(names, event.Action)
	}
	return names
}

func testService(t *testing.T) (*Service, *store) {
	t.Helper()

	svc, st, _ := testServiceWithLogs(t)
	return svc, st
}

func testServiceWithLogs(t *testing.T) (*Service, *store, *observer.ObservedLogs) {
	t.Helper()

	log, logs := logger.NewObserved()
	st := newStore()
	svc := NewService(Deps{
		Start:           st.Start,
		Insert:          st.Insert,
		ByVerifierRef:   st.ByVerifierRef,
		ByLoginSess:     st.ByLoginSess,
		Consume:         st.Consume,
		SetResult:       st.SetResult,
		OpenSession:     st.OpenSession,
		FindSession:     st.FindSession,
		CompleteSession: st.CompleteSession,
		User:            st.User,
		Audit:           audit.NewRecorder(st.Write, log),
		Log:             log,
		Now:             func() time.Time { return testNow },
	})
	return svc, st, logs
}

// pushBody renders one push of the Scan Verifier, as the handler hands it to the
// service: decoded into the request, with the bytes that arrived kept beside it.
func pushBody(t *testing.T, fields map[string]any) CallbackRequest {
	t.Helper()

	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("render the push body: %v", err)
	}
	return pushRaw(t, string(body))
}

// pushRaw decodes one push body written as it arrives on the wire.
func pushRaw(t *testing.T, body string) CallbackRequest {
	t.Helper()

	var req CallbackRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode the push body: %v", err)
	}
	req.Raw = []byte(body)
	return req
}

// verifiedPush is the push a successful scan sends.
func verifiedPush(t *testing.T, nonce string) CallbackRequest {
	t.Helper()

	fields := map[string]any{
		"stateWord":      "0",
		"presentationId": "presentation-1",
		"message":        "success",
		"DecodedVpToken": map[string]any{"Username": testUsername},
	}
	if nonce != "" {
		fields["nonce"] = nonce
	}
	return pushBody(t, fields)
}

// TestStart covers the step that puts a code on screen.
func TestStart(t *testing.T) {
	svc, st, logs := testServiceWithLogs(t)

	started, err := svc.Start(context.Background(), testTenantID, Meta{IP: "203.0.113.7", UserAgent: "a-browser"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// The code object of the Scan Verifier reaches the browser byte for byte. A
	// re-encode drops the fallback link the sign-in page offers as "no app?".
	if string(started.QRCode) != string(st.qrCode) {
		t.Errorf("QRCode = %s, want %s", started.QRCode, st.qrCode)
	}
	if started.SessionID == "" || started.SessionToken == "" {
		t.Errorf("start gave %+v, want a session id and a token", started)
	}
	if started.ExpiresIn != int(TransactionTTL.Seconds()) {
		t.Errorf("ExpiresIn = %d, want %d", started.ExpiresIn, int(TransactionTTL.Seconds()))
	}

	if len(st.rows) != 1 {
		t.Fatalf("the store holds %d transactions, want 1", len(st.rows))
	}
	row := st.rows[0]
	if row.State != StatePending || row.UserID != "" {
		t.Errorf("the written transaction is %+v, want pending and naming nobody", row)
	}
	// The window is sized above the window of the Scan Verifier.
	if want := testNow.Add(TransactionTTL); !row.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", row.ExpiresAt, want)
	}
	// The nonce reaches the Scan Verifier and nothing else. Only the digest is
	// stored.
	if len(st.nonces) != 1 || st.nonces[0] == "" {
		t.Fatalf("the nonces sent are %v, want exactly one that is not empty", st.nonces)
	}
	if row.NonceHash != aocrypto.Digest(st.nonces[0]) {
		t.Errorf("NonceHash = %q, want the digest of the nonce that was sent", row.NonceHash)
	}
	if row.NonceHash == st.nonces[0] {
		t.Error("the plaintext nonce was stored")
	}
	// The nonce reaches no log line, at any level.
	for _, entry := range logs.All() {
		if strings.Contains(entry.Message, st.nonces[0]) {
			t.Errorf("the nonce reached a log line: %s", entry.Message)
		}
		for _, field := range entry.Context {
			if strings.Contains(field.String, st.nonces[0]) {
				t.Errorf("the nonce reached a log field: %s", field.String)
			}
		}
	}

	// The presentation identifier of the Scan Verifier stays on the server.
	answer, err := json.Marshal(StartResponse{
		SessionID:    started.SessionID,
		SessionToken: started.SessionToken,
		QRCode:       started.QRCode,
		ExpiresIn:    started.ExpiresIn,
	})
	if err != nil {
		t.Fatalf("render the answer: %v", err)
	}
	if strings.Contains(string(answer), "presentation-1") {
		t.Errorf("the answer carries the presentation identifier: %s", answer)
	}

	// The login session names nobody yet.
	live, err := st.FindSession(context.Background(), testTenantID, started.SessionToken)
	if err != nil {
		t.Fatalf("read the opened login session: %v", err)
	}
	if live.UserID != "" {
		t.Errorf("the opened login session names %q, want nobody", live.UserID)
	}
}

// TestStartMintsAFreshNonce covers the replay binding. One nonce across two
// transactions would let a presentation captured from one replay into the other.
func TestStartMintsAFreshNonce(t *testing.T) {
	svc, st := testService(t)

	for range 2 {
		st.rows = nil // the unique keys of the store hold one transaction at a time
		if _, err := svc.Start(context.Background(), testTenantID, Meta{}); err != nil {
			t.Fatalf("start: %v", err)
		}
	}

	if len(st.nonces) != 2 {
		t.Fatalf("the nonces sent are %v, want two", st.nonces)
	}
	if st.nonces[0] == st.nonces[1] {
		t.Error("the same nonce was used twice")
	}
}

// TestStartLeavesNothingBehindOnAFailedVerifier covers the order of the two
// writes. A transaction that could not be opened writes no row and opens no
// login session.
func TestStartLeavesNothingBehindOnAFailedVerifier(t *testing.T) {
	svc, st := testService(t)
	st.startErr = errors.New("the verifier is down")

	if _, err := svc.Start(context.Background(), testTenantID, Meta{}); err == nil {
		t.Fatal("start gave no error, want the failure of the verifier")
	}
	if len(st.rows) != 0 || len(st.sessions) != 0 {
		t.Errorf("start left %d transactions and %d login sessions behind, want none",
			len(st.rows), len(st.sessions))
	}
}

// started runs the start step and returns the token of the login session it
// opened.
func started(t *testing.T, svc *Service) string {
	t.Helper()

	out, err := svc.Start(context.Background(), testTenantID, Meta{IP: "203.0.113.7", UserAgent: "a-browser"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return out.SessionToken
}

// TestCallbackAndPoll covers the whole flow and the division of labour in it.
// The callback records the result and never touches the login session. The poll
// binds the person and rotates the token.
func TestCallbackAndPoll(t *testing.T) {
	svc, st := testService(t)
	token := started(t, svc)

	// Nothing has been presented yet.
	polled, err := svc.Poll(context.Background(), testTenantID, token, Meta{})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if polled.Status != StatusPending {
		t.Errorf("status = %q, want %q", polled.Status, StatusPending)
	}

	if err := svc.Callback(context.Background(), verifiedPush(t, st.nonces[0]), Meta{}); err != nil {
		t.Fatalf("callback: %v", err)
	}

	// The callback wrote the result and left the login session alone. The token
	// the browser is polling with still works.
	if st.rows[0].State != StateVerified || st.rows[0].UserID != testUserID {
		t.Errorf("the transaction is %+v, want verified and naming %s", st.rows[0], testUserID)
	}
	if st.completed != 0 {
		t.Error("the callback completed the login session, which kills the token the browser polls with")
	}

	polled, err = svc.Poll(context.Background(), testTenantID, token, Meta{})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if polled.Status != StatusAuthenticated || polled.UserID != testUserID {
		t.Fatalf("poll gave %+v, want authenticated for %s", polled, testUserID)
	}
	// The token rotated, and the previous one is dead.
	if polled.SessionToken == "" || polled.SessionToken == token {
		t.Errorf("the poll gave token %q, want a rotated one", polled.SessionToken)
	}
	if _, err := st.FindSession(context.Background(), testTenantID, token); err == nil {
		t.Error("the previous login session token still works")
	}

	// A second poll answers authenticated again and rotates nothing. The browser
	// already holds the live token.
	again, err := svc.Poll(context.Background(), testTenantID, polled.SessionToken, Meta{})
	if err != nil {
		t.Fatalf("poll again: %v", err)
	}
	if again.Status != StatusAuthenticated || again.SessionToken != "" {
		t.Errorf("the second poll gave %+v, want authenticated with no token", again)
	}
	if st.completed != 1 {
		t.Errorf("the login session was completed %d times, want once", st.completed)
	}
}

// TestCallbackClaimsOnce covers the guarded claim. A second push, which is also
// what a retry looks like, changes nothing.
func TestCallbackClaimsOnce(t *testing.T) {
	svc, st := testService(t)
	started(t, svc)

	push := verifiedPush(t, st.nonces[0])
	if err := svc.Callback(context.Background(), push, Meta{}); err != nil {
		t.Fatalf("the first callback: %v", err)
	}
	before := st.rows[0]

	// A replay of the same push. It is refused, and it answers success, so the
	// endpoint never says which transactions exist.
	if err := svc.Callback(context.Background(), push, Meta{}); err != nil {
		t.Fatalf("the second callback: %v", err)
	}
	if st.rows[0] != before {
		t.Errorf("the replayed push changed the transaction to %+v, want %+v", st.rows[0], before)
	}
}

// TestCallbackFailsTheTransaction covers every push the service refuses. Each one
// answers success and leaves the transaction failed, and the poll then answers
// expired.
func TestCallbackFailsTheTransaction(t *testing.T) {
	tests := []struct {
		name string
		push func(t *testing.T, st *store) CallbackRequest
	}{
		{
			name: "a nonce that does not match",
			push: func(t *testing.T, _ *store) CallbackRequest {
				return verifiedPush(t, "a-nonce-of-another-transaction")
			},
		},
		{
			name: "a presented name that resolves to no person",
			push: func(t *testing.T, st *store) CallbackRequest {
				return pushBody(t, map[string]any{
					"presentationId": "presentation-1",
					"nonce":          st.nonces[0],
					"DecodedVpToken": map[string]any{"Username": "nobody@example.com"},
				})
			},
		},
		{
			// The Scan Verifier reports a refusal inside a successful push, under
			// a result code of its own. A push it did not accept signs nobody in.
			name: "a result code the verifier refused with",
			push: func(t *testing.T, st *store) CallbackRequest {
				return pushBody(t, map[string]any{
					"stateWord":      "1",
					"message":        "VERIFICATION_FAILED",
					"presentationId": "presentation-1",
					"nonce":          st.nonces[0],
					"DecodedVpToken": map[string]any{"Username": testUsername},
				})
			},
		},
		{
			name: "a result code the verifier refused with, as a number",
			push: func(t *testing.T, st *store) CallbackRequest {
				return pushBody(t, map[string]any{
					"stateWord":      2,
					"presentationId": "presentation-1",
					"nonce":          st.nonces[0],
					"DecodedVpToken": map[string]any{"Username": testUsername},
				})
			},
		},
		{
			name: "a push that names nobody at all",
			push: func(t *testing.T, st *store) CallbackRequest {
				return pushBody(t, map[string]any{
					"presentationId": "presentation-1",
					"nonce":          st.nonces[0],
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, st := testService(t)
			token := started(t, svc)

			if err := svc.Callback(context.Background(), tt.push(t, st), Meta{}); err != nil {
				t.Fatalf("callback: %v", err)
			}

			if st.rows[0].State != StateFailed {
				t.Errorf("the transaction is in state %d, want %d", st.rows[0].State, StateFailed)
			}
			// No person is created, and none is bound.
			if st.rows[0].UserID != "" {
				t.Errorf("the failed transaction names %q, want nobody", st.rows[0].UserID)
			}
			if st.completed != 0 {
				t.Error("a refused push completed a login session")
			}
			// The refusal is recorded once.
			if got := st.actions(); len(got) != 1 || got[0] != string(audit.ActionLoginFailed) {
				t.Errorf("the trail holds %v, want one %s", got, audit.ActionLoginFailed)
			}

			// A failure answers expired. The remedy is the same, scan again, and a
			// separate status would say which of the two happened.
			polled, err := svc.Poll(context.Background(), testTenantID, token, Meta{})
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if polled.Status != StatusExpired {
				t.Errorf("status = %q, want %q", polled.Status, StatusExpired)
			}
		})
	}
}

// TestCallbackTolerates covers every push the service answers success to without
// changing anything. The endpoint must never say which transactions exist.
func TestCallbackTolerates(t *testing.T) {
	tests := []struct {
		name string
		push map[string]any
	}{
		{
			name: "a reference that matches no transaction",
			push: map[string]any{"presentationId": "presentation-of-nothing"},
		},
		{
			name: "a session id that matches no transaction",
			push: map[string]any{"session_id": "verifier-session-of-nothing"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, st := testService(t)
			started(t, svc)
			before := st.rows[0]

			if err := svc.Callback(context.Background(), pushBody(t, tt.push), Meta{}); err != nil {
				t.Fatalf("callback: %v", err)
			}
			if st.rows[0] != before {
				t.Errorf("the transaction changed to %+v, want %+v", st.rows[0], before)
			}
		})
	}
}

// TestCallbackRefusesAnUnusableBody covers the one failure a caller can observe.
//
// A body that is not JSON never reaches here. The bind refuses it, and
// TestCallbackAnswersOneRefusal covers that seam.
func TestCallbackRefusesAnUnusableBody(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "a body that names no transaction", body: `{"message":"success"}`},
		{
			// stateWord is a result code and not a reference. Reading it as one
			// would look up a transaction named "0".
			name: "a body that carries only a result code",
			body: `{"stateWord":"0","message":"success"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := testService(t)
			if err := svc.Callback(context.Background(), pushRaw(t, tt.body), Meta{}); !errors.Is(err, ErrUnusableCallback) {
				t.Errorf("callback gave %v, want %v", err, ErrUnusableCallback)
			}
		})
	}
}

// TestCallbackReadsTheSpellingsOfTheVendor covers the shapes the push arrives in.
// The start operation answers in snake case, so the vendor spells both, and the
// wallet echoes the session identifier as state.
func TestCallbackReadsTheSpellingsOfTheVendor(t *testing.T) {
	tests := []struct {
		name string
		push func(nonce string) map[string]any
	}{
		{
			name: "snake case at the top level",
			push: func(nonce string) map[string]any {
				return map[string]any{
					"presentation_id": "presentation-1",
					"nonce":           nonce,
					"DecodedVpToken":  map[string]any{"Username": testUsername},
				}
			},
		},
		{
			name: "the session id the wallet echoes as state",
			push: func(nonce string) map[string]any {
				return map[string]any{
					"state":          "verifier-session-1",
					"nonce":          nonce,
					"DecodedVpToken": map[string]any{"Username": testUsername},
				}
			},
		},
		{
			name: "a data envelope",
			push: func(nonce string) map[string]any {
				return map[string]any{"data": map[string]any{
					"presentationId": "presentation-1",
					"nonce":          nonce,
					"DecodedVpToken": map[string]any{"Username": testUsername},
				}}
			},
		},
		{
			name: "the lower-case spelling of the decoded token",
			push: func(nonce string) map[string]any {
				return map[string]any{
					"presentationId": "presentation-1",
					"nonce":          nonce,
					"decodedVpToken": map[string]any{"username": testUsername},
				}
			},
		},
		{
			// The confirmed body of the vendor carries no nonce. The presentation
			// identifier binds the push instead: the Scan Verifier mints it and
			// never sends it to the browser.
			name: "a push that carries no nonce",
			push: func(string) map[string]any {
				return map[string]any{
					"stateWord":      "0",
					"presentationId": "presentation-1",
					"DecodedVpToken": map[string]any{"Username": testUsername},
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, st := testService(t)
			started(t, svc)

			if err := svc.Callback(context.Background(), pushBody(t, tt.push(st.nonces[0])), Meta{}); err != nil {
				t.Fatalf("callback: %v", err)
			}
			if st.rows[0].State != StateVerified || st.rows[0].UserID != testUserID {
				t.Errorf("the transaction is %+v, want verified and naming %s", st.rows[0], testUserID)
			}
		})
	}
}

// TestPollAnswersExpired covers every answer that is not pending and not
// authenticated. An expired transaction, a consumed one, and an unknown one all
// read the same.
func TestPollAnswersExpired(t *testing.T) {
	tests := []struct {
		name   string
		break_ func(st *store)
	}{
		{
			name:   "the transaction expired",
			break_: func(st *store) { st.rows[0].ExpiresAt = testNow.Add(-time.Second) },
		},
		{
			name:   "the transaction failed",
			break_: func(st *store) { st.rows[0].State = StateFailed },
		},
		{
			name:   "no transaction is bound to the login session",
			break_: func(st *store) { st.rows = nil },
		},
		{
			// A verified transaction that names nobody cannot sign anybody in.
			name:   "a verified transaction names no person",
			break_: func(st *store) { st.rows[0].State = StateVerified },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, st := testService(t)
			token := started(t, svc)
			tt.break_(st)

			polled, err := svc.Poll(context.Background(), testTenantID, token, Meta{})
			if err != nil {
				t.Fatalf("poll: %v", err)
			}
			if polled.Status != StatusExpired {
				t.Errorf("status = %q, want %q", polled.Status, StatusExpired)
			}
			if st.completed != 0 {
				t.Error("the poll completed a login session it must not have")
			}
		})
	}
}

// TestPollRefusesADeadToken covers the credential of the poll. A token that names
// no live login session never reaches the transaction.
func TestPollRefusesADeadToken(t *testing.T) {
	svc, _ := testService(t)
	started(t, svc)

	_, err := svc.Poll(context.Background(), testTenantID, "a-token-of-nothing", Meta{})
	if !errors.Is(err, session.ErrLoginSessionNotFound) {
		t.Errorf("poll gave %v, want %v", err, session.ErrLoginSessionNotFound)
	}
}

// TestPollRefusesASessionOfAnotherPerson covers the shape of an attempt to point
// a live login session at a second person.
func TestPollRefusesASessionOfAnotherPerson(t *testing.T) {
	svc, st := testService(t)
	token := started(t, svc)

	if err := svc.Callback(context.Background(), verifiedPush(t, st.nonces[0]), Meta{}); err != nil {
		t.Fatalf("callback: %v", err)
	}
	// The login session already names somebody else.
	live := st.sessions[token]
	live.UserID = "user-2"
	st.sessions[token] = live

	polled, err := svc.Poll(context.Background(), testTenantID, token, Meta{})
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if polled.Status != StatusExpired {
		t.Errorf("status = %q, want %q", polled.Status, StatusExpired)
	}
	if st.completed != 0 {
		t.Error("the poll completed a login session that names another person")
	}
}

// TestCallbackKeysReportNoValues covers the log line one push leaves behind. The
// body is a third party's and carries an asserted name, which is personal data.
func TestCallbackKeysReportNoValues(t *testing.T) {
	keys := callbackKeys([]byte(`{"presentationId":"presentation-1","DecodedVpToken":{"Username":"person@example.com"}}`))

	want := []string{"DecodedVpToken", "DecodedVpToken.Username", "presentationId"}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	for i, key := range want {
		if keys[i] != key {
			t.Fatalf("keys = %v, want %v", keys, want)
		}
	}
}
