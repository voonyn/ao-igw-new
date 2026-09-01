package identityprovider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// ErrTooManyTests reports a tenant that spent its whole connection test budget.
// The console asks the administrator to wait, and the directory is not dialled.
var ErrTooManyTests = errors.New("too many connection tests")

// ErrTestUnavailable reports a connection test budget nobody could read. Redis
// holds the whole counter, so a test that ran without it would leave an
// outbound call into a customer network unmetered for as long as Redis is down.
//
// It is not ErrTooManyTests. Both refuse, and the two ask the administrator for
// different things: one to wait, and one to call an operator.
var ErrTestUnavailable = errors.New("the connection test budget is unavailable")

// The value the stage metadata key carries when every stage passed. The audit
// trail names the outcome of each test, so a reader greps one key instead of
// reading the absence of one.
const stageNone = "none"

// testLimit and testWindow cap how many connection tests one tenant runs.
//
// The test is an outbound call into a customer network that any authenticated
// console user drives, so it is metered whoever drives it. The budget is keyed
// by tenant and not by person, because the directory is the thing being
// protected and every administrator of the tenant dials the same one.
//
// The number is generous, because an administrator who is fixing a bind DN runs
// the test after every edit. It still bounds the work.
//
// ponytail: two constants. Move them into a tenant policy row when a tenant asks
// for its own numbers.
const (
	testLimit  = 30
	testWindow = 15 * time.Minute
)

// testKey names the connection test budget of one tenant.
func testKey(tenantID string) string {
	return fmt.Sprintf("idp_tests:%s", tenantID)
}

// testSizeLimit caps the entries one test search reads. A base that holds a
// whole company must never land a whole company in memory, and the count only
// has to tell the administrator that the base and the object classes are right.
const testSizeLimit = 100

// TestResult is what one connection test answers.
//
// Stage names the step that failed: the dial, the TLS handshake, the service
// bind, or the search. It is empty when every stage passed.
//
// Matched is how many entries the search matched, capped at testSizeLimit. It is
// read only when OK is true.
//
// Detail is the message of the step that failed, so an administrator reads which
// value of the form is wrong. It carries no credential: the bind password never
// reaches the wire in a form a directory echoes, and no stage of this test takes
// a password of a person.
type TestResult struct {
	OK      bool   `json:"ok"`
	Stage   string `json:"stage"`
	Matched int    `json:"matched"`
	Detail  string `json:"detail"`
}

// failed is one stage that did not pass.
func failed(stage, detail string) TestResult {
	return TestResult{Stage: stage, Detail: detail}
}

// Test dials one directory, binds with the credential of the provider, and runs
// one search. It answers which stage failed, so an administrator finds a wrong
// bind DN before an employee finds it for them.
//
// The test never takes a password of a person, and it never creates a person.
// The search names the object classes of the row and no identifier.
//
// A stage that failed is not an error of this method. The test ran, so the
// answer is a 200 that names the stage, and the console renders it. An error
// here means the caller may not run the test at all, or the budget refused it.
//
// idpID is empty when the body carries a configuration nobody saved yet, which
// is how an administrator checks a directory before the first save. A body
// beside a stored id replaces the stored row for this one test, and an absent
// bind password in it keeps the stored credential.
func (s *Service) Test(ctx context.Context, a Actor, idpID string, body *Body) (TestResult, error) {
	s.log.Debug("test identity provider",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID),
		logger.String("idp_id", idpID), logger.RequestID(ctx))

	row, err := s.testable(ctx, a, idpID, body)
	if err != nil {
		return TestResult{}, err
	}
	// The budget is spent once the caller is admitted, so a person who may not
	// test a provider never spends the budget of the tenant that holds it.
	if err := s.spendTest(ctx, a); err != nil {
		return TestResult{}, err
	}

	result := probe(ctx, row)

	// The audit row is recorded after the call, the way the test message of the
	// notification domain records after the send. An outbound call cannot be
	// rolled back, so the trail records what happened and not what was intended.
	stage := result.Stage
	if result.OK {
		stage = stageNone
	}
	// The servers are recorded beside the stage. A test of a configuration
	// nobody saved yet names no stored row, so this is the only record of where
	// the outbound call went, and the budget above is what bounds how often an
	// administrator can drive one at a host of their choosing.
	entry := a.entry(audit.ActionIdpTested, idpID, row.OrgID)
	entry.Metadata["stage"] = stage
	entry.Metadata["servers"] = row.Servers

	if err := s.deps.InTx(ctx, func(ctx context.Context) error {
		return s.deps.Audit.Record(ctx, entry)
	}); err != nil {
		return TestResult{}, s.fail(a, "record the connection test", err)
	}

	s.log.Info("tested identity provider",
		logger.String("tenant_id", a.TenantID),
		logger.String("user_id", a.UserID),
		logger.String("idp_id", idpID),
		logger.String("stage", stage))
	return result, nil
}

// testable reads the provider one test runs against, once the person is allowed
// to run it.
//
// The gate is the write gate and not the read gate. Every administrator of the
// tenant reads the whole provider list, but a test spends the credential of the
// provider on an outbound call, which is what a write does.
func (s *Service) testable(ctx context.Context, a Actor, idpID string, body *Body) (Provider, error) {
	// A configuration nobody saved yet. The body is the whole row, so the level
	// it names is what the gate reads, the way a create reads it.
	if idpID == "" {
		held, err := s.admitted(ctx, a)
		if err != nil {
			return Provider{}, err
		}
		// The handler binds the body on this path, so a nil body is a caller
		// this package does not have. An empty one answers ErrServerScheme
		// below, which is a refusal and not a panic.
		if body == nil {
			body = &Body{}
		}
		if !held.CanWrite(body.OrgID) {
			return Provider{}, s.refuse(a, "", "test an identity provider")
		}
		if err := s.checkShape(ctx, a, *body); err != nil {
			return Provider{}, err
		}
		return body.apply(Provider{TenantID: a.TenantID, OrgID: body.OrgID}), nil
	}

	stored, err := s.writable(ctx, a, idpID, "test an identity provider")
	if err != nil {
		return Provider{}, err
	}
	if body == nil {
		return stored, nil
	}
	// A test of another level would dial with the credential of this provider
	// and report on an organization it does not belong to, so the level of a
	// stored row is as fixed here as it is on an update.
	if body.OrgID != stored.OrgID {
		return Provider{}, fmt.Errorf("%w: provider %s", ErrLevelFixed, idpID)
	}
	if err := s.checkShape(ctx, a, *body); err != nil {
		return Provider{}, err
	}
	return body.apply(stored), nil
}

// spendTest spends one connection test of the tenant's trailing-window budget,
// and refuses the test when nothing is left.
//
// A cache failure refuses the test. Redis holds the whole counter, so a test
// that ran without it would leave an outbound call into a customer network
// unmetered for as long as Redis is down. That call is driven by any console
// user of the tenant, against a host the tenant names, and there is nothing
// weaker to fall back to.
func (s *Service) spendTest(ctx context.Context, a Actor) error {
	allowed, err := s.deps.Allow(ctx, testKey(a.TenantID), testLimit, testWindow)
	if err != nil {
		s.log.Error("read the connection test budget",
			logger.String("tenant_id", a.TenantID),
			logger.String("user_id", a.UserID), logger.Err(err))
		return fmt.Errorf("%w: tenant %s", ErrTestUnavailable, a.TenantID)
	}
	if allowed {
		return nil
	}

	s.log.Warn("refused a connection test over the budget",
		logger.String("tenant_id", a.TenantID), logger.String("user_id", a.UserID))
	return fmt.Errorf("%w: tenant %s", ErrTooManyTests, a.TenantID)
}

// probe runs the four stages against one directory and answers the first one
// that did not pass.
//
// It is a package function and not a method, because it logs nothing. The stage
// and its message are the answer the console renders, and a log line beside them
// would say the same thing twice.
func probe(ctx context.Context, p Provider) TestResult {
	if p.BindDN == "" || p.BindPassword == "" {
		return failed(StageBind, "the identity provider carries no bind credential")
	}
	if len(p.UserObjectClasses) == 0 {
		return failed(StageSearch, "the identity provider maps no user object class")
	}

	conn, stage, err := dial(ctx, p)
	if err != nil {
		return failed(stage, err.Error())
	}
	defer conn.Close()

	if err := conn.Bind(p.BindDN, p.BindPassword); err != nil {
		return failed(StageBind, err.Error())
	}

	matched, err := countEntries(conn, p)
	if err != nil {
		return failed(StageSearch, err.Error())
	}
	return TestResult{OK: true, Matched: matched}
}

// countEntries runs one search under the base of the provider and answers how
// many entries it matched.
//
// The request asks for the attribute 1.1, which is the LDAP spelling of no
// attribute at all, so a test reads how many people the base holds and never one
// value about any of them.
//
// A directory that stops at the size limit answers the entries it sent, because
// the count is a check on the base and the object classes and not a census.
func countEntries(conn *ldap.Conn, p Provider) (int, error) {
	req := ldap.NewSearchRequest(
		searchBase(p),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		testSizeLimit, p.TimeoutMS/1000, false,
		classFilter(p), []string{"1.1"}, nil,
	)

	res, err := conn.Search(req)
	if err != nil && !cappedByTheSizeLimit(res, err) {
		return 0, err
	}
	return len(res.Entries), nil
}

// cappedByTheSizeLimit reports a search the size limit stopped, which is not a
// failure. The library answers the entries it read beside the error, and either
// side of the exchange can raise it: the directory answers result code 4, and
// the client raises its own error when it counts the limit first.
func cappedByTheSizeLimit(res *ldap.SearchResult, err error) bool {
	if res == nil {
		return false
	}
	return errors.Is(err, ldap.ErrSizeLimitExceeded) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)
}
