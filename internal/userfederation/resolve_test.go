package userfederation

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"go.uber.org/zap/zapcore"

	"alphaomega/identitygateway/internal/platform/logger"
)

// theIdentifier is the address every resolution test types, and theDomain is the
// domain it carries. The stored claim is lowercased on write, so the claim below
// is the lowercase one.
const (
	theIdentifier = "Ada@Corp.Example"
	theDomain     = "corp.example"
	bareUsername  = "ada"
)

// world is what one resolution test reads. A field nobody sets answers nothing
// found, which is a tenant that registered no directory at all.
type world struct {
	// claims maps one domain to the live active federation that holds it.
	claims map[string]string
	// linked names the live active federations the person is linked to, and
	// active names every live active federation of the tenant.
	linked []string
	active []string
	// held reports that the tenant holds an account for the identifier, in any
	// state and soft-deleted rows included.
	held bool

	// broken fails every read below. One test proves that a resolution nobody
	// could run refuses instead of naming a federation.
	broken error
}

// reads counts the seams one test drove, so a test can prove that a case which
// answered early never ran the reads below it.
type reads struct {
	domain, linked, active, held int
}

func testResolver(t *testing.T, w world) (*Resolver, *reads) {
	t.Helper()

	log, _ := logger.NewObserved()
	ran := &reads{}

	return NewResolver(ResolverDeps{
		DomainOwner: func(_ context.Context, _, domain string) (string, error) {
			ran.domain++
			if w.broken != nil {
				return "", w.broken
			}
			federationID, ok := w.claims[domain]
			if !ok {
				return "", fmt.Errorf("%w: domain %s", ErrNotFound, domain)
			}
			return federationID, nil
		},
		Linked: func(context.Context, string, string) ([]string, error) {
			ran.linked++
			return w.linked, w.broken
		},
		Active: func(context.Context, string) ([]string, error) {
			ran.active++
			return w.active, w.broken
		},
		Held: func(context.Context, string, string) (bool, error) {
			ran.held++
			return w.held, w.broken
		},
		Log: log,
	}), ran
}

// resolve runs one resolution and fails the test when it refused. email is the
// address the tenant holds for the person, and it is empty when the identifier
// named nobody.
func resolve(t *testing.T, r *Resolver, userID, identifier, email string) string {
	t.Helper()

	federationID, err := r.Resolve(context.Background(), testTenantID, userID, identifier, email)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return federationID
}

// TestCaseOneDomainClaimAnswers covers case 1. A domain a live active federation
// claims names the directory, and it outranks every case below it, including a
// person who holds a local password and a Federation Link of their own.
func TestCaseOneDomainClaimAnswers(t *testing.T) {
	r, ran := testResolver(t, world{
		claims: map[string]string{theDomain: tenantFederationID},
		linked: []string{orgFederationID},
	})

	if got := resolve(t, r, testUserID, theIdentifier, ""); got != tenantFederationID {
		t.Fatalf("federation = %q, want the federation that claims the domain", got)
	}
	if ran.linked != 0 || ran.held != 0 || ran.active != 0 {
		t.Fatalf("reads below the domain claim ran: %+v", ran)
	}
}

// TestDomainMatchIgnoresCaseAndSpace covers the reading of one identifier. A
// person types what their mail client shows them, and the column holds a
// lowercased host.
func TestDomainMatchIgnoresCaseAndSpace(t *testing.T) {
	r, _ := testResolver(t, world{claims: map[string]string{theDomain: tenantFederationID}})

	for _, typed := range []string{
		"ada@corp.example",
		"  ADA@CORP.EXAMPLE  ",
		"\tAda@Corp.Example\n",
	} {
		if got := resolve(t, r, "", typed, ""); got != tenantFederationID {
			t.Fatalf("%q resolved %q, want the federation that claims the domain", typed, got)
		}
	}
}

// TestBareUsernameReadsNoDomainClaim proves that a person who types no domain
// never drives the claim read. There is no domain to match, and case 3 answers.
func TestBareUsernameReadsNoDomainClaim(t *testing.T) {
	r, ran := testResolver(t, world{claims: map[string]string{theDomain: tenantFederationID}})

	if got := resolve(t, r, testUserID, bareUsername, ""); got != "" {
		t.Fatalf("federation = %q, want the local password compare", got)
	}
	if ran.domain != 0 {
		t.Fatalf("the domain claim was read %d times, want none", ran.domain)
	}
}

// TestCaseOneReadsTheEmailOfThePerson proves that a domain claim is resolved
// from the person and not from the string they typed. The identifier step
// accepts a username as well as an email address, so a claim that read the typed
// form alone was stepped around by typing the username, and the local bcrypt
// compare then proved the sign-in against the hash the claim retired.
//
// The person holds a Federation Link of their own here, so the test also proves
// that the email form outranks case 2 the way the typed form does.
func TestCaseOneReadsTheEmailOfThePerson(t *testing.T) {
	r, ran := testResolver(t, world{
		claims: map[string]string{theDomain: tenantFederationID},
		linked: []string{orgFederationID},
	})

	if got := resolve(t, r, testUserID, bareUsername, theIdentifier); got != tenantFederationID {
		t.Fatalf("federation = %q, want the federation that claims the domain", got)
	}
	if ran.linked != 0 || ran.held != 0 || ran.active != 0 {
		t.Fatalf("reads below the domain claim ran: %+v", ran)
	}
}

// TestCaseOneReadsTheTypedFormOnce proves that the two forms of one person cost
// one read. A person who types their own email address carries the same domain
// twice, and a claim that is not there is not there either way.
func TestCaseOneReadsTheTypedFormOnce(t *testing.T) {
	r, ran := testResolver(t, world{claims: map[string]string{theDomain: tenantFederationID}})

	if got := resolve(t, r, testUserID, theIdentifier, theIdentifier); got != tenantFederationID {
		t.Fatalf("federation = %q, want the federation that claims the domain", got)
	}
	if ran.domain != 1 {
		t.Fatalf("the domain claim was read %d times, want one", ran.domain)
	}
}

// TestNoClaimCoversTheEmailOfThePerson proves that the email form claims
// nothing on its own. The tenant claims one domain, the person carries another,
// and the cases below case 1 answer them as they do today.
func TestNoClaimCoversTheEmailOfThePerson(t *testing.T) {
	r, ran := testResolver(t, world{
		claims: map[string]string{theDomain: tenantFederationID},
		linked: []string{orgFederationID},
	})

	if got := resolve(t, r, testUserID, bareUsername, "ada@other.example"); got != orgFederationID {
		t.Fatalf("federation = %q, want the federation of the federation link", got)
	}
	if ran.domain != 1 {
		t.Fatalf("the domain claim was read %d times, want one for the email form", ran.domain)
	}
}

// TestCaseTwoOneFederationLinkAnswers covers case 2. The person holds one Identity
// Link with a federation that takes a typed password, so that directory proves the
// sign-in with no domain claim anywhere.
func TestCaseTwoOneFederationLinkAnswers(t *testing.T) {
	r, ran := testResolver(t, world{linked: []string{orgFederationID}, active: []string{orgFederationID}})

	if got := resolve(t, r, testUserID, bareUsername, ""); got != orgFederationID {
		t.Fatalf("federation = %q, want the linked federation", got)
	}
	if ran.held != 0 || ran.active != 0 {
		t.Fatalf("the reads of case 4 ran for a person the tenant holds: %+v", ran)
	}
}

// TestCaseTwoRefusesTwoFederationLinks covers the first refusal. One person holds
// at most one account per federation, which the unique key enforces, so two links
// that both take a typed password means two directories.
func TestCaseTwoRefusesTwoFederationLinks(t *testing.T) {
	r, _ := testResolver(t, world{linked: []string{orgFederationID, tenantFederationID}})

	_, err := r.resolve(context.Background(), testTenantID, testUserID, bareUsername, "")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous", err)
	}
}

// TestCaseThreeLocalPasswordAnswers covers case 3. The person the tenant holds
// is tied to no directory, so the bcrypt compare answers, as it does today.
func TestCaseThreeLocalPasswordAnswers(t *testing.T) {
	r, _ := testResolver(t, world{active: []string{tenantFederationID}})

	if got := resolve(t, r, testUserID, bareUsername, ""); got != "" {
		t.Fatalf("federation = %q, want the local password compare", got)
	}
}

// TestCaseFourSoleFederationAnswers covers case 4. Nobody holds this identifier,
// and the tenant registered one directory, which is how a person the directory
// owns signs in for the first time with a bare username.
func TestCaseFourSoleFederationAnswers(t *testing.T) {
	r, ran := testResolver(t, world{active: []string{tenantFederationID}})

	if got := resolve(t, r, "", bareUsername, ""); got != tenantFederationID {
		t.Fatalf("federation = %q, want the one federation of the tenant", got)
	}
	if ran.held != 1 {
		t.Fatalf("the account read ran %d times, want once", ran.held)
	}
}

// TestCaseFourRefusesTwoFederations covers the second refusal. A tenant that
// registers a second directory loses the bare-username route for everybody,
// because the alternative sends the password of one customer to the server of
// another.
func TestCaseFourRefusesTwoFederations(t *testing.T) {
	r, _ := testResolver(t, world{active: []string{tenantFederationID, orgFederationID}})

	_, err := r.resolve(context.Background(), testTenantID, "", bareUsername, "")
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous", err)
	}
}

// TestCaseFourSkipsAnAccountTheTenantHolds proves the second read of the person.
// FindByIdentifier filters state = active inside the query, so a deactivated,
// locked, or soft-deleted person names nobody there. Case 4 must still refuse to
// treat them as nobody, or the first bind writes them a brand-new row.
func TestCaseFourSkipsAnAccountTheTenantHolds(t *testing.T) {
	r, ran := testResolver(t, world{held: true, active: []string{tenantFederationID}})

	if got := resolve(t, r, "", bareUsername, ""); got != "" {
		t.Fatalf("federation = %q, want the local password compare", got)
	}
	if ran.active != 0 {
		t.Fatalf("the federations of the tenant were counted for an account that exists: %+v", ran)
	}
}

// TestTenantWithNoFederationResolvesNothing covers the tenant every deployment
// starts as. No federation is registered, so every identifier answers the local
// password compare and the sign-in is what it was.
func TestTenantWithNoFederationResolvesNothing(t *testing.T) {
	r, _ := testResolver(t, world{})

	for _, userID := range []string{testUserID, ""} {
		if got := resolve(t, r, userID, theIdentifier, ""); got != "" {
			t.Fatalf("federation = %q, want the local password compare", got)
		}
	}
}

// TestABrokenReadRefuses proves that resolution never guesses. A read that broke
// answers the error, and the caller decides what the sign-in does about it.
func TestABrokenReadRefuses(t *testing.T) {
	broken := errors.New("the database is unreachable")

	for _, name := range []string{"domain", "link", "account"} {
		w := world{broken: broken, claims: map[string]string{theDomain: tenantFederationID}}
		identifier, userID := theIdentifier, testUserID
		switch name {
		case "link":
			identifier = bareUsername
		case "account":
			identifier, userID = bareUsername, ""
		}

		r, _ := testResolver(t, w)
		if _, err := r.Resolve(context.Background(), testTenantID, userID, identifier, ""); !errors.Is(err, broken) {
			t.Fatalf("%s read: err = %v, want the read error", name, err)
		}
	}
}

// TestNoRefusalNamesTheCaseItRefused proves that neither the log line nor the
// error says which of the two refusals ran. Case 2 counts Federation Links and
// case 4 counts federations, so a refusal that named its case would say whether
// the identifier named a real person.
func TestNoRefusalNamesTheCaseItRefused(t *testing.T) {
	log, observed := logger.NewObserved()

	linked, _ := testResolverLogging(log, world{linked: []string{orgFederationID, tenantFederationID}}).
		Resolve(context.Background(), testTenantID, testUserID, bareUsername, "")
	unknown, _ := testResolverLogging(log, world{active: []string{orgFederationID, tenantFederationID}}).
		Resolve(context.Background(), testTenantID, "", bareUsername, "")

	if linked != "" || unknown != "" {
		t.Fatalf("a refusal named a federation: %q and %q", linked, unknown)
	}

	lines := observed.FilterLevelExact(zapcore.WarnLevel).All()
	if len(lines) != 2 {
		t.Fatalf("logged %d lines, want one per refusal", len(lines))
	}
	if lines[0].Message != lines[1].Message {
		t.Fatalf("the two refusals logged %q and %q, want one message",
			lines[0].Message, lines[1].Message)
	}
	for _, line := range lines {
		for _, field := range line.Context {
			if field.Key != "tenant_id" {
				t.Fatalf("a refusal logged %q, want the tenant alone", field.Key)
			}
		}
	}
}

// testResolverLogging builds one resolver on a log the caller reads.
func testResolverLogging(log logger.Logger, w world) *Resolver {
	return NewResolver(ResolverDeps{
		DomainOwner: func(_ context.Context, _, domain string) (string, error) {
			return "", fmt.Errorf("%w: domain %s", ErrNotFound, domain)
		},
		Linked: func(context.Context, string, string) ([]string, error) { return w.linked, nil },
		Active: func(context.Context, string) ([]string, error) { return w.active, nil },
		Held:   func(context.Context, string, string) (bool, error) { return w.held, nil },
		Log:    log,
	})
}

// TestResolveAnswersTheLocalCompareWhenItRefuses covers the seam the identifier
// step takes. Both refusals answer the local password compare, and neither
// reaches the caller: which of the two ran says whether the identifier named a
// real person.
func TestResolveAnswersTheLocalCompareWhenItRefuses(t *testing.T) {
	cases := map[string]world{
		"two federation links": {linked: []string{orgFederationID, tenantFederationID}},
		"two federations":      {active: []string{orgFederationID, tenantFederationID}},
	}
	userIDs := map[string]string{"two federation links": testUserID, "two federations": ""}

	for name, w := range cases {
		r, _ := testResolver(t, w)
		federationID, err := r.Resolve(context.Background(), testTenantID, userIDs[name], bareUsername, "")
		if err != nil {
			t.Fatalf("%s: Resolve gave %v, want the local password compare", name, err)
		}
		if federationID != "" {
			t.Errorf("%s: Resolve named %q, want the local password compare", name, federationID)
		}
	}
}

// TestResolveStopsOnABrokenRead proves that a read that failed is not a refusal.
// A sign-in that carried on would fall back to a local password hash that a
// claimed domain took out of service.
func TestResolveStopsOnABrokenRead(t *testing.T) {
	broken := errors.New("the database is unreachable")
	r, _ := testResolver(t, world{broken: broken})

	if _, err := r.Resolve(context.Background(), testTenantID, testUserID, theIdentifier, ""); !errors.Is(err, broken) {
		t.Fatalf("err = %v, want the read error", err)
	}
}
