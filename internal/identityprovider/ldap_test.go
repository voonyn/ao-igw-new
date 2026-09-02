package identityprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// TestSearchFilter covers the filter the search is built from. The object
// classes are required together, and the identifier matches any one of the
// filter attributes.
func TestSearchFilter(t *testing.T) {
	cases := []struct {
		name       string
		classes    []string
		filters    []string
		identifier string
		want       string
	}{
		{
			name: "one class and one filter", classes: []string{"inetOrgPerson"},
			filters: []string{"uid"}, identifier: "alice",
			want: "(&(objectClass=inetOrgPerson)(uid=alice))",
		},
		{
			name: "two classes and two filters", classes: []string{"person", "user"},
			filters: []string{"sAMAccountName", "mail"}, identifier: "alice",
			want: "(&(objectClass=person)(objectClass=user)(|(sAMAccountName=alice)(mail=alice)))",
		},
		{
			name: "an email address", classes: []string{"user"},
			filters: []string{"mail"}, identifier: "alice@corp.example",
			want: "(&(objectClass=user)(mail=alice@corp.example))",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Provider{UserObjectClasses: c.classes, UserFilters: c.filters}

			if got := searchFilter(p, c.identifier); got != c.want {
				t.Fatalf("searchFilter = %q, want %q", got, c.want)
			}
		})
	}
}

// TestSearchFilterEscapesTheIdentifier proves that a hostile value cannot change
// the search. An unescaped identifier closes the parenthesis and widens the
// search to every person of the directory, and the second bind then proves the
// password of somebody else.
func TestSearchFilterEscapesTheIdentifier(t *testing.T) {
	p := Provider{UserObjectClasses: []string{"user"}, UserFilters: []string{"uid"}}

	hostile := []string{"*", "*)(uid=*", "alice)(|(uid=admin", "alice\\", "alice\x00"}

	for _, identifier := range hostile {
		got := searchFilter(p, identifier)

		want := fmt.Sprintf("(&(objectClass=user)(uid=%s))", ldap.EscapeFilter(identifier))
		if got != want {
			t.Fatalf("searchFilter(%q) = %q, want %q", identifier, got, want)
		}
		// The filter holds one opening parenthesis for each attribute and one
		// for the operator. A value that added its own would read as a filter of
		// its own.
		if strings.Count(got, "(") != 3 {
			t.Fatalf("searchFilter(%q) = %q, want three parentheses", identifier, got)
		}
	}
}

// TestSearchBase covers the subtree the search runs under. user_base is a
// subtree of base_dn, so it is prefixed and never replaces the base.
func TestSearchBase(t *testing.T) {
	p := Provider{BaseDN: "dc=corp,dc=example"}
	if got := searchBase(p); got != "dc=corp,dc=example" {
		t.Fatalf("searchBase = %q, want the base", got)
	}

	p.UserBase = "ou=people"
	if got := searchBase(p); got != "ou=people,dc=corp,dc=example" {
		t.Fatalf("searchBase = %q, want the base under the user base", got)
	}
}

// TestAttributes covers the six names one row maps. A name the row leaves empty
// is never asked for, and the answer carries an empty value instead of a
// failure.
func TestAttributes(t *testing.T) {
	p := storedProvider(testOrgID)
	p.AttrDisplayName = "displayName"

	want := []string{"objectGUID", "sAMAccountName", "mail", "displayName"}
	got := attributes(p)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("attributes = %v, want %v", got, want)
	}

	entry := ldap.NewEntry("cn=alice,dc=corp,dc=example", map[string][]string{
		"objectGUID":     {"a-stable-id"},
		"sAMAccountName": {"alice"},
		"mail":           {"alice@corp.example"},
	})

	person := identityOf(p, entry)
	if person.Username != "alice" || person.Email != "alice@corp.example" {
		t.Fatalf("identityOf = %+v, want the mapped attributes", person)
	}
	if person.ExternalID != "a-stable-id" || person.DN != "cn=alice,dc=corp,dc=example" {
		t.Fatalf("identityOf = %+v, want the stable id and the DN", person)
	}
	if person.DisplayName != "" || person.FirstName != "" {
		t.Fatalf("identityOf = %+v, want empty optional attributes", person)
	}
}

// TestStableIDEncodesBinary covers objectGUID, which Active Directory answers as
// raw binary. No VARCHAR column holds those bytes, so the id is hex encoded, and
// the same account reads as the same id on every later bind.
func TestStableIDEncodesBinary(t *testing.T) {
	guid := string([]byte{0xd0, 0x8f, 0x00, 0xff, 0x11, 0x22})
	entry := ldap.NewEntry("cn=alice", map[string][]string{"objectGUID": {guid}})

	got := stableID(entry, "objectGUID")
	if got != "d08f00ff1122" {
		t.Fatalf("stableID = %q, want the hex encoding", got)
	}
	if again := stableID(entry, "objectGUID"); again != got {
		t.Fatalf("stableID = %q then %q, want one stable answer", got, again)
	}
	if empty := stableID(entry, "nothing"); empty != "" {
		t.Fatalf("stableID = %q, want an empty answer for a missing attribute", empty)
	}

	// Sixteen random bytes read as valid text often enough to matter, and the
	// column is part of a primary key.
	text := string([]byte{0xd0, 0x8f, 0x00, 0x11})
	entry = ldap.NewEntry("cn=alice", map[string][]string{"objectGUID": {text}})
	if got := stableID(entry, "objectGUID"); got != "d08f0011" {
		t.Fatalf("stableID = %q, want the hex encoding of a value that holds control bytes", got)
	}
}

// TestBindRefusesAProviderWithNoFilter covers a row that maps no user filter.
// The filter would then name no identifier, and the search would match whichever
// person the base holds. The columns are nullable, so the guard is not the body
// alone.
func TestBindRefusesAProviderWithNoFilter(t *testing.T) {
	svc := testService(t, deps{})
	ctx := context.Background()

	p := storedProvider(testOrgID)
	p.UserFilters = nil
	if _, err := svc.Bind(ctx, p, "alice", "the-typed-password"); !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory for a row with no user filter", err)
	}

	p = storedProvider(testOrgID)
	p.UserObjectClasses = nil
	if _, err := svc.Bind(ctx, p, "alice", "the-typed-password"); !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory for a row with no object class", err)
	}
}

// TestAddress covers the port each transport dials when the server string names
// none, and the host the certificate must carry.
func TestAddress(t *testing.T) {
	cases := []struct {
		mode   int
		server string
		addr   string
		host   string
	}{
		{ModeLDAPS, "ldaps://dc1.corp.example", "dc1.corp.example:636", "dc1.corp.example"},
		{ModeLDAPS, "ldaps://dc1.corp.example:1636", "dc1.corp.example:1636", "dc1.corp.example"},
		{ModePlain, "ldap://dc1.corp.example", "dc1.corp.example:389", "dc1.corp.example"},
		{ModeStartTLS, "ldap://dc1.corp.example", "dc1.corp.example:389", "dc1.corp.example"},
	}

	for _, c := range cases {
		addr, host, err := address(c.mode, c.server)
		if err != nil {
			t.Fatalf("address(%s): %v", c.server, err)
		}
		if addr != c.addr || host != c.host {
			t.Fatalf("address(%s) = %q, %q, want %q, %q", c.server, addr, host, c.addr, c.host)
		}
	}

	if _, _, err := address(ModeLDAPS, "ldaps://"); !errors.Is(err, ErrServerScheme) {
		t.Fatalf("err = %v, want ErrServerScheme for a string that names no host", err)
	}
}

// TestTLSConfig covers the transport of one provider. Certificate checks are on,
// the minimum version is pinned, and root_ca is the one authority the provider
// trusts.
func TestTLSConfig(t *testing.T) {
	p := storedProvider(testOrgID)

	cfg, err := tlsConfig(p, "dc1.corp.example")
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("tlsConfig skips the certificate check, want the check on")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.ServerName != "dc1.corp.example" {
		t.Fatalf("ServerName = %q, want the host of the server", cfg.ServerName)
	}
	if cfg.RootCAs != nil {
		t.Fatal("tlsConfig holds a pool, want the system store when no root_ca is set")
	}

	p.RootCA = selfSignedPEM(t)
	cfg, err = tlsConfig(p, "dc1.corp.example")
	if err != nil {
		t.Fatalf("tlsConfig with a root CA: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("tlsConfig holds no pool, want the root_ca as the one authority")
	}

	p.RootCA = "not a certificate"
	if _, err := tlsConfig(p, "dc1.corp.example"); !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory for a root_ca that holds no PEM", err)
	}
}

// TestBindRefusesAnEmptyPassword covers the unauthenticated bind. A directory
// answers an empty password with success, so the password never reaches the
// wire, and the answer is the wrong-password sentinel.
func TestBindRefusesAnEmptyPassword(t *testing.T) {
	svc := testService(t, deps{})

	if _, err := svc.Bind(context.Background(), storedProvider(testOrgID), "alice", ""); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v, want ErrWrongPassword", err)
	}
}

// TestBindStopsAtTheTimeout covers the deadline. The directory here accepts the
// connection and answers nothing, which is the failure that hangs a request, and
// timeout_ms bounds it.
//
// The same test walks every log line: neither the password the person typed nor
// the bind password of the provider reaches one.
func TestBindStopsAtTheTimeout(t *testing.T) {
	svc := testService(t, deps{})
	silent := silentDirectory(t)

	p := storedProvider(testOrgID)
	p.Mode, p.Servers, p.TimeoutMS = ModePlain, []string{"ldap://" + silent}, 200

	start := time.Now()
	_, err := svc.Bind(context.Background(), p, "alice", "the-typed-password")
	if !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the bind took %s, want the timeout to bound it", took)
	}

	for _, line := range logs.All() {
		read := fmt.Sprintf("%s %v", line.Message, line.ContextMap())
		if strings.Contains(read, "the-typed-password") || strings.Contains(read, theSecret) {
			t.Fatalf("a log line reads %q, want no password in it", read)
		}
	}
}

// TestBindReportsADirectoryThatRefusesTheConnection covers the dial failure. It
// is not a credential failure, so the caller answers directory_unavailable.
func TestBindReportsADirectoryThatRefusesTheConnection(t *testing.T) {
	svc := testService(t, deps{})

	p := storedProvider(testOrgID)
	p.Mode, p.Servers, p.TimeoutMS = ModePlain, []string{"ldap://" + closedPort(t)}, 2000

	_, err := svc.Bind(context.Background(), p, "alice", "the-typed-password")
	if !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory", err)
	}
	if errors.Is(err, ErrWrongPassword) || errors.Is(err, ErrNoEntry) {
		t.Fatalf("err = %v, want a directory failure and not a credential failure", err)
	}
}

// TestProveRefusesAnInactiveProvider covers the switch a tenant turns off. The
// directory is not dialled and the budget is not spent, because neither the
// person nor the directory did anything wrong.
func TestProveRefusesAnInactiveProvider(t *testing.T) {
	off := failingProvider(t)
	off.State = StateInactive
	svc := testService(t, deps{rows: []Provider{off}})

	_, err := svc.Prove(context.Background(), testTenantID, tenantIdpID, personID, "alice", "the-typed-password")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
	if spends != 0 {
		t.Errorf("the refused sign-in spent %d binds, want none", spends)
	}
}

// TestProveRefusesAProviderNobodyHolds covers the soft-deleted row. The read
// filters deleted_at, so a deleted provider is a miss, and the two states behave
// alike: both refuse and neither spends the budget.
func TestProveRefusesAProviderNobodyHolds(t *testing.T) {
	svc := testService(t, deps{})

	_, err := svc.Prove(context.Background(), testTenantID, deadIdpID, personID, "alice", "the-typed-password")
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
	if spends != 0 {
		t.Errorf("the refused sign-in spent %d binds, want none", spends)
	}
}

// TestProveRefusesASpentBindBudget covers the cap. The provider dials an address
// nothing listens on, so an answer that named the directory would prove that the
// bind ran. ErrTooManyBinds proves that it did not.
func TestProveRefusesASpentBindBudget(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{failingProvider(t)}, budgetSpent: true})

	_, err := svc.Prove(context.Background(), testTenantID, tenantIdpID, personID, "alice", "the-typed-password")
	if !errors.Is(err, ErrTooManyBinds) {
		t.Fatalf("err = %v, want ErrTooManyBinds", err)
	}
	if errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want the cap and not a directory that was dialled", err)
	}
}

// TestProveRefusesABindBudgetNobodyCouldRead covers the cache failure. Redis
// holds the whole budget, so a bind that ran without it would leave an outbound
// call into a customer network unmetered for as long as Redis is down.
func TestProveRefusesABindBudgetNobodyCouldRead(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{failingProvider(t)}, budgetBroken: true})

	_, err := svc.Prove(context.Background(), testTenantID, tenantIdpID, personID, "alice", "the-typed-password")
	if !errors.Is(err, ErrBindUnavailable) {
		t.Fatalf("err = %v, want ErrBindUnavailable", err)
	}
	if errors.Is(err, ErrTooManyBinds) || errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want the unreadable budget and not the spent one", err)
	}
}

// TestProveSpendsOneBindOnALiveProvider covers the order the budget is spent in.
// It is spent on the way in, because it bounds the outbound call and not the
// answer, so a directory that never answered has spent one bind.
func TestProveSpendsOneBindOnALiveProvider(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{failingProvider(t)}})

	_, err := svc.Prove(context.Background(), testTenantID, tenantIdpID, personID, "alice", "the-typed-password")
	if !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory", err)
	}
	if spends != 1 {
		t.Errorf("the sign-in spent %d binds, want one", spends)
	}
}

// TestProveSpendsNothingOnAnEmptyPassword covers the value that costs the
// directory nothing. An unauthenticated bind never reaches the wire, so it must
// not cost the person the budget a real bind costs: without this order, a
// stranger locks a named person out of the directory sign-in with ten empty
// requests.
func TestProveSpendsNothingOnAnEmptyPassword(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{failingProvider(t)}})

	_, err := svc.Prove(context.Background(), testTenantID, tenantIdpID, personID, "alice", "")
	if !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("err = %v, want ErrWrongPassword", err)
	}
	if spends != 0 {
		t.Errorf("the empty password spent %d binds, want none", spends)
	}
}

// TestUnnamedBindKeyCarriesNoIdentifier covers the fallback, which a sign-in
// takes whenever the identifier step named no person. The key carries the digest
// of the identifier and never the address itself, because every operator who
// lists the keyspace reads these keys.
func TestUnnamedBindKeyCarriesNoIdentifier(t *testing.T) {
	key := bindKey(testTenantID, "", "alice@corp.example")

	if strings.Contains(key, "alice") || strings.Contains(key, "corp.example") {
		t.Fatalf("bindKey = %q, want no identifier in it", key)
	}
	if key == bindKey(testTenantID, "", "bob@corp.example") {
		t.Fatal("two identifiers share one budget key, want one key each")
	}
	if key != bindKey(testTenantID, "", "alice@corp.example") {
		t.Fatal("the key of one identifier changed between two reads")
	}
}

// TestUnnamedBindKeyFoldsTheIdentifier covers the multiplication a raw digest
// left open. The directory matches a DirectoryString attribute with
// caseIgnoreMatch, so it folds case and insignificant space onto one entry. A
// key that folded neither gave one entry a fresh counter of ten for every typed
// form a caller invented. See .scratch/directory-sign-in/issues/34.
func TestUnnamedBindKeyFoldsTheIdentifier(t *testing.T) {
	key := bindKey(testTenantID, "", "alice@corp.example")

	forms := []string{
		"Alice@corp.example",
		"ALICE@CORP.EXAMPLE",
		" alice@corp.example",
		"alice@corp.example\t",
	}
	for _, form := range forms {
		if bindKey(testTenantID, "", form) != key {
			t.Errorf("the form %q holds a budget of its own, want one counter for one entry", form)
		}
	}

	if bindKey(testTenantID, "", "bob@corp.example") == key {
		t.Error("two entries share one budget key, want one key each")
	}
}

// TestBindKeyNamesThePerson covers the key of a named person. A tenant matches
// a username and an email address, so a key of the typed string gave one person
// two counters of ten, and the real cap was twenty.
func TestBindKeyNamesThePerson(t *testing.T) {
	byUsername := bindKey(testTenantID, personID, "alice")

	if byUsername != bindKey(testTenantID, personID, "alice@corp.example") {
		t.Fatalf("bindKey = %q, want both forms of one identifier on one key", byUsername)
	}
	if byUsername == bindKey(testTenantID, testUserID, "alice") {
		t.Fatal("two people share one budget key, want one key each")
	}
	if byUsername == bindKey(otherTenant, personID, "alice") {
		t.Fatal("two tenants share one budget key, want one key each")
	}
	if byUsername == bindKey(testTenantID, "", "alice") {
		t.Fatal("a named person and a first bind share one key, want one key each")
	}
}

// TestProveSpendsOneBudgetForBothIdentifierForms covers the cap end to end. The
// person types their username and then their email address, and the two binds
// spend one counter.
func TestProveSpendsOneBudgetForBothIdentifierForms(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{failingProvider(t)}})

	for _, identifier := range []string{"alice", "alice@corp.example"} {
		_, err := svc.Prove(
			context.Background(), testTenantID, tenantIdpID, personID, identifier, "the-typed-password",
		)
		if !errors.Is(err, ErrDirectory) {
			t.Fatalf("err = %v, want ErrDirectory", err)
		}
	}

	if len(spentKeys) != 2 {
		t.Fatalf("the two sign-ins spent %d binds, want two", len(spentKeys))
	}
	if spentKeys[0] != spentKeys[1] {
		t.Fatalf("the two forms spent %q and %q, want one counter", spentKeys[0], spentKeys[1])
	}
}

// TestProveKeepsASecondCounterForAnUnresolvableForm pins the residual the person
// key leaves. The person types a User Principal Name the identifier step cannot
// resolve, so the bind names nobody and the budget keys on the typed string. The
// Identity Link names the same person after that bind, and their next sign-in
// spends the counter of the person. The two counters are separate, and no key
// available before the bind can join them. See the ceiling on bindLimit and
// docs/specs/0002-directory-sign-in.md.
func TestProveKeepsASecondCounterForAnUnresolvableForm(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{failingProvider(t)}})

	for _, c := range []struct{ userID, identifier string }{
		{"", "alice@corp.example"},
		{personID, "alice"},
	} {
		_, err := svc.Prove(
			context.Background(), testTenantID, tenantIdpID, c.userID, c.identifier, "the-typed-password",
		)
		if !errors.Is(err, ErrDirectory) {
			t.Fatalf("err = %v, want ErrDirectory", err)
		}
	}

	if len(spentKeys) != 2 {
		t.Fatalf("the two sign-ins spent %d binds, want two", len(spentKeys))
	}
	if spentKeys[0] == spentKeys[1] {
		t.Fatalf("both sign-ins spent %q, want a counter each", spentKeys[0])
	}
}

// TestProveLogsNoPassword proves that neither the typed password nor the
// configured bind password reaches a log line of the sign-in bind.
func TestProveLogsNoPassword(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{failingProvider(t)}})

	if _, err := svc.Prove(
		context.Background(), testTenantID, tenantIdpID, personID, "alice", "the-typed-password",
	); err == nil {
		t.Fatal("Prove answered no error, want a directory that refused the connection")
	}

	for _, entry := range logs.All() {
		line := fmt.Sprintf("%s %v", entry.Message, entry.ContextMap())
		if strings.Contains(line, "the-typed-password") || strings.Contains(line, theSecret) {
			t.Fatalf("a log line reads %q, want no password in it", line)
		}
	}
}

// silentDirectory listens, accepts, and answers nothing. It is the directory
// that hangs a request.
func silentDirectory(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { conn.Close() })
		}
	}()
	return ln.Addr().String()
}

// closedPort answers an address nothing listens on.
func closedPort(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// selfSignedPEM is one certificate for the root_ca test.
func selfSignedPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "corp.example private authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
