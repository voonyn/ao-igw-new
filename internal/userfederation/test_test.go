package userfederation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/tenant"
)

// TestClassFilter covers the filter the connection test searches with. It names
// every object class the row requires, and it names no person.
func TestClassFilter(t *testing.T) {
	cases := []struct {
		name    string
		classes []string
		want    string
	}{
		{"one class", []string{"inetOrgPerson"}, "(objectClass=inetOrgPerson)"},
		{"two classes", []string{"person", "user"}, "(&(objectClass=person)(objectClass=user))"},
		{"a hostile class", []string{"a)(uid=*"}, `(objectClass=a\29\28uid=\2a)`},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classFilter(Federation{UserObjectClasses: c.classes})
			if got != c.want {
				t.Fatalf("classFilter = %q, want %q", got, c.want)
			}
			if strings.Contains(got, "uid=") && !strings.Contains(got, `\29`) {
				t.Fatalf("classFilter = %q, want the value escaped", got)
			}
		})
	}
}

// TestProbeNamesTheStageThatFailed covers the four stages. An administrator who
// saved a wrong value reads which step it broke, and not one message that covers
// all four.
func TestProbeNamesTheStageThatFailed(t *testing.T) {
	cases := []struct {
		name  string
		row   func(Federation) Federation
		stage string
	}{
		{
			name: "the dial",
			row: func(p Federation) Federation {
				p.Mode, p.Servers = ModePlain, []string{"ldap://" + closedPort(t)}
				return p
			},
			stage: StageDial,
		},
		{
			// The directory accepts the socket and never finishes the handshake,
			// so the deadline stops the test at the TLS stage and never reports
			// a directory that is down.
			name: "the TLS handshake",
			row: func(p Federation) Federation {
				p.Mode, p.Servers = ModeLDAPS, []string{"ldaps://" + silentDirectory(t)}
				p.TimeoutMS = 300
				return p
			},
			stage: StageTLS,
		},
		{
			name: "the service bind",
			row: func(p Federation) Federation {
				p.Mode, p.Servers = ModePlain, []string{"ldap://" + directory(t, ldap.LDAPResultInvalidCredentials, 0, 0)}
				return p
			},
			stage: StageBind,
		},
		{
			name: "the search",
			row: func(p Federation) Federation {
				p.Mode, p.Servers = ModePlain, []string{"ldap://" + directory(t, ldap.LDAPResultSuccess, 0, ldap.LDAPResultNoSuchObject)}
				return p
			},
			stage: StageSearch,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := probe(context.Background(), c.row(storedFederation(testOrgID)))
			if got.OK || got.Stage != c.stage {
				t.Fatalf("probe = %+v, want a failure at %s", got, c.stage)
			}
			if got.Detail == "" {
				t.Errorf("probe = %+v, want a message the console renders", got)
			}
			if strings.Contains(got.Detail, theSecret) {
				t.Fatalf("the answer reads %q, want no bind password in it", got.Detail)
			}
		})
	}
}

// TestProbeRefusesARowWithNoBindCredential answers before it dials. A row that
// carries no credential cannot bind, and the stage says so.
func TestProbeRefusesARowWithNoBindCredential(t *testing.T) {
	p := storedFederation(testOrgID)
	p.BindPassword = ""

	if got := probe(context.Background(), p); got.OK || got.Stage != StageBind {
		t.Fatalf("probe = %+v, want a failure at %s", got, StageBind)
	}
}

// TestProbeReportsWhatTheSearchMatched covers the success. The count is what
// tells an administrator that the base and the object classes are right.
func TestProbeReportsWhatTheSearchMatched(t *testing.T) {
	p := storedFederation(testOrgID)
	p.Mode = ModePlain
	p.Servers = []string{"ldap://" + directory(t, ldap.LDAPResultSuccess, 3, ldap.LDAPResultSuccess)}

	got := probe(context.Background(), p)
	if !got.OK || got.Stage != "" {
		t.Fatalf("probe = %+v, want a success", got)
	}
	if got.Matched != 3 {
		t.Fatalf("probe matched %d, want the 3 entries the directory sent", got.Matched)
	}
}

// TestProbeCountsWhatTheSizeLimitLeft covers a base that holds more people than
// the cap. The directory stops at the limit, which is not a failure: the count
// still says the base and the object classes are right.
func TestProbeCountsWhatTheSizeLimitLeft(t *testing.T) {
	p := storedFederation(testOrgID)
	p.Mode = ModePlain
	p.Servers = []string{"ldap://" + directory(t, ldap.LDAPResultSuccess, 5, ldap.LDAPResultSizeLimitExceeded)}

	got := probe(context.Background(), p)
	if !got.OK || got.Matched != 5 {
		t.Fatalf("probe = %+v, want a success that counts the 5 entries it read", got)
	}
}

// TestTestRecordsTheEventWithTheStage covers the trail. The action is one row
// whoever the test failed on, and the stage rides in the metadata.
func TestTestRecordsTheEventWithTheStage(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{failingFederation(t)},
	})

	got, err := svc.Test(context.Background(), admin, tenantFederationID, nil)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if got.OK || got.Stage != StageDial {
		t.Fatalf("Test = %+v, want a failure at %s", got, StageDial)
	}
	if len(events) != 1 || events[0].Action != string(audit.ActionFederationTested) {
		t.Fatalf("the test recorded %+v, want one federation.tested", events)
	}
	if !strings.Contains(events[0].Metadata, `"stage":"dial"`) {
		t.Errorf("the event metadata reads %q, want the stage that failed", events[0].Metadata)
	}
	if !strings.Contains(events[0].Metadata, `"servers"`) {
		t.Errorf("the event metadata reads %q, want where the call went", events[0].Metadata)
	}
}

// TestTestRefusesASpentBudget covers the cap. The directory is not dialled when
// nothing is left, so the budget bounds the outbound call and not the answer.
func TestTestRefusesASpentBudget(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{failingFederation(t)},
		budgetSpent: true,
	})

	if _, err := svc.Test(context.Background(), admin, tenantFederationID, nil); !errors.Is(err, ErrTooManyTests) {
		t.Fatalf("err = %v, want ErrTooManyTests", err)
	}
	if len(events) != 0 {
		t.Errorf("the refused test recorded %+v, want nothing", events)
	}
}

// TestTestRefusesABudgetNobodyCouldRead covers the cache failure. Redis holds
// the whole counter, so a test that ran without it would leave an outbound call
// into a customer network unmetered.
func TestTestRefusesABudgetNobodyCouldRead(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles:  []string{tenant.RoleIAMOwner},
		rows:         []Federation{failingFederation(t)},
		budgetBroken: true,
	})

	_, err := svc.Test(context.Background(), admin, tenantFederationID, nil)
	if !errors.Is(err, ErrTestUnavailable) {
		t.Fatalf("err = %v, want ErrTestUnavailable", err)
	}
	if errors.Is(err, ErrTooManyTests) {
		t.Fatalf("err = %v, want the unreadable budget and not the spent one", err)
	}
}

// TestTestRefusesAnOrgOwnerOfAnotherOrganization covers the gate. A test spends
// the credential of the federation on an outbound call, so it reads the write gate
// and not the read gate every administrator passes.
func TestTestRefusesAnOrgOwnerOfAnotherOrganization(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgOwner}}},
		rows:        []Federation{failingFederation(t)},
	})

	if _, err := svc.Test(context.Background(), admin, tenantFederationID, nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// TestTestRunsAnUnsavedConfiguration covers the check an administrator makes
// before the first save. No id names a stored row, so the body is the whole
// federation.
func TestTestRunsAnUnsavedConfiguration(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	write := body()
	write.Mode, write.Servers = ModePlain, []string{"ldap://" + closedPort(t)}
	write.ConfirmPlaintext = true

	got, err := svc.Test(context.Background(), admin, "", &write)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if got.OK || got.Stage != StageDial {
		t.Fatalf("Test = %+v, want a failure at %s", got, StageDial)
	}
	if len(written) != 0 || len(updated) != 0 {
		t.Errorf("the test wrote %+v and %+v, want nothing stored", written, updated)
	}
}

// TestTestKeepsTheStoredCredentialWhenTheBodyOmitsIt covers the form the console
// submits. The bind password is write-only, so the console cannot send it back
// and the stored one is what the test binds with.
func TestTestKeepsTheStoredCredentialWhenTheBodyOmitsIt(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{failingFederation(t)},
	})

	write := body()
	write.OrgID, write.Mode, write.Servers = testOrgID, ModePlain, []string{"ldap://" + closedPort(t)}
	write.ConfirmPlaintext, write.BindPassword = true, nil

	got, err := svc.Test(context.Background(), admin, tenantFederationID, &write)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	// A row with no credential answers at the bind stage before it dials, so a
	// dial failure proves the stored credential survived the body.
	if got.Stage != StageDial {
		t.Fatalf("Test = %+v, want the dial to run, which needs the stored credential", got)
	}
}

// TestNoTestAnswerOrLogLineCarriesTheBindPassword walks the answer and every log
// line of one test. Neither carries the credential the federation binds with.
func TestNoTestAnswerOrLogLineCarriesTheBindPassword(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{failingFederation(t)},
	})

	got, err := svc.Test(context.Background(), admin, tenantFederationID, nil)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", got), theSecret) {
		t.Fatalf("the answer reads %+v, want no bind password in it", got)
	}
	for _, line := range logs.All() {
		read := fmt.Sprintf("%s %v", line.Message, line.ContextMap())
		if strings.Contains(read, theSecret) {
			t.Fatalf("a log line reads %q, want no bind password in it", read)
		}
	}
	for _, event := range events {
		if strings.Contains(event.Metadata, theSecret) {
			t.Fatalf("an audit row reads %q, want no bind password in it", event.Metadata)
		}
	}
}

// failingFederation is the stored row the service tests run against. It dials a
// port nothing listens on, so the test fails at the first stage and no test of
// this file needs a directory to answer.
func failingFederation(t *testing.T) Federation {
	t.Helper()

	p := storedFederation(testOrgID)
	p.Mode, p.Servers, p.TimeoutMS = ModePlain, []string{"ldap://" + closedPort(t)}, 2000
	return p
}

// directory is an LDAP server that answers one bind and one search with the
// codes the test names, and nothing else.
//
// It exists because the four stages cannot be told apart without a server that
// completes the earlier ones. entries is how many search results it sends before
// the done message, which is what the matched count reads.
func directory(t *testing.T, bindCode int, entries, searchCode int) string {
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
			go serve(conn, bindCode, entries, searchCode)
		}
	}()
	return ln.Addr().String()
}

// serve answers the requests of one connection. An unbind, and anything else
// this server does not know, is read and dropped.
func serve(conn net.Conn, bindCode, entries, searchCode int) {
	defer conn.Close()

	for {
		req, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(req.Children) < 2 {
			return
		}
		id, ok := req.Children[0].Value.(int64)
		if !ok {
			return
		}

		switch req.Children[1].Tag {
		case ldap.ApplicationBindRequest:
			if _, err := conn.Write(result(id, ldap.ApplicationBindResponse, bindCode)); err != nil {
				return
			}
		case ldap.ApplicationSearchRequest:
			for i := 0; i < entries; i++ {
				if _, err := conn.Write(entry(id, i)); err != nil {
					return
				}
			}
			if _, err := conn.Write(result(id, ldap.ApplicationSearchResultDone, searchCode)); err != nil {
				return
			}
		default:
			return
		}
	}
}

// result is one LDAPMessage that carries a result code and nothing else. A bind
// answer and a search-done answer have the same shape.
func result(id int64, app ber.Tag, code int) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, app, nil, "Response")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	return message(id, op)
}

// entry is one search result. The test search asks for no attribute, so the
// entry carries a name and an empty attribute list.
func entry(id int64, n int) []byte {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldap.ApplicationSearchResultEntry), nil, "Entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString,
		fmt.Sprintf("uid=person-%d,dc=corp,dc=example", n), "objectName"))
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	return message(id, op)
}

// message wraps one operation in the envelope every LDAP message carries.
func message(id int64, op *ber.Packet) []byte {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	packet.AppendChild(op)
	return packet.Bytes()
}
