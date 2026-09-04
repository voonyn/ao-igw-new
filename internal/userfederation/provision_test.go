package userfederation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"alphaomega/identitygateway/internal/audit"
)

// createdUserID is the id the fake person creator answers with.
const createdUserID = "cccccccc-cccc-cccc-cccc-cccccccccccc"

// typed is what the person typed at the identifier step. Every provisioning test
// binds as alice, who types the email address a claimed domain routes.
const typed = "alice@corp.example"

// firstBind is the attempt every provisioning test makes: alice types the email
// address a claimed domain routes, and the identifier step named nobody. Tests
// that name a person copy it and set UserID.
var firstBind = Attempt{TenantID: testTenantID, FederationID: tenantFederationID, Identifier: typed}

// sessionBind is the same attempt for a person the identifier step already
// named. The Federation Link is still read first, so the two differ only in the
// fallback each one reaches.
var sessionBind = Attempt{
	TenantID: testTenantID, FederationID: tenantFederationID, UserID: testUserID, Identifier: typed,
}

// alice is the directory account every provisioning test binds as. It carries
// the six attributes the mapping reads, and nothing else.
var alice = Identity{
	DN:          "uid=alice,ou=people,dc=corp,dc=example",
	ExternalID:  "d3b07384d113edec49eaa6238ad5ff00",
	Username:    "alice",
	Email:       "alice@corp.example",
	FirstName:   "Alice",
	LastName:    "Adams",
	DisplayName: "Alice Adams",
}

// TestProvision covers the person one first bind creates. The row lands in the
// organization the federation names, the link holds the stable directory id, and
// the trail records that the sign-in created the person.
func TestProvision(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}})

	userID, err := svc.Provision(context.Background(), firstBind, alice)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if userID != createdUserID {
		t.Fatalf("the bind created %q, want %q", userID, createdUserID)
	}

	if len(people) != 1 {
		t.Fatalf("the bind wrote %d people, want one", len(people))
	}
	want := Person{
		TenantID: testTenantID, OrgID: testOrgID, Username: "alice",
		Email: "alice@corp.example", FirstName: "Alice", LastName: "Adams",
		DisplayName: "Alice Adams",
	}
	if people[0] != want {
		t.Errorf("the bind wrote %+v, want %+v", people[0], want)
	}

	if len(linked) != 1 {
		t.Fatalf("the bind wrote %d links, want one", len(linked))
	}
	// The link holds the stable id and never the username, so a username the
	// directory later changes does not orphan the person.
	if linked[0].ExternalID != alice.ExternalID {
		t.Errorf("the link holds %q, want the stable directory id", linked[0].ExternalID)
	}
	if linked[0].UserID != createdUserID || linked[0].FederationID != tenantFederationID {
		t.Errorf("the link ties %q to %q, want %q to %q",
			linked[0].UserID, linked[0].FederationID, createdUserID, tenantFederationID)
	}
	if linked[0].TenantID != testTenantID {
		t.Errorf("the link belongs to tenant %q, want %q", linked[0].TenantID, testTenantID)
	}
	if linked[0].CreatedAt.IsZero() {
		t.Error("the link carries no creation time")
	}

	if len(events) != 1 || events[0].Action != string(audit.ActionIdpLinked) {
		t.Fatalf("the trail holds %v, want one %s row", events, audit.ActionIdpLinked)
	}
	if events[0].ActorID != createdUserID || events[0].EntityID != tenantFederationID {
		t.Errorf("the trail names actor %q on %q, want %q on %q",
			events[0].ActorID, events[0].EntityID, createdUserID, tenantFederationID)
	}
	if !strings.Contains(events[0].Metadata, createdUserID) {
		t.Errorf("the trail recorded %q, want the person the bind created", events[0].Metadata)
	}
}

// TestProvisionUsesTheDefaultOrganization covers a tenant-wide federation. It
// belongs to no organization, so the column of its own names the one the people
// it creates land in: users.org_id is mandatory.
func TestProvisionUsesTheDefaultOrganization(t *testing.T) {
	row := storedFederation("")
	row.DefaultOrgID = otherOrgID
	svc := testService(t, deps{rows: []Federation{row}})

	if _, err := svc.Provision(context.Background(), firstBind, alice); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if len(people) != 1 || people[0].OrgID != otherOrgID {
		t.Fatalf("the bind wrote %+v, want the person in organization %s", people, otherOrgID)
	}
}

// TestProvisionWithoutAnOrganization covers a tenant-wide row that names no
// default organization. The service refuses to save one, so a row that reaches
// this was written around both it and the console, and it creates nobody.
func TestProvisionWithoutAnOrganization(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation("")}})

	_, err := svc.Provision(context.Background(), firstBind, alice)
	if !errors.Is(err, ErrNoOrganization) {
		t.Fatalf("err = %v, want ErrNoOrganization", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestProvisionWithoutAUsername covers a directory entry the federation read no
// username from. The person would hold no identifier to sign in with, so nobody
// is created.
func TestProvisionWithoutAUsername(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}})

	nameless := alice
	nameless.Username = ""

	_, err := svc.Provision(context.Background(), firstBind, nameless)
	if !errors.Is(err, ErrNoUsername) {
		t.Fatalf("err = %v, want ErrNoUsername", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestProvisionRefusesADisabledFederation covers a federation switched off, or soft
// deleted, between the bind and this write. Both behave alike, and neither
// creates anybody.
func TestProvisionRefusesADisabledFederation(t *testing.T) {
	off := storedFederation(testOrgID)
	off.State = StateInactive

	for name, d := range map[string]deps{
		"an inactive federation": {rows: []Federation{off}},
		"a deleted federation":   {},
	} {
		t.Run(name, func(t *testing.T) {
			svc := testService(t, d)

			_, err := svc.Provision(context.Background(), firstBind, alice)
			if !errors.Is(err, ErrDisabled) {
				t.Fatalf("err = %v, want ErrDisabled", err)
			}
			if len(people) != 0 || len(linked) != 0 {
				t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
			}
		})
	}
}

// TestProvisionLeavesNoHalfPerson covers a username another person of the tenant
// already holds. The create is refused, and the transaction leaves neither a
// person, nor a link, nor an audit row behind.
func TestProvisionLeavesNoHalfPerson(t *testing.T) {
	taken := errors.New("duplicate username")
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}, createFails: taken})

	_, err := svc.Provision(context.Background(), firstBind, alice)
	if !errors.Is(err, taken) {
		t.Fatalf("err = %v, want the refused create", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
	}
	if len(events) != 0 {
		t.Errorf("the trail holds %v, want nothing", events)
	}
}

// TestProvisionRollsTheLinkBack covers a link that could not be written. The
// person is rolled back with it, because a person with no link would sign in
// against a local password hash that does not exist.
func TestProvisionRollsTheLinkBack(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}})
	broken := errors.New("the link could not be written")
	svc.deps.WriteLink = func(context.Context, Link) error { return broken }

	if _, err := svc.Provision(context.Background(), firstBind, alice); !errors.Is(err, broken) {
		t.Fatalf("err = %v, want the failed link write", err)
	}
	if !rolledBack {
		t.Error("the failed link write left the person behind")
	}
}

// TestProvisionLogsNoCredential proves that nothing this write logs carries the
// bind password of the federation, or the identifier of the person. The row is
// read again here, and it holds the credential in the clear.
func TestProvisionLogsNoCredential(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}})

	if _, err := svc.Provision(context.Background(), firstBind, alice); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	for _, line := range logs.All() {
		read := fmt.Sprintf("%s %v", line.Message, line.ContextMap())
		if strings.Contains(read, theSecret) || strings.Contains(read, alice.Email) {
			t.Fatalf("a log line reads %q, want no credential and no identifier", read)
		}
	}
	for _, event := range events {
		if strings.Contains(fmt.Sprintf("%+v", event), theSecret) {
			t.Fatalf("an audit row reads %+v, want no bind password in it", event)
		}
	}
}

// aliceLink is the Federation Link the first bind of alice wrote. It holds the
// stable directory id and the person that bind created.
func aliceLink() Link {
	return Link{
		TenantID: testTenantID, FederationID: tenantFederationID,
		ExternalID: alice.ExternalID, UserID: personID,
	}
}

// TestPersonOfAnswersTheLinkedPerson covers every sign-in after the first one.
// The person types a User Principal Name that matches neither the username nor
// the email the first bind stored, so the identifier step found nobody. The
// Federation Link holds the stable directory id, and it names the person.
//
// Before this read, the empty session person read as a first bind, the create
// ran again, and uq_username refused it. The person was told for ever that the
// directory was unavailable.
func TestPersonOfAnswersTheLinkedPerson(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}, links: []Link{aliceLink()}})

	userID, err := svc.PersonOf(context.Background(), firstBind, alice)
	if err != nil {
		t.Fatalf("PersonOf: %v", err)
	}
	if userID != personID {
		t.Fatalf("the bind signed in %q, want the person the link holds, %q", userID, personID)
	}
	if len(people) != 0 || len(linked) != 0 || len(events) != 0 {
		t.Errorf("the second sign-in wrote %+v, %+v and %+v, want nothing", people, linked, events)
	}
}

// TestPersonOfAnswersOnePersonWhateverTheIdentifier covers the three forms one
// person signs in with: the bare username and the mapped email, which the
// identifier step matches, and an unmapped User Principal Name, which it does
// not. The Federation Link answers the same person for all three.
func TestPersonOfAnswersOnePersonWhateverTheIdentifier(t *testing.T) {
	cases := []struct {
		name    string
		session string
	}{
		{"the bare username the directory stored", personID},
		{"the mapped email the directory stored", personID},
		{"a User Principal Name the mapping never wrote", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := testService(t, deps{
				rows:  []Federation{storedFederation(testOrgID)},
				links: []Link{aliceLink()},
			})

			attempt := Attempt{
				TenantID:     testTenantID,
				FederationID: tenantFederationID,
				UserID:       c.session,
				Identifier:   typed,
			}

			userID, err := svc.PersonOf(context.Background(), attempt, alice)
			if err != nil {
				t.Fatalf("PersonOf: %v", err)
			}
			if userID != personID {
				t.Fatalf("the bind signed in %q, want %q", userID, personID)
			}
			if len(people) != 0 {
				t.Errorf("the sign-in wrote %+v, want no person", people)
			}
		})
	}
}

// TestPersonOfAnswersTheSessionPerson covers the local account a domain claim
// routed to a directory. The identifier step found them, they hold no Identity
// Link, and the bind writes none: the sign-in creates nobody.
func TestPersonOfAnswersTheSessionPerson(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}})

	userID, err := svc.PersonOf(context.Background(), sessionBind, alice)
	if err != nil {
		t.Fatalf("PersonOf: %v", err)
	}
	if userID != testUserID {
		t.Fatalf("the bind signed in %q, want the person the session names, %q", userID, testUserID)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the sign-in wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestPersonOfProvisionsWhenNoLinkHoldsTheExternalID covers the first bind. No
// link holds the stable id and the session names nobody, so this account belongs
// to somebody this gateway does not hold yet.
func TestPersonOfProvisionsWhenNoLinkHoldsTheExternalID(t *testing.T) {
	other := aliceLink()
	other.ExternalID = "a-stable-id-of-somebody-else"
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}, links: []Link{other}})

	userID, err := svc.PersonOf(context.Background(), firstBind, alice)
	if err != nil {
		t.Fatalf("PersonOf: %v", err)
	}
	if userID != createdUserID {
		t.Fatalf("the first bind created %q, want %q", userID, createdUserID)
	}
	if len(people) != 1 || len(linked) != 1 {
		t.Fatalf("the first bind wrote %+v and %+v, want one of each", people, linked)
	}
}

// TestPersonOfRefusesABrokenLinkRead covers the read that did not answer. The
// sign-in stops there. A read that failed says nothing about whether a link
// exists, and a create that ran on it would double the person.
func TestPersonOfRefusesABrokenLinkRead(t *testing.T) {
	svc := testService(t, deps{
		rows:          []Federation{storedFederation(testOrgID)},
		findLinkFails: errors.New("the database is down"),
	})

	if _, err := svc.PersonOf(context.Background(), firstBind, alice); err == nil {
		t.Fatal("PersonOf answered a person, want the failed read")
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused sign-in wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestPersonOfRefusesAnOffboardedLinkedPerson covers the person an administrator
// deactivated or soft deleted while their directory account still lives. The
// Federation Link still holds them, and the sign-in must refuse.
//
// The refusal says that the gateway cannot carry on. It is not a wrong password,
// because the password was proved, and a slug of its own would say which people
// the tenant holds.
func TestPersonOfRefusesAnOffboardedLinkedPerson(t *testing.T) {
	svc := testService(t, deps{
		rows:             []Federation{storedFederation(testOrgID)},
		links:            []Link{aliceLink()},
		personOffboarded: true,
	})

	_, err := svc.PersonOf(context.Background(), firstBind, alice)
	if !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused sign-in wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestProvisionRefusesAnAccountTheTenantHolds covers the first bind of somebody
// this gateway already holds in a state the identifier step reads as absent.
//
// Federation Resolution case 1 answers a claimed domain and returns before the
// read that would have caught them, so the sign-in reaches the bind naming
// nobody. Without this guard a soft-deleted person whose directory account still
// lives is created again as a brand-new active person, and the offboarding is
// undone: uq_username maps a NULL deleted_at to an epoch, so the username is
// free and the insert stands. A deactivated person trips that key instead and
// answers a 500 after the password was proved.
//
// The bind runs through PersonOf, which is the whole of case 1: no Identity
// Link, and no person the session names.
//
// A soft-deleted person and a deactivated person are one case here. Held filters
// neither the state nor the soft delete, so both answer true, and which of the
// two rows the tenant holds is what internal/user/repo_test.go proves of the
// read itself. What differs here is the form the row is held under, and each
// case names one, because one form alone would leave the others through.
//
// The refusal is ErrDirectory, and never a credential failure. The password was
// proved, and a slug of its own would say that the tenant holds a row for that
// identifier.
func TestProvisionRefusesAnAccountTheTenantHolds(t *testing.T) {
	for name, held := range map[string][]string{
		"held under the identifier the person typed": {typed},
		"held under the username of the entry":       {alice.Username},
		"held under the email of the entry":          {alice.Email},
	} {
		t.Run(name, func(t *testing.T) {
			svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}, held: held})

			_, err := svc.PersonOf(context.Background(), firstBind, alice)
			if !errors.Is(err, ErrDirectory) {
				t.Fatalf("err = %v, want ErrDirectory", err)
			}
			if len(people) != 0 || len(linked) != 0 {
				t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
			}
			if len(events) != 0 {
				t.Errorf("the trail holds %v, want nothing", events)
			}
		})
	}
}

// TestProvisionReadsTheTypedIdentifier covers a federation that maps no email
// attribute, and a directory username the local row does not hold. The person
// types the address the soft-deleted row carries, and that address is the only
// form that names them. A guard that read the entry alone would create them
// again.
func TestProvisionReadsTheTypedIdentifier(t *testing.T) {
	entry := alice
	entry.Username = "a.adams"
	entry.Email = ""

	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}, held: []string{typed}})

	_, err := svc.Provision(context.Background(), firstBind, entry)
	if !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestProvisionRefusesABrokenHeldRead covers the read that says whether the
// tenant already holds the account. A read that broke creates nobody: a first
// bind that carried on would write the person the read was there to refuse.
func TestProvisionRefusesABrokenHeldRead(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}, heldBroken: true})

	_, err := svc.Provision(context.Background(), firstBind, alice)
	if err == nil {
		t.Fatal("the broken read created a person, want a refusal")
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestProvisionLogsNoIdentifierOnARefusal proves that the refusal of an account
// the tenant already holds names the tenant and the federation, and never the
// identifier. The identifier is personal data, and the refusal is the one answer
// that would say the tenant holds a row for it.
func TestProvisionLogsNoIdentifierOnARefusal(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}, held: []string{alice.Username}})

	if _, err := svc.Provision(context.Background(), firstBind, alice); err == nil {
		t.Fatal("the held account was created, want a refusal")
	}
	for _, entry := range logs.All() {
		line := fmt.Sprint(entry.Message, entry.ContextMap())
		for _, secret := range []string{alice.Username, alice.Email, theSecret} {
			if strings.Contains(line, secret) {
				t.Errorf("a log line carries %q: %s", secret, line)
			}
		}
	}
}

// TestPersonOfRefusesAnEntryAnotherLinkNames covers a directory that gave one
// identifier to a second entry. The rename frees the old address, the directory
// hands it to somebody else, and the search of the next sign-in matches that
// second entry alone.
//
// The bind proves the password of the second entry, and the Federation Link read
// misses on its stable id. The person the session names holds a link with this
// federation already, and that link names the first entry. The bind proved
// somebody else, so the sign-in stops.
//
// The refusal is ErrDirectory, and never a credential failure. The password was
// proved, and a slug of its own would say which people the tenant holds.
func TestPersonOfRefusesAnEntryAnotherLinkNames(t *testing.T) {
	svc := testService(t, deps{
		rows:   []Federation{storedFederation(testOrgID)},
		linked: []string{tenantFederationID},
	})

	_, err := svc.PersonOf(context.Background(), sessionBind, alice)
	if !errors.Is(err, ErrDirectory) {
		t.Fatalf("err = %v, want ErrDirectory", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused sign-in wrote %+v and %+v, want nothing", people, linked)
	}
	if len(events) != 0 {
		t.Errorf("the trail holds %v, want nothing", events)
	}
}

// TestPersonOfAnswersTheSessionPersonLinkedElsewhere covers the documented
// fallback of a person who holds a link with another federation. The link of this
// federation is the one that must name the proved entry, and the person holds
// none, so the session person still answers.
func TestPersonOfAnswersTheSessionPersonLinkedElsewhere(t *testing.T) {
	svc := testService(t, deps{
		rows:   []Federation{storedFederation(testOrgID)},
		linked: []string{otherFederationID},
	})

	userID, err := svc.PersonOf(context.Background(), sessionBind, alice)
	if err != nil {
		t.Fatalf("PersonOf: %v", err)
	}
	if userID != testUserID {
		t.Fatalf("the bind signed in %q, want the person the session names, %q", userID, testUserID)
	}
}

// TestPersonOfRefusesABrokenLinkedRead covers the read of the links the session
// person holds. A read that did not answer says nothing about whether the person
// is linked to this federation, so the sign-in stops there.
func TestPersonOfRefusesABrokenLinkedRead(t *testing.T) {
	svc := testService(t, deps{rows: []Federation{storedFederation(testOrgID)}})
	broken := errors.New("the database is down")
	svc.deps.Linked = func(context.Context, string, string) ([]string, error) { return nil, broken }

	if _, err := svc.PersonOf(context.Background(), sessionBind, alice); !errors.Is(err, broken) {
		t.Fatalf("err = %v, want the failed read", err)
	}
}
