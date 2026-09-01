package identityprovider

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
// organization the provider names, the link holds the stable directory id, and
// the trail records that the sign-in created the person.
func TestProvision(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{storedProvider(testOrgID)}})

	userID, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, alice)
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
	if linked[0].UserID != createdUserID || linked[0].IdpID != tenantIdpID {
		t.Errorf("the link ties %q to %q, want %q to %q",
			linked[0].UserID, linked[0].IdpID, createdUserID, tenantIdpID)
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
	if events[0].ActorID != createdUserID || events[0].EntityID != tenantIdpID {
		t.Errorf("the trail names actor %q on %q, want %q on %q",
			events[0].ActorID, events[0].EntityID, createdUserID, tenantIdpID)
	}
	if !strings.Contains(events[0].Metadata, createdUserID) {
		t.Errorf("the trail recorded %q, want the person the bind created", events[0].Metadata)
	}
}

// TestProvisionUsesTheDefaultOrganization covers a tenant-wide provider. It
// belongs to no organization, so the column of its own names the one the people
// it creates land in: users.org_id is mandatory.
func TestProvisionUsesTheDefaultOrganization(t *testing.T) {
	row := storedProvider("")
	row.DefaultOrgID = otherOrgID
	svc := testService(t, deps{rows: []Provider{row}})

	if _, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, alice); err != nil {
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
	svc := testService(t, deps{rows: []Provider{storedProvider("")}})

	_, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, alice)
	if !errors.Is(err, ErrNoOrganization) {
		t.Fatalf("err = %v, want ErrNoOrganization", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestProvisionWithoutAUsername covers a directory entry the provider read no
// username from. The person would hold no identifier to sign in with, so nobody
// is created.
func TestProvisionWithoutAUsername(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{storedProvider(testOrgID)}})

	nameless := alice
	nameless.Username = ""

	_, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, nameless)
	if !errors.Is(err, ErrNoUsername) {
		t.Fatalf("err = %v, want ErrNoUsername", err)
	}
	if len(people) != 0 || len(linked) != 0 {
		t.Errorf("the refused bind wrote %+v and %+v, want nothing", people, linked)
	}
}

// TestProvisionRefusesADisabledProvider covers a provider switched off, or soft
// deleted, between the bind and this write. Both behave alike, and neither
// creates anybody.
func TestProvisionRefusesADisabledProvider(t *testing.T) {
	off := storedProvider(testOrgID)
	off.State = StateInactive

	for name, d := range map[string]deps{
		"an inactive provider": {rows: []Provider{off}},
		"a deleted provider":   {},
	} {
		t.Run(name, func(t *testing.T) {
			svc := testService(t, d)

			_, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, alice)
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
	svc := testService(t, deps{rows: []Provider{storedProvider(testOrgID)}, createFails: taken})

	_, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, alice)
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
	svc := testService(t, deps{rows: []Provider{storedProvider(testOrgID)}})
	broken := errors.New("the link could not be written")
	svc.deps.WriteLink = func(context.Context, Link) error { return broken }

	if _, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, alice); !errors.Is(err, broken) {
		t.Fatalf("err = %v, want the failed link write", err)
	}
	if !rolledBack {
		t.Error("the failed link write left the person behind")
	}
}

// TestProvisionLogsNoCredential proves that nothing this write logs carries the
// bind password of the provider, or the identifier of the person. The row is
// read again here, and it holds the credential in the clear.
func TestProvisionLogsNoCredential(t *testing.T) {
	svc := testService(t, deps{rows: []Provider{storedProvider(testOrgID)}})

	if _, err := svc.Provision(context.Background(), testTenantID, tenantIdpID, alice); err != nil {
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
