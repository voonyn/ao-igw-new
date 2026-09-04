package userfederation

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap/zaptest/observer"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/platform/logger"
	"alphaomega/identitygateway/internal/tenant"
)

// admin is the person every service test acts as.
var admin = Actor{TenantID: testTenantID, UserID: testUserID, IP: "203.0.113.7", UserAgent: "a-browser"}

// theSecret is the bind password every test writes. No answer and no log line is
// allowed to carry it.
const theSecret = "a-directory-secret"

// body is a valid LDAPS write. Each test changes the one field it is about.
func body() Body {
	secret := theSecret
	return Body{
		OrgID: testOrgID, Name: "Head office", State: StateActive,
		Mode: ModeLDAPS, Servers: []string{"ldaps://dc1.corp.example:636"}, TimeoutSeconds: 5,
		BindDN: "cn=svc,dc=corp,dc=example", BindPassword: &secret,
		BaseDN: "dc=corp,dc=example", UserObjectClasses: []string{"inetOrgPerson"},
		UserFilters: []string{"uid"},
		AttrID:      "objectGUID", AttrUsername: "sAMAccountName", AttrEmail: "mail",
		Domains: []string{"Corp.Example"},
	}
}

// storedFederation is the row the fake repository answers reads with. It carries
// the opened bind password, the way the repository hands it up.
func storedFederation(orgID string) Federation {
	return Federation{
		ID: tenantFederationID, TenantID: testTenantID, OrgID: orgID, Name: "Head office",
		Type: TypeDirectory, State: StateActive, Mode: ModeLDAPS,
		Servers: []string{"ldaps://dc1.corp.example:636"}, TimeoutMS: 5000,
		BindDN: "cn=svc,dc=corp,dc=example", BindPassword: theSecret,
		BaseDN: "dc=corp,dc=example", UserObjectClasses: []string{"inetOrgPerson"},
		UserFilters: []string{"uid"}, AttrID: "objectGUID",
		AttrUsername: "sAMAccountName", AttrEmail: "mail",
	}
}

// TestListRefusesPersonWithoutAdminRole refuses a person who administers
// nothing. The bearer guard admits any token minted for the admin resource, so
// the roles decide here.
func TestListRefusesPersonWithoutAdminRole(t *testing.T) {
	svc := testService(t, deps{})

	if _, err := svc.List(context.Background(), admin); !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("err = %v, want ErrNotAdmin", err)
	}
}

// TestNoAnswerCarriesTheBindPassword proves the credential is write-only. The
// repository opens it for the sign-in bind, and every view drops it.
func TestNoAnswerCarriesTheBindPassword(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{storedFederation(testOrgID)},
	})

	view, err := svc.Find(context.Background(), admin, tenantFederationID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", view), theSecret) {
		t.Fatalf("the view reads %+v, want no bind password in it", view)
	}
	if !view.BindPasswordSet {
		t.Errorf("the view reports no stored credential, want the flag set")
	}

	views, err := svc.List(context.Background(), admin)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if strings.Contains(fmt.Sprintf("%+v", views), theSecret) {
		t.Fatalf("the list reads %+v, want no bind password in it", views)
	}
}

// TestNoLogLineCarriesTheBindPassword walks every line a full write wrote. A
// credential never reaches a log line, at any level.
func TestNoLogLineCarriesTheBindPassword(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{storedFederation(testOrgID)},
	})
	ctx := context.Background()

	if _, err := svc.Create(ctx, admin, body()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Update(ctx, admin, tenantFederationID, body()); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if _, err := svc.Find(ctx, admin, tenantFederationID); err != nil {
		t.Fatalf("Find: %v", err)
	}

	for _, line := range logs.All() {
		if strings.Contains(fmt.Sprintf("%s %v", line.Message, line.ContextMap()), theSecret) {
			t.Fatalf("a log line reads %q, want no bind password in it", line.Message)
		}
	}
	for _, event := range events {
		if strings.Contains(fmt.Sprintf("%+v", event), theSecret) {
			t.Fatalf("an audit row reads %+v, want no bind password in it", event)
		}
	}
}

// TestCreateRefusesATenantWideFederationFromAnOrgOwner covers the level gate. A
// tenant-wide federation serves every organization, so a tenant manager writes it.
func TestCreateRefusesATenantWideFederationFromAnOrgOwner(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	write := body()
	write.OrgID, write.DefaultOrgID = "", testOrgID
	if _, err := svc.Create(context.Background(), admin, write); !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(written) != 0 {
		t.Errorf("the refused create wrote %+v, want nothing", written)
	}
}

// TestCreateClaimsTheDomainsAndRecordsTheEvent covers one whole create: the row,
// the lowercased claims, and the audit event on the same transaction.
func TestCreateClaimsTheDomainsAndRecordsTheEvent(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
	})

	view, err := svc.Create(context.Background(), admin, body())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(written) != 1 || written[0].OrgID != testOrgID || written[0].Type != TypeDirectory {
		t.Fatalf("the create wrote %+v, want one LDAP row of %s", written, testOrgID)
	}
	if written[0].BindPassword != theSecret {
		t.Errorf("the row carries %q, want the credential the body sent", written[0].BindPassword)
	}
	if len(claimed) != 1 || claimed[0] != "corp.example" {
		t.Errorf("the create claimed %v, want the lowercased domain", claimed)
	}
	if len(events) != 1 || events[0].Action != string(audit.ActionIdpCreated) {
		t.Fatalf("the create recorded %+v, want one idp.created", events)
	}
	if view.TimeoutSeconds != 5 || len(view.Domains) != 1 {
		t.Errorf("the view reads %+v, want the timeout and the claim it wrote", view)
	}
}

// TestCreateRefusesAServerThatDoesNotMatchTheTransport covers the scheme check.
// The egress precedent of this repo checks no scheme at all, so this one is
// written out and proved.
func TestCreateRefusesAServerThatDoesNotMatchTheTransport(t *testing.T) {
	cases := []struct {
		name   string
		mode   int
		server string
		valid  bool
	}{
		{"LDAPS over its own scheme", ModeLDAPS, "ldaps://dc1.corp.example:636", true},
		{"LDAPS over the plaintext scheme", ModeLDAPS, "ldap://dc1.corp.example:389", false},
		{"StartTLS over the plaintext scheme", ModeStartTLS, "ldap://dc1.corp.example:389", true},
		{"StartTLS over the LDAPS scheme", ModeStartTLS, "ldaps://dc1.corp.example:636", false},
		{"a plain bind", ModePlain, "ldap://dc1.corp.example:389", true},
		{"a scheme nobody dials", ModeLDAPS, "https://dc1.corp.example", false},
	}

	for _, c := range cases {
		svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})
		write := body()
		write.Mode, write.Servers, write.ConfirmPlaintext = c.mode, []string{c.server}, true

		_, err := svc.Create(context.Background(), admin, write)
		if c.valid && err != nil {
			t.Errorf("%s reads %v, want a valid write", c.name, err)
		}
		if !c.valid && !errors.Is(err, ErrServerScheme) {
			t.Errorf("%s reads %v, want ErrServerScheme", c.name, err)
		}
	}
}

// TestCreateLeavesNothingBehindWhenADomainIsClaimed covers the refusal and the
// rollback. The row and the claim land on one transaction, so a refused claim
// takes the federation with it.
func TestCreateLeavesNothingBehindWhenADomainIsClaimed(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		claimTaken:  true,
	})

	_, err := svc.Create(context.Background(), admin, body())
	if !errors.Is(err, ErrDomainClaimed) {
		t.Fatalf("err = %v, want ErrDomainClaimed", err)
	}
	if !rolledBack || len(written) != 0 {
		t.Errorf("the refused create left %+v behind, want the transaction rolled back", written)
	}
}

// TestUpdateKeepsTheStoredCredentialWhenTheBodyOmitsIt covers the write-only
// rule: absent keeps, empty clears, and a value replaces.
func TestUpdateKeepsTheStoredCredentialWhenTheBodyOmitsIt(t *testing.T) {
	cases := []struct {
		name string
		sent *string
		want string
	}{
		{"an absent field keeps the stored credential", nil, theSecret},
		{"an empty string clears it", ptr(""), ""},
		{"a value replaces it", ptr("a-new-secret"), "a-new-secret"},
	}

	for _, c := range cases {
		svc := testService(t, deps{
			tenantRoles: []string{tenant.RoleIAMOwner},
			rows:        []Federation{storedFederation(testOrgID)},
		})

		write := body()
		write.BindPassword = c.sent
		if _, err := svc.Update(context.Background(), admin, tenantFederationID, write); err != nil {
			t.Fatalf("%s: Update: %v", c.name, err)
		}
		if len(updated) != 1 || updated[0].BindPassword != c.want {
			t.Errorf("%s wrote %q, want %q", c.name, updated[0].BindPassword, c.want)
		}
	}
}

// TestUpdateRefusesAMoveBetweenLevels covers the fixed level. A federation that
// moved would relocate every person the next bind creates.
func TestUpdateRefusesAMoveBetweenLevels(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{storedFederation(testOrgID)},
	})

	write := body()
	write.OrgID, write.DefaultOrgID = "", testOrgID
	if _, err := svc.Update(context.Background(), admin, tenantFederationID, write); !errors.Is(err, ErrLevelFixed) {
		t.Fatalf("err = %v, want ErrLevelFixed", err)
	}
	if len(updated) != 0 {
		t.Errorf("the refused update wrote %+v, want nothing", updated)
	}
}

// TestDeleteRecordsTheEvent covers the soft delete and the trail beside it.
func TestDeleteRecordsTheEvent(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{storedFederation(testOrgID)},
	})

	if err := svc.Delete(context.Background(), admin, tenantFederationID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != tenantFederationID {
		t.Fatalf("the delete removed %v, want %s", deleted, tenantFederationID)
	}
	if len(events) != 1 || events[0].Action != string(audit.ActionIdpDeleted) {
		t.Errorf("the delete recorded %+v, want one idp.deleted", events)
	}
}

// TestFindReportsAMiss answers ErrNotFound for an id nobody holds, which is what
// a soft-deleted federation reads as.
func TestFindReportsAMiss(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	if _, err := svc.Find(context.Background(), admin, deadFederationID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

// TestUnlinkRecordsTheEventAndNamesThePerson covers the unlink. The link is hard
// deleted, so the audit row is the only record that the tie ever existed.
func TestUnlinkRecordsTheEventAndNamesThePerson(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		userOrg:     testOrgID,
		hasPassword: true,
		links:       []Link{{TenantID: testTenantID, FederationID: tenantFederationID, ExternalID: "a-stable-guid", UserID: personID}},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantFederationID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if len(unlinked) != 1 || unlinked[0] != personID {
		t.Fatalf("the unlink removed %v, want the link of %s", unlinked, personID)
	}
	if len(events) != 1 || events[0].Action != string(audit.ActionIdpUnlinked) {
		t.Fatalf("the unlink recorded %+v, want one idp.unlinked", events)
	}
	if !strings.Contains(events[0].Metadata, personID) {
		t.Errorf("the event reads %s, want the person named in the metadata", events[0].Metadata)
	}
}

// TestUnlinkRefusesAnOrgOwnerOfAnotherOrganization covers the write gate of the
// unlink. The organization of the person decides, not the one of the federation.
func TestUnlinkRefusesAnOrgOwnerOfAnotherOrganization(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: otherOrgID, Roles: []string{organization.RoleOrgOwner}}},
		userOrg:     testOrgID,
	})

	err := svc.Unlink(context.Background(), admin, personID, tenantFederationID)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if len(unlinked) != 0 {
		t.Errorf("the refused unlink removed %v, want nothing", unlinked)
	}
}

// TestLinksReportAMissingPerson covers the tenant scope of the link routes. A
// person the tenant does not hold answers a miss, never an empty list.
func TestLinksReportAMissingPerson(t *testing.T) {
	svc := testService(t, deps{tenantRoles: []string{tenant.RoleIAMOwner}})

	if _, err := svc.Links(context.Background(), admin, personID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("err = %v, want ErrUserNotFound", err)
	}
}

// TestAFederationThatMapsNoEmailAttribute covers a directory that publishes no
// mail attribute. The id keys the Federation Link and the username keys the
// person, so the third identifier is optional: a create stores the empty value,
// the answer carries it, and an update clears a stored one.
func TestAFederationThatMapsNoEmailAttribute(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: []string{tenant.RoleIAMOwner},
		rows:        []Federation{storedFederation(testOrgID)},
	})
	ctx := context.Background()

	noEmail := body()
	noEmail.AttrEmail = ""

	created, err := svc.Create(ctx, admin, noEmail)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.AttrEmail != "" {
		t.Errorf("the created federation maps %q, want no email attribute", created.AttrEmail)
	}
	if len(written) != 1 || written[0].AttrEmail != "" {
		t.Fatalf("the create wrote %+v, want a row with no email attribute", written)
	}

	// The stored row maps "mail", so this update clears it.
	changed, err := svc.Update(ctx, admin, tenantFederationID, noEmail)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if changed.AttrEmail != "" {
		t.Errorf("the updated federation maps %q, want the stored one cleared", changed.AttrEmail)
	}
	if len(updated) != 1 || updated[0].AttrEmail != "" {
		t.Fatalf("the update wrote %+v, want a row with no email attribute", updated)
	}
}

// What the fake repository answers with.
type deps struct {
	tenantRoles []string
	memberships []organization.Membership
	rows        []Federation
	links       []Link
	userOrg     string
	claimTaken  bool

	// localOwners is the IAM_OWNERs the local password compare still signs in.
	// An empty list is a tenant with none, which the first guard rail leaves
	// alone. hasPassword is what the person one unlink names holds.
	//
	// linked is the federations that still sign that person in. It is not links: a
	// link with a federation that is inactive or soft deleted is listed and signs
	// nobody in.
	localOwners []tenant.LocalOwner
	hasPassword bool
	linked      []string

	// moves is the people of the tenant the claim preview reads. The fake below
	// filters them by the domain of their address and caps the page the way the
	// query does, so a test proves the answer and not the passthrough.
	// movesBroken breaks the read instead, which is what a database that did not
	// answer does.
	moves       []tenant.DomainPerson
	movesBroken bool

	// What the person creator of a first bind answers. A test that sets it
	// refuses the create, which is what a username another person of the tenant
	// already holds does.
	createFails error

	// What the Federation Link read of a sign-in answers. A test that sets it
	// breaks the read, which is what a database that did not answer does.
	findLinkFails error

	// Whether the person one Federation Link names can still sign in. A test that
	// sets it offboards them, which is what a deactivated row and a soft-deleted
	// row both do.
	personOffboarded bool

	// The identifiers the tenant already holds an account for, whatever its
	// state and soft-deleted rows included. A test that names one here holds an
	// offboarded person whose directory account still lives, so the first bind
	// of that account creates nobody. heldBroken breaks the read instead, which
	// is what a database that did not answer does.
	held       []string
	heldBroken bool

	// The connection test budget and the sign-in bind budget. A test that sets
	// none of the three fields runs with a budget that allows everything and
	// that takes every refund. releaseBroken breaks the refund alone, which is
	// what a Redis that answered the spend and then went down does.
	budgetSpent   bool
	budgetBroken  bool
	releaseBroken bool
}

// What the writes of one test did. testService clears them, and the tests of one
// package run one after another, so each test reads its own writes.
var (
	written      []Federation
	updated      []Federation
	deleted      []string
	claimed      []string
	unlinked     []string
	people       []Person
	linked       []Link
	events       []audit.Event
	rolledBack   bool
	spends       int
	spentKeys    []string
	releases     int
	releasedKeys []string
	logs         *observer.ObservedLogs
)

func testService(t *testing.T, d deps) *Service {
	t.Helper()
	var log logger.Logger
	log, logs = logger.NewObserved()
	written, updated, deleted, claimed, unlinked, events, rolledBack = nil, nil, nil, nil, nil, nil, false
	people, linked = nil, nil
	spends, spentKeys = 0, nil
	releases, releasedKeys = 0, nil

	countWrites := func() int {
		return len(written) + len(updated) + len(deleted) + len(claimed) +
			len(unlinked) + len(people) + len(linked)
	}

	return NewService(Deps{
		Insert: func(_ context.Context, row Federation) error {
			written = append(written, row)
			return nil
		},
		Update: func(_ context.Context, row Federation) error {
			updated = append(updated, row)
			return nil
		},
		Delete: func(_ context.Context, _, federationID string) error {
			deleted = append(deleted, federationID)
			return nil
		},
		Claim: func(_ context.Context, _, _ string, domains []string) error {
			if d.claimTaken {
				return fmt.Errorf("%w: corp.example", ErrDomainClaimed)
			}
			claimed = append(claimed, domains...)
			return nil
		},
		DeleteLink: func(_ context.Context, _, _, userID string) error {
			unlinked = append(unlinked, userID)
			return nil
		},
		CreatePerson: func(_ context.Context, p Person) (string, error) {
			if d.createFails != nil {
				return "", d.createFails
			}
			people = append(people, p)
			return createdUserID, nil
		},
		WriteLink: func(_ context.Context, row Link) error {
			linked = append(linked, row)
			return nil
		},
		CanSignIn: func(context.Context, string, string) (bool, error) {
			return !d.personOffboarded, nil
		},
		Held: func(_ context.Context, _, identifier string) (bool, error) {
			if d.heldBroken {
				return false, errors.New("the database is down")
			}
			return slices.Contains(d.held, identifier), nil
		},
		FindLink: func(_ context.Context, _, federationID, externalID string) (string, error) {
			if d.findLinkFails != nil {
				return "", d.findLinkFails
			}
			for _, row := range d.links {
				if row.FederationID == federationID && row.ExternalID == externalID {
					return row.UserID, nil
				}
			}
			return "", ErrLinkNotFound
		},
		// The unit of work either commits whole or leaves nothing behind, so a
		// failed step clears what the earlier steps wrote.
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			before := countWrites()
			err := fn(ctx)
			if err != nil && countWrites() != before {
				written, updated, deleted, claimed, unlinked = nil, nil, nil, nil, nil
				people, linked = nil, nil
				rolledBack = true
			}
			return err
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			events = append(events, e)
			return nil
		}, log),
		List: func(context.Context, string) ([]Federation, error) { return d.rows, nil },
		Find: func(_ context.Context, _, federationID string) (Federation, error) {
			for _, row := range d.rows {
				if row.ID == federationID {
					return row, nil
				}
			}
			return Federation{}, ErrNotFound
		},
		Domains: func(context.Context, string, []string) ([]Domain, error) { return nil, nil },
		Links:   func(context.Context, string, string) ([]Link, error) { return d.links, nil },
		Linked:  func(context.Context, string, string) ([]string, error) { return d.linked, nil },
		Org: func(_ context.Context, _, orgID string) (organization.Organization, error) {
			if orgID == testOrgID || orgID == otherOrgID {
				return organization.Organization{ID: orgID, TenantID: testTenantID}, nil
			}
			return organization.Organization{}, organization.ErrNotFound
		},
		UserOrg: func(context.Context, string, string) (string, error) {
			if d.userOrg == "" {
				return "", ErrUserNotFound
			}
			return d.userOrg, nil
		},
		Allow: func(_ context.Context, key string, _ int, _ time.Duration) (bool, error) {
			if d.budgetBroken {
				return false, errors.New("the cache is down")
			}
			spends++
			spentKeys = append(spentKeys, key)
			return !d.budgetSpent, nil
		},
		Release: func(_ context.Context, key string) error {
			if d.releaseBroken {
				return errors.New("the cache is down")
			}
			releases++
			releasedKeys = append(releasedKeys, key)
			return nil
		},
		LocalOwners: func(context.Context, string) ([]tenant.LocalOwner, error) {
			return d.localOwners, nil
		},
		PeopleAtDomains: func(
			_ context.Context, _ string, claimed []string, limit int,
		) ([]tenant.DomainPerson, int, error) {
			if d.movesBroken {
				return nil, 0, errors.New("the database is down")
			}
			var hit []tenant.DomainPerson
			for _, person := range d.moves {
				// Both forms, the way the query reads them: the address the
				// tenant holds, and the identifier the person types.
				if slices.Contains(claimed, emailDomain(person.Email)) ||
					slices.Contains(claimed, emailDomain(person.Username)) {
					hit = append(hit, person)
				}
			}
			total := len(hit)
			if len(hit) > limit {
				hit = hit[:limit]
			}
			return hit, total, nil
		},
		HasPassword: func(context.Context, string, string) (bool, error) { return d.hasPassword, nil },
		TenantRoles: func(context.Context, string, string) ([]string, error) { return d.tenantRoles, nil },
		Memberships: func(context.Context, string, string) ([]organization.Membership, error) {
			return d.memberships, nil
		},
		Log: log,
	})
}

func ptr[T any](v T) *T { return &v }
