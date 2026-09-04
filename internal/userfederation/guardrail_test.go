package userfederation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/organization"
	"alphaomega/identitygateway/internal/tenant"
)

// The two owners the guard rail tests read. One of them carries an address in
// the domain the write claims, and one does not.
var (
	claimedOwner = tenant.LocalOwner{UserID: testUserID, Email: "owner@corp.example"}
	safeOwner    = tenant.LocalOwner{UserID: personID, Email: "second@acme.test"}
)

// ownerRoles is the caller of every test here: a tenant manager, who writes a
// federation at either level.
func ownerRoles() []string { return []string{tenant.RoleIAMOwner} }

// TestCreateRefusesAClaimThatTakesTheLastLocalOwner covers the first guard rail
// of docs/specs/0002-directory-sign-in.md at the domain claim.
//
// Federation Resolution case 1 outranks case 3, so the claim routes every person
// whose email address carries corp.example to the directory, the people who hold
// a local password included. The only local owner of the tenant is one of them.
func TestCreateRefusesAClaimThatTakesTheLastLocalOwner(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		localOwners: []tenant.LocalOwner{claimedOwner},
	})

	_, err := svc.Create(context.Background(), admin, body())
	if !errors.Is(err, tenant.ErrLastLocalOwner) {
		t.Fatalf("err = %v, want tenant.ErrLastLocalOwner", err)
	}
	if len(written) != 0 || len(claimed) != 0 {
		t.Errorf("a refused create wrote %+v and claimed %v, want nothing", written, claimed)
	}
}

// TestCreateAllowsAClaimThatLeavesALocalOwner covers the other side of the same
// rail. One owner keeps an address the claim does not name, so the tenant keeps
// an administrator that no directory outage takes.
func TestCreateAllowsAClaimThatLeavesALocalOwner(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		localOwners: []tenant.LocalOwner{claimedOwner, safeOwner},
	})

	if _, err := svc.Create(context.Background(), admin, body()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(claimed) != 1 || claimed[0] != "corp.example" {
		t.Errorf("the create claimed %v, want the one domain of the body", claimed)
	}
}

// TestCreateIgnoresTheRailForATenantWithNoLocalOwner covers a tenant whose
// owners a directory already proves. There is no local owner left to protect, so
// a refusal would only trap the administrator who is registering the directory.
func TestCreateIgnoresTheRailForATenantWithNoLocalOwner(t *testing.T) {
	svc := testService(t, deps{tenantRoles: ownerRoles()})

	if _, err := svc.Create(context.Background(), admin, body()); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(written) != 1 {
		t.Errorf("the create wrote %d federations, want one", len(written))
	}
}

// TestAnInactiveFederationClaimsNobody covers the state the write stores. An
// inactive federation routes nobody, so its claim takes no owner and the rail says
// nothing. This is how an administrator prepares a directory before they switch
// it on.
func TestAnInactiveFederationClaimsNobody(t *testing.T) {
	off := body()
	off.State = StateInactive
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		localOwners: []tenant.LocalOwner{claimedOwner},
	})

	if _, err := svc.Create(context.Background(), admin, off); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(written) != 1 {
		t.Errorf("the create wrote %d federations, want one", len(written))
	}
}

// TestUpdateRefusesAClaimThatTakesTheLastLocalOwner covers the same rail on the
// update. A federation switched on with a claim ties the same people the create
// would.
func TestUpdateRefusesAClaimThatTakesTheLastLocalOwner(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		rows:        []Federation{storedFederation(testOrgID)},
		localOwners: []tenant.LocalOwner{claimedOwner},
	})

	_, err := svc.Update(context.Background(), admin, tenantFederationID, body())
	if !errors.Is(err, tenant.ErrLastLocalOwner) {
		t.Fatalf("err = %v, want tenant.ErrLastLocalOwner", err)
	}
	if len(updated) != 0 || len(claimed) != 0 {
		t.Errorf("a refused update wrote %+v and claimed %v, want nothing", updated, claimed)
	}
}

// TestUnlinkRefusesTheLastLinkOfAPersonWithNoPassword covers the second guard
// rail. The person holds a NULL password hash, so the link is the whole of their
// credential, and the removal locks them out for ever.
func TestUnlinkRefusesTheLastLinkOfAPersonWithNoPassword(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		userOrg:     testOrgID,
		links:       []Link{{TenantID: testTenantID, FederationID: tenantFederationID, UserID: personID}},
		linked:      []string{tenantFederationID},
	})

	err := svc.Unlink(context.Background(), admin, personID, tenantFederationID)
	if !errors.Is(err, ErrLastLink) {
		t.Fatalf("err = %v, want ErrLastLink", err)
	}
	if len(unlinked) != 0 {
		t.Errorf("a refused unlink removed %v, want nothing", unlinked)
	}
}

// TestUnlinkAllowsAPersonWhoHoldsAPassword covers the other side of the rail.
// The local password compare still signs that person in, so the removal leaves
// them a way in.
func TestUnlinkAllowsAPersonWhoHoldsAPassword(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		userOrg:     testOrgID,
		hasPassword: true,
		links:       []Link{{TenantID: testTenantID, FederationID: tenantFederationID, UserID: personID}},
		linked:      []string{tenantFederationID},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantFederationID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if len(unlinked) != 1 {
		t.Errorf("the unlink removed %v, want the one link", unlinked)
	}
}

// TestUnlinkAllowsOneLinkOfTwo covers a person tied to two directories. The
// second link is still a way in, so the removal of the first stands.
func TestUnlinkAllowsOneLinkOfTwo(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		userOrg:     testOrgID,
		links: []Link{
			{TenantID: testTenantID, FederationID: tenantFederationID, UserID: personID},
			{TenantID: testTenantID, FederationID: orgFederationID, UserID: personID},
		},
		linked: []string{orgFederationID, tenantFederationID},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantFederationID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if len(unlinked) != 1 {
		t.Errorf("the unlink removed %v, want the one link", unlinked)
	}
}

// TestUnlinkLeavesTheMissToTheDelete covers a federation the person holds no link
// with. The rail must not turn that into a refusal of its own: DeleteLink
// answers the miss, and the route answers not_found.
func TestUnlinkLeavesTheMissToTheDelete(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		userOrg:     testOrgID,
		links:       []Link{{TenantID: testTenantID, FederationID: orgFederationID, UserID: personID}},
		linked:      []string{orgFederationID},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantFederationID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
}

// TestUnlinkAllowsTheLinkOfADeadFederation covers the rail against the third one.
// The person is tied to a federation that is inactive or soft deleted, so nothing
// signs them in already, and a refusal would only trap the administrator who is
// moving them off a directory that is gone for good.
func TestUnlinkAllowsTheLinkOfADeadFederation(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		userOrg:     testOrgID,
		links:       []Link{{TenantID: testTenantID, FederationID: tenantFederationID, UserID: personID}},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantFederationID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if len(unlinked) != 1 {
		t.Errorf("the unlink removed %v, want the one link", unlinked)
	}
}

// TestErrLastLinkMaps covers the slug of the second guard rail. The console
// branches on it and says why the removal cannot happen.
func TestErrLastLinkMaps(t *testing.T) {
	app := fiber.New()
	app.Get("/", func(c fiber.Ctx) error {
		return response.Fail(c, fmt.Errorf("delete federation link: %w", ErrLastLink))
	})

	res, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/", nil))
	if err != nil {
		t.Fatalf("run request: %v", err)
	}
	defer res.Body.Close() //nolint:errcheck

	if res.StatusCode != fiber.StatusConflict {
		t.Errorf("status is %d, want %d", res.StatusCode, fiber.StatusConflict)
	}

	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatalf("decode the answer: %v", err)
	}
	if body.Error != "last_federation_link" {
		t.Errorf("the answer carries the slug %q, want last_federation_link", body.Error)
	}
}

// TestTheRailRunsOnTheSaveAndNotOnTheConnectionTest covers one body against both
// paths. The claim takes the last local owner, so the save is refused. The test
// dials, binds and searches, and it reads no domain, so it runs.
func TestTheRailRunsOnTheSaveAndNotOnTheConnectionTest(t *testing.T) {
	write := body()
	write.Mode, write.Servers = ModePlain, []string{"ldap://" + closedPort(t)}
	write.ConfirmPlaintext = true

	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		localOwners: []tenant.LocalOwner{claimedOwner},
	})
	if _, err := svc.Create(context.Background(), admin, write); !errors.Is(err, tenant.ErrLastLocalOwner) {
		t.Fatalf("Create err = %v, want tenant.ErrLastLocalOwner", err)
	}

	svc = testService(t, deps{
		tenantRoles: ownerRoles(),
		localOwners: []tenant.LocalOwner{claimedOwner},
	})
	got, err := svc.Test(context.Background(), admin, "", &write)
	if err != nil {
		t.Fatalf("Test: %v", err)
	}
	if got.OK || got.Stage != StageDial {
		t.Fatalf("Test = %+v, want a failure at %s", got, StageDial)
	}
}

// TestTheConnectionTestStillChecksTheTransport covers what the split keeps. The
// body names a server whose scheme the mode does not carry, so the test is
// refused before it dials.
func TestTheConnectionTestStillChecksTheTransport(t *testing.T) {
	write := body()
	write.Mode, write.Servers = ModeLDAPS, []string{"ldap://dc1.corp.example:389"}

	svc := testService(t, deps{tenantRoles: ownerRoles()})
	if _, err := svc.Test(context.Background(), admin, "", &write); !errors.Is(err, ErrServerScheme) {
		t.Fatalf("Test err = %v, want ErrServerScheme", err)
	}
}

// TestTheConnectionTestStillChecksTheOrganizations covers the other rule the
// split keeps. The body names a default organization the tenant does not hold.
func TestTheConnectionTestStillChecksTheOrganizations(t *testing.T) {
	write := body()
	write.Mode, write.Servers = ModePlain, []string{"ldap://" + closedPort(t)}
	write.ConfirmPlaintext, write.DefaultOrgID = true, "no-such-org"

	svc := testService(t, deps{tenantRoles: ownerRoles()})
	if _, err := svc.Test(context.Background(), admin, "", &write); !errors.Is(err, organization.ErrNotFound) {
		t.Fatalf("Test err = %v, want organization.ErrNotFound", err)
	}
}

// The population the claim preview tests read. Three people carry the domain the
// write claims, and one carries another, so a preview that answered the owner
// subset or the whole tenant is named by the count.
var (
	movedOwner  = tenant.DomainPerson{UserID: testUserID, Username: "owner", Email: "owner@corp.example"}
	movedPerson = tenant.DomainPerson{UserID: personID, Username: "second", Email: "second@corp.example"}
	stayingOne  = tenant.DomainPerson{
		UserID: "36363636-3636-3636-3636-363636363636", Username: "third", Email: "third@acme.test",
	}
)

// TestPreviewClaimNamesEverybodyTheClaimMoves covers the read half of the first
// guard rail of docs/specs/0002-directory-sign-in.md: the console names the
// people a claim moves before it saves.
//
// The claim on corp.example moves a local IAM_OWNER and a person who holds no
// role. Federation Resolution case 1 outranks every case below it, so the preview
// names both. A preview that named the owner subset would read as the whole
// blast radius, and the person it dropped would still move.
func TestPreviewClaimNamesEverybodyTheClaimMoves(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		moves:       []tenant.DomainPerson{movedOwner, movedPerson, stayingOne},
	})

	preview, err := svc.PreviewClaim(context.Background(), admin,
		ClaimPreviewBody{OrgID: testOrgID, Domains: []string{"Corp.Example"}})
	if err != nil {
		t.Fatalf("PreviewClaim: %v", err)
	}

	if preview.Total != 2 || len(preview.People) != 2 {
		t.Fatalf("the preview names %+v (total %d), want both people of corp.example",
			preview.People, preview.Total)
	}
	if preview.People[0].UserID != testUserID || preview.People[1].UserID != personID {
		t.Errorf("the preview names %+v, want the owner and the person", preview.People)
	}
	if preview.People[0].Email != "owner@corp.example" || preview.People[0].Username != "owner" {
		t.Errorf("the first name reads %+v, want the seeded owner", preview.People[0])
	}
	if len(written) != 0 || len(claimed) != 0 {
		t.Errorf("a preview wrote %+v and claimed %v, want nothing", written, claimed)
	}
}

// TestPreviewClaimReadsBothFormsOfTheIdentifier covers the second form Federation
// Resolution case 1 reads. A person whose username is an address at a claimed
// domain is routed by the claim even when the tenant holds another address for
// them, so a preview that read the email alone would under-report.
func TestPreviewClaimReadsBothFormsOfTheIdentifier(t *testing.T) {
	byUsername := tenant.DomainPerson{
		UserID:   "37373737-3737-3737-3737-373737373737",
		Username: "fourth@corp.example", Email: "fourth@acme.test",
	}
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		moves:       []tenant.DomainPerson{byUsername, stayingOne},
	})

	preview, err := svc.PreviewClaim(context.Background(), admin,
		ClaimPreviewBody{OrgID: testOrgID, Domains: []string{"corp.example"}})
	if err != nil {
		t.Fatalf("PreviewClaim: %v", err)
	}
	if preview.Total != 1 || len(preview.People) != 1 || preview.People[0].UserID != byUsername.UserID {
		t.Fatalf("the preview names %+v (total %d), want the person the username moves",
			preview.People, preview.Total)
	}
}

// TestPreviewClaimAnswersNobodyForAnEmptyList covers a form with no domain in the
// box. Nothing moves, and the read answers that without a query.
func TestPreviewClaimAnswersNobodyForAnEmptyList(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		moves:       []tenant.DomainPerson{movedOwner},
	})

	preview, err := svc.PreviewClaim(context.Background(), admin,
		ClaimPreviewBody{OrgID: testOrgID})
	if err != nil {
		t.Fatalf("PreviewClaim: %v", err)
	}
	if preview.Total != 0 || len(preview.People) != 0 {
		t.Errorf("an empty domain list names %+v (total %d), want nobody",
			preview.People, preview.Total)
	}
}

// TestPreviewClaimRefusesACallerWhoCannotWriteTheFederation covers the gate. The
// preview names the people of the tenant, so the right to read it is the right
// to write the claim. An ORG_OWNER of one organization asks for a tenant-wide
// claim here.
func TestPreviewClaimRefusesACallerWhoCannotWriteTheFederation(t *testing.T) {
	svc := testService(t, deps{
		memberships: []organization.Membership{{OrgID: testOrgID, Roles: []string{organization.RoleOrgOwner}}},
		moves:       []tenant.DomainPerson{movedOwner, movedPerson},
	})

	_, err := svc.PreviewClaim(context.Background(), admin,
		ClaimPreviewBody{Domains: []string{"corp.example"}})
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

// TestPreviewClaimRefusesAPersonWithoutAdminRole refuses a person who
// administers nothing, the way every other route of this package does.
func TestPreviewClaimRefusesAPersonWithoutAdminRole(t *testing.T) {
	svc := testService(t, deps{moves: []tenant.DomainPerson{movedOwner}})

	_, err := svc.PreviewClaim(context.Background(), admin,
		ClaimPreviewBody{Domains: []string{"corp.example"}})
	if !errors.Is(err, ErrNotAdmin) {
		t.Fatalf("err = %v, want ErrNotAdmin", err)
	}
}
