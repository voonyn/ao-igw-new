package identityprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"alphaomega/identitygateway/internal/api/http/response"
	"alphaomega/identitygateway/internal/tenant"
)

// The two owners the guard rail tests read. One of them carries an address in
// the domain the write claims, and one does not.
var (
	claimedOwner = tenant.LocalOwner{UserID: testUserID, Email: "owner@corp.example"}
	safeOwner    = tenant.LocalOwner{UserID: personID, Email: "second@acme.test"}
)

// ownerRoles is the caller of every test here: a tenant manager, who writes a
// provider at either level.
func ownerRoles() []string { return []string{tenant.RoleIAMOwner} }

// TestCreateRefusesAClaimThatTakesTheLastLocalOwner covers the first guard rail
// of docs/specs/0002-directory-sign-in.md at the domain claim.
//
// Provider Resolution case 1 outranks case 3, so the claim routes every person
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
		t.Errorf("the create wrote %d providers, want one", len(written))
	}
}

// TestAnInactiveProviderClaimsNobody covers the state the write stores. An
// inactive provider routes nobody, so its claim takes no owner and the rail says
// nothing. This is how an administrator prepares a directory before they switch
// it on.
func TestAnInactiveProviderClaimsNobody(t *testing.T) {
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
		t.Errorf("the create wrote %d providers, want one", len(written))
	}
}

// TestUpdateRefusesAClaimThatTakesTheLastLocalOwner covers the same rail on the
// update. A provider switched on with a claim ties the same people the create
// would.
func TestUpdateRefusesAClaimThatTakesTheLastLocalOwner(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		rows:        []Provider{storedProvider(testOrgID)},
		localOwners: []tenant.LocalOwner{claimedOwner},
	})

	_, err := svc.Update(context.Background(), admin, tenantIdpID, body())
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
		links:       []Link{{TenantID: testTenantID, IdpID: tenantIdpID, UserID: personID}},
		linked:      []string{tenantIdpID},
	})

	err := svc.Unlink(context.Background(), admin, personID, tenantIdpID)
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
		links:       []Link{{TenantID: testTenantID, IdpID: tenantIdpID, UserID: personID}},
		linked:      []string{tenantIdpID},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantIdpID); err != nil {
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
			{TenantID: testTenantID, IdpID: tenantIdpID, UserID: personID},
			{TenantID: testTenantID, IdpID: orgIdpID, UserID: personID},
		},
		linked: []string{orgIdpID, tenantIdpID},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantIdpID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	if len(unlinked) != 1 {
		t.Errorf("the unlink removed %v, want the one link", unlinked)
	}
}

// TestUnlinkLeavesTheMissToTheDelete covers a provider the person holds no link
// with. The rail must not turn that into a refusal of its own: DeleteLink
// answers the miss, and the route answers not_found.
func TestUnlinkLeavesTheMissToTheDelete(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		userOrg:     testOrgID,
		links:       []Link{{TenantID: testTenantID, IdpID: orgIdpID, UserID: personID}},
		linked:      []string{orgIdpID},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantIdpID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
}

// TestUnlinkAllowsTheLinkOfADeadProvider covers the rail against the third one.
// The person is tied to a provider that is inactive or soft deleted, so nothing
// signs them in already, and a refusal would only trap the administrator who is
// moving them off a directory that is gone for good.
func TestUnlinkAllowsTheLinkOfADeadProvider(t *testing.T) {
	svc := testService(t, deps{
		tenantRoles: ownerRoles(),
		userOrg:     testOrgID,
		links:       []Link{{TenantID: testTenantID, IdpID: tenantIdpID, UserID: personID}},
	})

	if err := svc.Unlink(context.Background(), admin, personID, tenantIdpID); err != nil {
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
		return response.Fail(c, fmt.Errorf("delete identity link: %w", ErrLastLink))
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
	if body.Error != "last_identity_link" {
		t.Errorf("the answer carries the slug %q, want last_identity_link", body.Error)
	}
}
