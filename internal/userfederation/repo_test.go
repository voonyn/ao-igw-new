package userfederation

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/uptrace/bun"

	"alphaomega/identitygateway/internal/platform/crypto"
	"alphaomega/identitygateway/internal/platform/db/dbtest"
	"alphaomega/identitygateway/internal/platform/logger"
)

const (
	testTenantID = "11111111-1111-1111-1111-111111111111"
	otherTenant  = "12121212-1212-1212-1212-121212121212"
	testOrgID    = "22222222-2222-2222-2222-222222222222"
	otherOrgID   = "44444444-4444-4444-4444-444444444444"
	testUserID   = "33333333-3333-3333-3333-333333333333"
	personID     = "35353535-3535-3535-3535-353535353535"

	tenantFederationID = "77777777-7777-7777-7777-777777777777"
	orgFederationID    = "88888888-8888-8888-8888-888888888888"
	deadFederationID   = "99999999-9999-9999-9999-999999999999"
	otherFederationID  = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

// seed writes one tenant with three federations — the tenant-wide row, one
// organization row, and one soft-deleted row — plus one federation of a second
// tenant, the domains they claim, and one Federation Link.
func seed(t *testing.T, bdb *bun.DB) {
	t.Helper()

	ctx := context.Background()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := bdb.ExecContext(ctx, query, args...); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}

	federation := `INSERT INTO user_federations
	    (id, tenant_id, org_id, name, type, state, default_org_id, mode, servers,
	     timeout_ms, bind_dn, base_dn, user_object_classes, user_filters,
	     attr_id, attr_username, attr_email, created_at, deleted_at)
	  VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, 5000, ?, ?,
	          '["inetOrgPerson"]', '["uid"]', 'objectGUID', 'sAMAccountName', 'mail',
	          NOW(3), ?)`

	exec(federation, tenantFederationID, testTenantID, "", "Head office", StateActive, testOrgID,
		ModeLDAPS, `["ldaps://dc1.corp.example:636"]`, "cn=svc,dc=corp,dc=example", "dc=corp,dc=example", nil)
	exec(federation, orgFederationID, testTenantID, testOrgID, "Subsidiary", StateInactive, nil,
		ModeStartTLS, `["ldap://dc2.sub.example:389"]`, "cn=reader,dc=sub,dc=example", "dc=sub,dc=example", nil)
	exec(federation, deadFederationID, testTenantID, "", "Retired", StateActive, testOrgID,
		ModeLDAPS, `["ldaps://old.corp.example:636"]`, "cn=old,dc=corp,dc=example", "dc=corp,dc=example", "2024-01-01 00:00:00.000000")
	exec(federation, otherFederationID, otherTenant, "", "Another tenant", StateActive, otherOrgID,
		ModeLDAPS, `["ldaps://dc.other.example:636"]`, "cn=svc,dc=other,dc=example", "dc=other,dc=example", nil)

	exec(`INSERT INTO user_federation_domains (tenant_id, domain, federation_id)
	      VALUES (?, 'corp.example', ?)`, testTenantID, tenantFederationID)
	exec(`INSERT INTO user_federation_domains (tenant_id, domain, federation_id)
	      VALUES (?, 'sub.example', ?)`, testTenantID, orgFederationID)

	exec(`INSERT INTO user_federation_links (tenant_id, federation_id, external_id, user_id, created_at)
	      VALUES (?, ?, 'a-stable-guid', ?, NOW(3))`, testTenantID, tenantFederationID, personID)
}

func testRepo(t *testing.T) (*Repository, context.Context) {
	t.Helper()

	bdb := dbtest.Open(t, "userfederation")
	seed(t, bdb)
	cipher, err := crypto.NewCipher("a-test-encryption-key")
	if err != nil {
		t.Fatalf("build the cipher: %v", err)
	}
	return NewRepository(bdb, cipher, logger.New()), context.Background()
}

// TestInsertSealsTheBindPasswordAndFindOpensIt is the cipher round trip. The
// column holds ciphertext, the read answers the credential, and the sealed bytes
// never leave the repository.
func TestInsertSealsTheBindPasswordAndFindOpensIt(t *testing.T) {
	repo, ctx := testRepo(t)

	written := Federation{
		ID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", TenantID: testTenantID, OrgID: testOrgID,
		Name: "Warehouse", Type: TypeDirectory, State: StateActive,
		Mode: ModeLDAPS, Servers: []string{"ldaps://dc3.corp.example:636"}, TimeoutMS: 5000,
		BindDN: "cn=svc,dc=corp,dc=example", BindPassword: "a-directory-secret",
		BaseDN: "dc=corp,dc=example", UserObjectClasses: []string{"inetOrgPerson"},
		UserFilters: []string{"uid"}, AttrID: "objectGUID", AttrUsername: "sAMAccountName",
		AttrEmail: "mail",
	}
	if err := repo.Insert(ctx, written); err != nil {
		t.Fatalf("create the federation: %v", err)
	}

	row, err := repo.FindByID(ctx, testTenantID, written.ID)
	if err != nil {
		t.Fatalf("read the federation: %v", err)
	}
	if row.BindPassword != "a-directory-secret" {
		t.Errorf("the bind password reads %q, want the written credential", row.BindPassword)
	}
	if len(row.Sealed) != 0 {
		t.Errorf("the row carries %d ciphertext bytes, want the column left behind", len(row.Sealed))
	}
	if len(row.Servers) != 1 || row.Servers[0] != "ldaps://dc3.corp.example:636" {
		t.Errorf("the servers read %v, want the written list", row.Servers)
	}

	// The column holds ciphertext, not the credential.
	var stored []byte
	if err := repo.db.NewSelect().Model((*Federation)(nil)).
		Column("bind_password").Where("uf.id = ?", written.ID).
		Scan(ctx, &stored); err != nil {
		t.Fatalf("read the stored column: %v", err)
	}
	if len(stored) == 0 || bytes.Contains(stored, []byte("a-directory-secret")) {
		t.Errorf("the column holds the bind password in the clear")
	}

	// An update that clears the credential leaves no ciphertext behind.
	written.BindPassword = ""
	if err := repo.Update(ctx, written); err != nil {
		t.Fatalf("update the federation: %v", err)
	}
	row, err = repo.FindByID(ctx, testTenantID, written.ID)
	if err != nil {
		t.Fatalf("read the federation: %v", err)
	}
	if row.BindPassword != "" {
		t.Errorf("the bind password reads %q, want it cleared", row.BindPassword)
	}
}

// TestTheTwoLevelsAreSeparateRows covers the replace rule. Each level answers its
// own row whole, and no field of one reaches the other.
func TestTheTwoLevelsAreSeparateRows(t *testing.T) {
	repo, ctx := testRepo(t)

	wide, err := repo.FindByID(ctx, testTenantID, tenantFederationID)
	if err != nil {
		t.Fatalf("read the tenant-wide federation: %v", err)
	}
	own, err := repo.FindByID(ctx, testTenantID, orgFederationID)
	if err != nil {
		t.Fatalf("read the organization federation: %v", err)
	}

	if wide.OrgID != "" || wide.DefaultOrgID != testOrgID || wide.Mode != ModeLDAPS {
		t.Errorf("the tenant-wide row reads %+v, want its own level and transport", wide)
	}
	if own.OrgID != testOrgID || own.DefaultOrgID != "" || own.Mode != ModeStartTLS {
		t.Errorf("the organization row reads %+v, want its own level and transport", own)
	}
	if own.BindDN == wide.BindDN || own.BaseDN == wide.BaseDN {
		t.Errorf("the organization row borrowed a field of the tenant row: %+v", own)
	}
}

// TestEveryReadIsTenantScopedAndSkipsADeletedFederation covers the soft delete and
// the tenant scope. A deleted federation is invisible to the list and to the read,
// and a federation of another tenant is never reachable.
func TestEveryReadIsTenantScopedAndSkipsADeletedFederation(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, err := repo.List(ctx, testTenantID)
	if err != nil {
		t.Fatalf("list the federations: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("the list holds %d rows, want the two live rows of this tenant", len(rows))
	}
	for _, row := range rows {
		if row.ID == deadFederationID || row.TenantID != testTenantID {
			t.Errorf("the list holds %s of tenant %s, want this tenant's live rows", row.ID, row.TenantID)
		}
	}

	if _, err := repo.FindByID(ctx, testTenantID, deadFederationID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a soft-deleted federation reads %v, want ErrNotFound", err)
	}
	if _, err := repo.FindByID(ctx, testTenantID, otherFederationID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a federation of another tenant reads %v, want ErrNotFound", err)
	}
}

// TestClaimRefusesADomainAnotherLiveFederationHolds covers the unique key. The
// database settles the claim, so two administrators who save at the same moment
// cannot both hold one domain.
func TestClaimRefusesADomainAnotherLiveFederationHolds(t *testing.T) {
	repo, ctx := testRepo(t)

	err := repo.Claim(ctx, testTenantID, orgFederationID, []string{"sub.example", "corp.example"})
	if !errors.Is(err, ErrDomainClaimed) {
		t.Fatalf("the second claim reads %v, want ErrDomainClaimed", err)
	}

	// The owner of the live row stands.
	rows, err := repo.Domains(ctx, testTenantID, []string{tenantFederationID})
	if err != nil {
		t.Fatalf("read the claimed domains: %v", err)
	}
	if len(rows) != 1 || rows[0].Domain != "corp.example" {
		t.Errorf("the claims read %+v, want corp.example still held by %s", rows, tenantFederationID)
	}
}

// TestClaimReplacesTheWholeList covers a write that drops one domain and adds
// another. The dropped claim is released, so a second federation can take it.
func TestClaimReplacesTheWholeList(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.Claim(ctx, testTenantID, tenantFederationID, []string{"hq.example"}); err != nil {
		t.Fatalf("replace the claims: %v", err)
	}
	rows, err := repo.Domains(ctx, testTenantID, []string{tenantFederationID})
	if err != nil {
		t.Fatalf("read the claimed domains: %v", err)
	}
	if len(rows) != 1 || rows[0].Domain != "hq.example" {
		t.Fatalf("the claims read %+v, want hq.example alone", rows)
	}

	// corp.example is free, so the other federation claims it.
	if err := repo.Claim(ctx, testTenantID, orgFederationID, []string{"sub.example", "corp.example"}); err != nil {
		t.Fatalf("claim the released domain: %v", err)
	}
	rows, err = repo.Domains(ctx, testTenantID, []string{orgFederationID})
	if err != nil {
		t.Fatalf("read the claimed domains: %v", err)
	}
	if len(rows) != 2 {
		t.Errorf("the claims read %+v, want both domains", rows)
	}
}

// TestDeleteReleasesTheDomains covers the delete. The federation is soft deleted,
// and every domain it claimed is free for another federation to take.
func TestDeleteReleasesTheDomains(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.Delete(ctx, testTenantID, tenantFederationID); err != nil {
		t.Fatalf("delete the federation: %v", err)
	}
	if _, err := repo.FindByID(ctx, testTenantID, tenantFederationID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the deleted federation reads %v, want ErrNotFound", err)
	}
	rows, err := repo.Domains(ctx, testTenantID, []string{tenantFederationID})
	if err != nil {
		t.Fatalf("read the claimed domains: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("the deleted federation still claims %+v, want the domains released", rows)
	}

	if err := repo.Claim(ctx, testTenantID, orgFederationID, []string{"corp.example"}); err != nil {
		t.Errorf("claim the released domain: %v", err)
	}
	if err := repo.Delete(ctx, testTenantID, tenantFederationID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a second delete reads %v, want ErrNotFound", err)
	}
}

// TestLinksAreListedAndHardDeleted covers the Federation Link. The list names the
// federation, and the delete removes the row rather than marking it.
func TestLinksAreListedAndHardDeleted(t *testing.T) {
	repo, ctx := testRepo(t)

	rows, err := repo.Links(ctx, testTenantID, personID)
	if err != nil {
		t.Fatalf("list the links: %v", err)
	}
	if len(rows) != 1 || rows[0].FederationID != tenantFederationID || rows[0].ExternalID != "a-stable-guid" {
		t.Fatalf("the links read %+v, want the one seeded link", rows)
	}
	if rows[0].FederationName != "Head office" {
		t.Errorf("the link names %q, want the federation name joined", rows[0].FederationName)
	}

	if err := repo.DeleteLink(ctx, testTenantID, tenantFederationID, personID); err != nil {
		t.Fatalf("delete the link: %v", err)
	}
	rows, err = repo.Links(ctx, testTenantID, personID)
	if err != nil {
		t.Fatalf("list the links: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("the links read %+v, want the row gone", rows)
	}
	if err := repo.DeleteLink(ctx, testTenantID, tenantFederationID, personID); !errors.Is(err, ErrLinkNotFound) {
		t.Errorf("a second delete reads %v, want ErrLinkNotFound", err)
	}
}

// TestASoftDeletedFederationStillListsThePeopleTiedToIt covers the third guard
// rail of docs/specs/0002-directory-sign-in.md.
//
// The delete of a federation was chosen over a delete blocked by live links, so an
// administrator whose directory is gone for good is never trapped. The links it
// leaves behind must therefore stay readable, or nobody could move the people
// off it.
//
// The federation name is joined over the live federations alone, so a deleted
// federation reads as an empty name and the link is still listed and still
// unlinkable.
func TestASoftDeletedFederationStillListsThePeopleTiedToIt(t *testing.T) {
	repo, ctx := testRepo(t)

	if err := repo.Delete(ctx, testTenantID, tenantFederationID); err != nil {
		t.Fatalf("delete the federation: %v", err)
	}

	rows, err := repo.Links(ctx, testTenantID, personID)
	if err != nil {
		t.Fatalf("list the links: %v", err)
	}
	if len(rows) != 1 || rows[0].FederationID != tenantFederationID {
		t.Fatalf("the links read %+v, want the link the deleted federation left behind", rows)
	}
	if rows[0].FederationName != "" {
		t.Errorf("the link names %q, want an empty name for a deleted federation", rows[0].FederationName)
	}

	if err := repo.DeleteLink(ctx, testTenantID, tenantFederationID, personID); err != nil {
		t.Errorf("unlink the person from the deleted federation: %v", err)
	}
}

// TestInsertLink covers the write of one first bind, and the two unique keys
// that bound it: one directory account maps to one person, and one person holds
// at most one account per federation.
func TestInsertLink(t *testing.T) {
	repo, ctx := testRepo(t)

	written := Link{
		TenantID: testTenantID, FederationID: tenantFederationID,
		ExternalID: "another-stable-guid", UserID: testUserID,
	}
	if err := repo.InsertLink(ctx, written); err != nil {
		t.Fatalf("write the link: %v", err)
	}

	rows, err := repo.Links(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("list the links: %v", err)
	}
	if len(rows) != 1 || rows[0].ExternalID != "another-stable-guid" {
		t.Fatalf("the links read %+v, want the written link", rows)
	}

	// The directory account is already tied to somebody.
	taken := written
	taken.UserID = personID
	if err := repo.InsertLink(ctx, taken); err == nil {
		t.Error("a second link on the same directory account was written, want the key to refuse it")
	}

	// The person is already tied to this federation.
	second := written
	second.ExternalID = "a-third-stable-guid"
	if err := repo.InsertLink(ctx, second); err == nil {
		t.Error("a second link of the same person with the same federation was written, want the key to refuse it")
	}
}

// TestADuplicateNameAnswersTheConflictSentinel covers uq_user_federations_name.
// An administrator who types a name the tenant already carries reads a conflict,
// never a server error.
func TestADuplicateNameAnswersTheConflictSentinel(t *testing.T) {
	repo, ctx := testRepo(t)

	twin := Federation{
		ID: "cccccccc-cccc-cccc-cccc-cccccccccccc", TenantID: testTenantID, OrgID: testOrgID,
		Name: "Head office", Type: TypeDirectory, State: StateActive,
		Mode: ModeLDAPS, Servers: []string{"ldaps://dc4.corp.example:636"}, TimeoutMS: 5000,
		BindDN: "cn=svc,dc=corp,dc=example", BaseDN: "dc=corp,dc=example",
		UserObjectClasses: []string{"inetOrgPerson"}, UserFilters: []string{"uid"},
		AttrID: "objectGUID", AttrUsername: "sAMAccountName", AttrEmail: "mail",
	}
	if err := repo.Insert(ctx, twin); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a duplicate name reads %v, want ErrNameTaken", err)
	}

	// A name of another tenant is free, and so is a rename onto a free name.
	twin.Name = "Warehouse"
	if err := repo.Insert(ctx, twin); err != nil {
		t.Fatalf("create the federation: %v", err)
	}
	twin.Name = "Subsidiary"
	if err := repo.Update(ctx, twin); !errors.Is(err, ErrNameTaken) {
		t.Errorf("a rename onto a taken name reads %v, want ErrNameTaken", err)
	}
}

// TestFindByDomainReadsTheLiveActiveClaim covers case 1 of Federation Resolution.
// The claim of the active federation answers, and the claim of the inactive one is
// matched by nothing.
func TestFindByDomainReadsTheLiveActiveClaim(t *testing.T) {
	repo, ctx := testRepo(t)

	federationID, err := repo.FindByDomain(ctx, testTenantID, "corp.example")
	if err != nil {
		t.Fatalf("read the federation that claims the domain: %v", err)
	}
	if federationID != tenantFederationID {
		t.Errorf("the domain resolved %q, want the tenant-wide federation", federationID)
	}

	// sub.example is claimed by the inactive federation, and nobody claims
	// nowhere.example.
	for _, domain := range []string{"sub.example", "nowhere.example"} {
		if _, err := repo.FindByDomain(ctx, testTenantID, domain); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s gave %v, want ErrNotFound", domain, err)
		}
	}
}

// TestFindByDomainKeepsTheTenantScope proves that a domain of one tenant never
// routes the sign-in of another. Both tenants can claim the same host.
func TestFindByDomainKeepsTheTenantScope(t *testing.T) {
	repo, ctx := testRepo(t)

	if _, err := repo.FindByDomain(ctx, otherTenant, "corp.example"); !errors.Is(err, ErrNotFound) {
		t.Errorf("the other tenant read %v, want ErrNotFound", err)
	}
}

// TestLinkedFederationsReadsTheLiveActiveLinks covers case 2 of Federation
// Resolution. A link with an inactive federation and a link with a soft-deleted one
// are matched by nothing, so neither routes a password step and neither makes
// the person ambiguous.
func TestLinkedFederationsReadsTheLiveActiveLinks(t *testing.T) {
	repo, ctx := testRepo(t)

	link := `INSERT INTO user_federation_links
	    (tenant_id, federation_id, external_id, user_id, created_at) VALUES (?, ?, ?, ?, NOW(3))`
	for _, federationID := range []string{orgFederationID, deadFederationID} {
		if _, err := repo.db.ExecContext(ctx, link, testTenantID, federationID, "guid-"+federationID, personID); err != nil {
			t.Fatalf("write the identity link with %s: %v", federationID, err)
		}
	}

	federationIDs, err := repo.LinkedFederations(ctx, testTenantID, personID)
	if err != nil {
		t.Fatalf("read the linked federations: %v", err)
	}
	if len(federationIDs) != 1 || federationIDs[0] != tenantFederationID {
		t.Errorf("the person is linked to %v, want the live active federation alone", federationIDs)
	}
}

// TestLinkedFederationsReadsNothingForAPersonWithNoLink covers case 3. The person
// the tenant holds is tied to no directory, so the local compare answers.
func TestLinkedFederationsReadsNothingForAPersonWithNoLink(t *testing.T) {
	repo, ctx := testRepo(t)

	federationIDs, err := repo.LinkedFederations(ctx, testTenantID, testUserID)
	if err != nil {
		t.Fatalf("read the linked federations: %v", err)
	}
	if len(federationIDs) != 0 {
		t.Errorf("the person is linked to %v, want nothing", federationIDs)
	}
}

// TestActiveIDsCountsBothLevelsAndNothingElse covers case 4. The count covers the
// tenant-wide row and the organization rows together, and an inactive federation, a
// soft-deleted one, and the federation of another tenant are counted by nothing.
func TestActiveIDsCountsBothLevelsAndNothingElse(t *testing.T) {
	repo, ctx := testRepo(t)

	federationIDs, err := repo.ActiveIDs(ctx, testTenantID)
	if err != nil {
		t.Fatalf("read the active federations: %v", err)
	}
	if len(federationIDs) != 1 || federationIDs[0] != tenantFederationID {
		t.Errorf("the tenant holds %v, want the live active federation alone", federationIDs)
	}

	// The organization row is inactive. Switching it on makes the tenant
	// ambiguous, which is the refusal case 4 answers with, and it proves that
	// both levels are counted together.
	if _, err := repo.db.ExecContext(ctx,
		`UPDATE user_federations SET state = ? WHERE id = ?`, StateActive, orgFederationID); err != nil {
		t.Fatalf("activate the organization federation: %v", err)
	}

	federationIDs, err = repo.ActiveIDs(ctx, testTenantID)
	if err != nil {
		t.Fatalf("read the active federations: %v", err)
	}
	if len(federationIDs) != 2 {
		t.Errorf("the tenant holds %v, want both levels counted together", federationIDs)
	}
}

// TestLinkedUserReadsTheStableExternalID covers the read every sign-in after the
// first one takes. The key is the stable directory id, so a username the
// directory later changes still names the same person, and an identifier that
// matches no column of the person still signs them in.
//
// The read is tenant scoped, and a stable id no link holds answers the sentinel.
func TestLinkedUserReadsTheStableExternalID(t *testing.T) {
	repo, ctx := testRepo(t)

	userID, err := repo.LinkedUser(ctx, testTenantID, tenantFederationID, "a-stable-guid")
	if err != nil {
		t.Fatalf("read the linked person: %v", err)
	}
	if userID != personID {
		t.Errorf("the link names %q, want %q", userID, personID)
	}

	if _, err := repo.LinkedUser(ctx, testTenantID, tenantFederationID, "another-guid"); !errors.Is(err, ErrLinkNotFound) {
		t.Errorf("a stable id no link holds answered %v, want ErrLinkNotFound", err)
	}
	if _, err := repo.LinkedUser(ctx, otherTenant, tenantFederationID, "a-stable-guid"); !errors.Is(err, ErrLinkNotFound) {
		t.Errorf("the link of another tenant answered %v, want ErrLinkNotFound", err)
	}
}
