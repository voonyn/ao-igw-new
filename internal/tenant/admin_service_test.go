package tenant

import (
	"context"
	"errors"
	"testing"
	"time"

	"alphaomega/identitygateway/internal/audit"
	"alphaomega/identitygateway/internal/platform/logger"
)

// otherTenantID is the tenant that holds a host this tenant cannot have.
const otherTenantID = "88888888-8888-8888-8888-888888888888"

// owner is the person every administrative test acts as.
var owner = Actor{TenantID: testTenantID, UserID: testUserID, IP: "203.0.113.7", UserAgent: "a-browser"}

// adminDeps is what one test seeds the service with.
type adminDeps struct {
	roles   []string
	domains []Domain

	// existing is what the global domain read answers, keyed by the host. It
	// carries the rows of every tenant, because the host is globally unique and
	// an add must see a claim another tenant already holds.
	existing map[string]Domain

	noBootstrap bool
}

// What the writes of one test left behind.
var (
	inserted []Domain
	restored []string
	removed  []string
	written  []audit.Event
)

func testAdminService(t *testing.T, d adminDeps) *AdminService {
	t.Helper()
	log, _ := logger.NewObserved()
	inserted, restored, removed, written = nil, nil, nil, nil

	return NewAdminService(AdminDeps{
		Tenant: func(context.Context, string) (Tenant, error) {
			return Tenant{
				ID: testTenantID, Name: "AlphaOmega", State: 1,
				DefaultOrgID: testOrgID, CreatedAt: bootstrapAt,
			}, nil
		},
		Domains: func(context.Context, string) ([]Domain, error) { return d.domains, nil },
		FindDomain: func(_ context.Context, domain string) (Domain, error) {
			row, ok := d.existing[domain]
			if !ok {
				return Domain{}, ErrDomainNotFound
			}
			return row, nil
		},
		InsertDomain: func(_ context.Context, row Domain) error {
			inserted = append(inserted, row)
			return nil
		},
		RestoreDomain: func(_ context.Context, _, domain string) error {
			restored = append(restored, domain)
			return nil
		},
		RemoveDomain: func(_ context.Context, _, domain string) error {
			removed = append(removed, domain)
			return nil
		},
		Bootstrap: func(context.Context) (Bootstrap, error) {
			if d.noBootstrap {
				return Bootstrap{}, ErrNoBootstrapRecord
			}
			return Bootstrap{ID: 1, TenantID: testTenantID, Version: "1", AppliedAt: bootstrapAt}, nil
		},
		TenantRoles: func(context.Context, string, string) ([]string, error) { return d.roles, nil },

		// The unit of work either commits whole or leaves nothing behind, so a
		// failed step clears what the earlier steps wrote.
		InTx: func(ctx context.Context, fn func(context.Context) error) error {
			before := len(inserted) + len(restored) + len(removed)
			err := fn(ctx)
			if err != nil && len(inserted)+len(restored)+len(removed) != before {
				inserted, restored, removed = nil, nil, nil
			}
			return err
		},
		Audit: audit.NewRecorder(func(_ context.Context, e audit.Event) error {
			written = append(written, e)
			return nil
		}, log),
		Log: log,
	})
}

// bootstrapAt is when the seeded tenant was created.
var bootstrapAt = time.Unix(1_700_000_000, 0).UTC()

// TestReadTenantRefusesAnybodyButATenantManager covers the read gate. The tenant
// record names every host the gateway answers on, so an organization manager
// does not read it.
func TestReadTenantRefusesAnybodyButATenantManager(t *testing.T) {
	svc := testAdminService(t, adminDeps{roles: []string{"ORG_OWNER"}})
	if _, err := svc.Read(context.Background(), owner); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner reads %v, want ErrForbidden", err)
	}

	svc = testAdminService(t, adminDeps{roles: []string{RoleIAMAdmin}})
	if _, err := svc.Read(context.Background(), owner); err != nil {
		t.Errorf("a tenant administrator reads %v, want the tenant", err)
	}
}

// TestReadTenantCarriesEveryDomain covers what the console renders on the domain
// tab. A removed host stays in the answer and reads as inactive: the row still
// holds the globally unique host, and the operator must see that it is theirs.
func TestReadTenantCarriesEveryDomain(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{RoleIAMOwner},
		domains: []Domain{
			{Domain: "auth.acme.com", TenantID: testTenantID, IsPrimary: true, IsVerified: true, State: 1},
			{Domain: "old.acme.com", TenantID: testTenantID, IsVerified: true, State: 2},
		},
	})

	view, err := svc.Read(context.Background(), owner)
	if err != nil {
		t.Fatalf("read the tenant: %v", err)
	}
	if view.ID != testTenantID || view.Name != "AlphaOmega" || view.DefaultOrgID != testOrgID {
		t.Errorf("the tenant reads %+v, want the seeded record", view)
	}
	if len(view.Domains) != 2 {
		t.Fatalf("the tenant carries %d domains, want 2", len(view.Domains))
	}
	if !view.Domains[0].IsPrimary || view.Domains[0].Domain != "auth.acme.com" {
		t.Errorf("the first domain reads %+v, want the primary host", view.Domains[0])
	}
	if view.Domains[1].State != DomainStateInactive {
		t.Errorf("the removed host reads state %d, want the inactive state", view.Domains[1].State)
	}
}

// TestAddDomainRefusesAnybodyButTheOwner covers the write gate. A domain maps a
// globally unique host to this tenant, so only an IAM_OWNER writes one. A tenant
// administrator reads the tenant and does not change what it answers on.
func TestAddDomainRefusesAnybodyButTheOwner(t *testing.T) {
	svc := testAdminService(t, adminDeps{roles: []string{RoleIAMAdmin}})
	if _, err := svc.AddDomain(context.Background(), owner, "new.acme.com"); !errors.Is(err, ErrForbidden) {
		t.Errorf("a tenant administrator writes %v, want ErrForbidden", err)
	}
	if len(inserted) != 0 {
		t.Errorf("the refused write inserted %+v, want nothing", inserted)
	}
}

// TestAddDomainStoresTheBareHost covers the write an operator makes. The host is
// stored lowercased and trimmed, because the lookup that resolves a request to
// its tenant compares the stored value to the request host.
func TestAddDomainStoresTheBareHost(t *testing.T) {
	svc := testAdminService(t, adminDeps{roles: []string{RoleIAMOwner}})

	view, err := svc.AddDomain(context.Background(), owner, "  New.Acme.COM  ")
	if err != nil {
		t.Fatalf("add the domain: %v", err)
	}
	if view.Domain != "new.acme.com" || view.IsPrimary || !view.IsVerified {
		t.Errorf("the new domain reads %+v, want the lowercased host, not primary, verified", view)
	}
	if len(inserted) != 1 || inserted[0].Domain != "new.acme.com" || inserted[0].State != DomainStateActive {
		t.Fatalf("the write stored %+v, want one active row for the lowercased host", inserted)
	}

	if len(written) != 1 {
		t.Fatalf("the write recorded %d events, want 1", len(written))
	}
	if written[0].Action != string(audit.ActionDomainAdded) ||
		written[0].EntityType != audit.EntityTenantDomain ||
		written[0].EntityID != "new.acme.com" {
		t.Errorf("the event reads %+v, want the domain that was added", written[0])
	}
}

// TestAddDomainRefusesAHostAnotherTenantHolds covers the globally unique key. A
// host resolves to exactly one tenant, so a claim on somebody else's host is
// refused. The answer never says which tenant holds it.
func TestAddDomainRefusesAHostAnotherTenantHolds(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{RoleIAMOwner},
		existing: map[string]Domain{
			"taken.acme.com": {Domain: "taken.acme.com", TenantID: otherTenantID, State: DomainStateActive},
		},
	})

	_, err := svc.AddDomain(context.Background(), owner, "taken.acme.com")
	if !errors.Is(err, ErrDomainTaken) {
		t.Errorf("a host of another tenant reads %v, want ErrDomainTaken", err)
	}
	if len(inserted) != 0 {
		t.Errorf("the refused write inserted %+v, want nothing", inserted)
	}
}

// TestAddDomainRefusesAHostTheTenantAlreadyServes covers the second half of the
// key. The row is already there and already active, so there is nothing to add.
func TestAddDomainRefusesAHostTheTenantAlreadyServes(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{RoleIAMOwner},
		existing: map[string]Domain{
			"auth.acme.com": {Domain: "auth.acme.com", TenantID: testTenantID, State: DomainStateActive},
		},
	})

	if _, err := svc.AddDomain(context.Background(), owner, "auth.acme.com"); !errors.Is(err, ErrDomainTaken) {
		t.Errorf("a host the tenant serves reads %v, want ErrDomainTaken", err)
	}
}

// TestAddDomainRestoresARemovedHost covers re-adding a host this tenant removed.
// The row was never deleted, so the write puts it back to work instead of
// failing on a key the tenant already holds.
func TestAddDomainRestoresARemovedHost(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{RoleIAMOwner},
		existing: map[string]Domain{
			"old.acme.com": {Domain: "old.acme.com", TenantID: testTenantID, State: DomainStateInactive},
		},
	})

	view, err := svc.AddDomain(context.Background(), owner, "old.acme.com")
	if err != nil {
		t.Fatalf("restore the domain: %v", err)
	}
	if view.State != DomainStateActive {
		t.Errorf("the restored domain reads state %d, want the active state", view.State)
	}
	if len(restored) != 1 || restored[0] != "old.acme.com" {
		t.Fatalf("the write restored %+v, want the removed host", restored)
	}
	if len(inserted) != 0 {
		t.Errorf("the write inserted %+v, want the existing row to be restored", inserted)
	}
}

// TestRemoveDomainDeactivatesTheHost covers the remove. The row stays and flips
// to inactive, so no other tenant can claim the host, and the operator can put
// it back.
func TestRemoveDomainDeactivatesTheHost(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{RoleIAMOwner},
		existing: map[string]Domain{
			"extra.acme.com": {Domain: "extra.acme.com", TenantID: testTenantID, State: DomainStateActive},
		},
	})

	if err := svc.RemoveDomain(context.Background(), owner, "Extra.Acme.com"); err != nil {
		t.Fatalf("remove the domain: %v", err)
	}
	if len(removed) != 1 || removed[0] != "extra.acme.com" {
		t.Fatalf("the write removed %+v, want the lowercased host", removed)
	}
	if len(written) != 1 || written[0].Action != string(audit.ActionDomainRemoved) {
		t.Errorf("the write recorded %+v, want one domain-removed event", written)
	}
}

// TestRemoveDomainRefusesThePrimaryHost covers the guard that keeps a tenant
// reachable. The issuer names the primary host, so removing it would refuse
// every token of the tenant, including the one the operator is holding.
func TestRemoveDomainRefusesThePrimaryHost(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{RoleIAMOwner},
		existing: map[string]Domain{
			"auth.acme.com": {
				Domain: "auth.acme.com", TenantID: testTenantID,
				IsPrimary: true, State: DomainStateActive,
			},
		},
	})

	if err := svc.RemoveDomain(context.Background(), owner, "auth.acme.com"); !errors.Is(err, ErrPrimaryDomain) {
		t.Errorf("the primary host reads %v, want ErrPrimaryDomain", err)
	}
	if len(removed) != 0 {
		t.Errorf("the refused write removed %+v, want nothing", removed)
	}
}

// TestRemoveDomainRefusesAHostOfAnotherTenant covers the tenant boundary. The
// host exists, and it is not this tenant's to remove, so it answers the same way
// a host nobody holds answers.
func TestRemoveDomainRefusesAHostOfAnotherTenant(t *testing.T) {
	svc := testAdminService(t, adminDeps{
		roles: []string{RoleIAMOwner},
		existing: map[string]Domain{
			"taken.acme.com": {Domain: "taken.acme.com", TenantID: otherTenantID, State: DomainStateActive},
		},
	})

	if err := svc.RemoveDomain(context.Background(), owner, "taken.acme.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("a host of another tenant reads %v, want ErrDomainNotFound", err)
	}
	if err := svc.RemoveDomain(context.Background(), owner, "nobody.acme.com"); !errors.Is(err, ErrDomainNotFound) {
		t.Errorf("a host nobody holds reads %v, want ErrDomainNotFound", err)
	}
}

// TestReadBootstrapReadsTheSingletonRecord covers the record the console renders
// on the bootstrap page. The routine records no per-artifact provenance, so the
// list is empty and never null: the console iterates it without a guard.
func TestReadBootstrapReadsTheSingletonRecord(t *testing.T) {
	svc := testAdminService(t, adminDeps{roles: []string{RoleIAMAdmin}})

	view, err := svc.ReadBootstrap(context.Background(), owner)
	if err != nil {
		t.Fatalf("read the bootstrap record: %v", err)
	}
	if view.ID != 1 || view.TenantID != testTenantID || view.Version != "1" {
		t.Errorf("the record reads %+v, want the seeded singleton", view)
	}
	if view.Artifacts == nil || len(view.Artifacts) != 0 {
		t.Errorf("the record carries %v artifacts, want an empty list", view.Artifacts)
	}

	svc = testAdminService(t, adminDeps{roles: []string{"ORG_OWNER"}})
	if _, err := svc.ReadBootstrap(context.Background(), owner); !errors.Is(err, ErrForbidden) {
		t.Errorf("an organization owner reads %v, want ErrForbidden", err)
	}
}

// TestReadBootstrapReportsAnUnbootstrappedDeployment covers a gateway whose
// schema was migrated but never bootstrapped. The console names the missing
// subsystem, so the read must not answer an empty record.
func TestReadBootstrapReportsAnUnbootstrappedDeployment(t *testing.T) {
	svc := testAdminService(t, adminDeps{roles: []string{RoleIAMOwner}, noBootstrap: true})

	if _, err := svc.ReadBootstrap(context.Background(), owner); !errors.Is(err, ErrNoBootstrapRecord) {
		t.Errorf("an unbootstrapped deployment reads %v, want ErrNoBootstrapRecord", err)
	}
}
